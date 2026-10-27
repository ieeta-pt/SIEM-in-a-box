"""Isolated, explicitly invoked runner for ICISSP revision pilots/runs.

Commands: plan, preflight, execute --set pilots|confirmatory --hours N.
The default commands never start containers or generators. Confirmation runs
require a protocol_lock.json created only after pilots are inspected.
Historical bench/results and campaign.json are never written by this runner.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

import numpy as np
import requests

HERE = Path(__file__).resolve().parent
BENCH = HERE.parent
sys.path.insert(0, str(BENCH))
sys.path.insert(0, str(HERE))

import analyze  # noqa: E402
import run as legacy  # noqa: E402
from analyze_new import summarize_stream, write_backlog  # noqa: E402
from assess_run import assess as assess_saved_run  # noqa: E402
from config_revision import PIPELINE_IDS, TOPICS, render  # noqa: E402
from eventlog import read as read_events  # noqa: E402
from telemetry import Telemetry, host_snapshot  # noqa: E402

NEW_RESULTS = HERE / "new_results"
IMAGE_TAGS = {
    "A-sep": ["docker.elastic.co/elasticsearch/elasticsearch:8.19.7",
              "bitnamilegacy/kafka:3.9", "docker.elastic.co/logstash/logstash:8.19.7",
              legacy.FB_IMAGE],
    "A-shared": ["docker.elastic.co/elasticsearch/elasticsearch:8.19.7",
                 "bitnamilegacy/kafka:3.9", "docker.elastic.co/logstash/logstash:8.19.7",
                 legacy.FB_IMAGE],
    "A-topics": ["docker.elastic.co/elasticsearch/elasticsearch:8.19.7",
                 "bitnamilegacy/kafka:3.9", "docker.elastic.co/logstash/logstash:8.19.7",
                 legacy.FB_IMAGE],
    "A-pipelines": ["docker.elastic.co/elasticsearch/elasticsearch:8.19.7",
                    "bitnamilegacy/kafka:3.9", "docker.elastic.co/logstash/logstash:8.19.7",
                    legacy.FB_IMAGE],
    "B-disk": ["docker.elastic.co/elasticsearch/elasticsearch:8.19.7", legacy.FB_IMAGE],
    "C": ["wazuh/wazuh-manager:4.14.5", "wazuh/wazuh-indexer:4.14.5"],
}


KIBANA_IMAGE = "docker.elastic.co/kibana/kibana:8.19.7"
SPEC_FILES = {"pilots": "pilot_specs.json", "confirmatory": "campaign_ready.json",
              "factorial": "campaign_factorial.json", "alerts": "campaign_alerts.json"}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_specs(which: str) -> list[dict]:
    specs = json.loads((HERE / SPEC_FILES[which]).read_text())
    if len({s["id"] for s in specs}) != len(specs):
        raise ValueError("Duplicate run ID")
    for spec in specs:
        validate_spec(spec)
    return specs


def validate_spec(spec: dict) -> None:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", spec["id"]):
        raise ValueError("Unsafe/non-lowercase run ID")
    if spec["variant"] not in IMAGE_TAGS or spec["mode"] != "udp":
        raise ValueError("Unexpected variant or source mode")
    if (BENCH / "results" / spec["id"]).exists():
        raise ValueError("Run ID collides with historical results")
    if spec["rate"] <= 0 or spec["duration"] <= 0:
        raise ValueError("Invalid production rate/duration")
    if spec.get("flood") and spec.get("fault"):
        raise ValueError("Flood and backend pause must be separate cells")
    if spec.get("flood"):
        flood = spec["flood"]
        if flood["at"] < 0 or flood["dur"] <= 0 or flood["at"] + flood["dur"] > spec["duration"]:
            raise ValueError("Flood window outside generator duration")
    if spec.get("fault"):
        fault = spec["fault"]
        if fault["type"] != "es_pause" or fault["at"] + fault["dur"] > spec["duration"]:
            raise ValueError("Invalid backend pause")
        if spec.get("post_clearance_production_s") != spec["duration"] - fault["at"] - fault["dur"]:
            raise ValueError("Incorrect post-clearance production window")
    if spec["variant"] in PIPELINE_IDS and spec["phase"] != "pilot":
        if (spec["kafka_partitions_total"], spec["kafka_consumer_threads_total"],
            spec["logstash_workers_total"]) != (2, 2, 3):
            raise ValueError("A treatment budgets differ")


def static_preflight() -> dict:
    hardware = host_snapshot()
    ac = hardware["ac_online"]
    free = os.statvfs(BENCH)
    free_gib = free.f_bavail * free.f_frsize / 1024**3
    # The controller is deliberately pinned to 8–11 with other desktop tasks.
    # Its current sched affinity is narrower than the cgroup's allowed CPUs;
    # taskset can still place generator children on 12–19. Check the effective
    # cpuset and online CPUs, rather than the controller's inherited mask.
    def parse_cpu_list(value: str) -> set[int]:
        cpus = set()
        for part in value.strip().split(","):
            if not part:
                continue
            ends = part.split("-")
            cpus.update(range(int(ends[0]), int(ends[-1]) + 1))
        return cpus

    online = parse_cpu_list(Path("/sys/devices/system/cpu/online").read_text())
    cpuset_path = Path("/sys/fs/cgroup/cpuset.cpus.effective")
    allowed = parse_cpu_list(cpuset_path.read_text()) if cpuset_path.exists() else online
    available_cpus = online & allowed
    required_cpus = set(range(0, 8)) | set(range(12, 20))
    return {
        "no_turbo": hardware["no_turbo"],
        "ac_online": ac,
        "free_gib": round(free_gib, 1),
        "cpu_freq_samples_present": all(v is not None for v in hardware["cpu_khz"].values()),
        "required_cpu_affinity_available": required_cpus.issubset(available_cpus),
        "ready_for_pilots": (hardware["no_turbo"] == "1" and bool(ac)
                             and all(value == "1" for value in ac)
                             and free_gib >= 20
                             and required_cpus.issubset(available_cpus)
                             and all(v is not None for v in hardware["cpu_khz"].values())),
        "checks_are_read_only": True,
    }


def require_factorial_lock() -> None:
    """Campaign 3 (factorial topic x pipeline cells and the full-stack cost run) is
    pre-registered: the spec file hash is frozen before the first execution."""
    path = HERE / "factorial_lock.json"
    if not path.exists():
        raise RuntimeError("Factorial campaign is locked until campaign_factorial.json is frozen")
    lock = json.loads(path.read_text())
    if lock.get("campaign_sha256") != sha256(HERE / "campaign_factorial.json"):
        raise RuntimeError("Factorial specs changed after their lock")
    if not lock.get("expectations"):
        raise RuntimeError("Factorial lock lacks pre-registered expectations")


def docker_image_identifiers(variant: str, extra_services: tuple[str, ...] = ()) -> dict:
    out = {}
    tags = list(IMAGE_TAGS[variant]) + ([KIBANA_IMAGE] if "kibana" in extra_services else [])
    for tag in tags:
        proc = subprocess.run(["docker", "image", "inspect", tag, "--format", "{{json .}}"],
                              capture_output=True, text=True, timeout=15)
        if proc.returncode:
            raise RuntimeError(f"Image unavailable locally: {tag}: {proc.stderr.strip()}")
        image = json.loads(proc.stdout)
        out[tag] = {"id": image["Id"], "repo_digests": image.get("RepoDigests", [])}
    return out


def require_protocol_lock() -> None:
    path = HERE / "protocol_lock.json"
    if not path.exists():
        raise RuntimeError("Confirmatory runs are locked until pilots and protocol review")
    lock = json.loads(path.read_text())
    if lock.get("campaign_sha256") != sha256(HERE / "campaign_ready.json"):
        raise RuntimeError("Campaign specs changed after protocol lock")
    if lock.get("pilot_specs_sha256") != sha256(HERE / "pilot_specs.json"):
        raise RuntimeError("Pilot specs changed after protocol lock")
    probe_relative = Path(lock.get("overhead_probe_file", ""))
    probe = (HERE / probe_relative).resolve()
    if not probe.is_relative_to(NEW_RESULTS.resolve()) or not probe.is_file() or \
            lock.get("overhead_probe_sha256") != sha256(probe):
        raise RuntimeError("Generator overhead probe changed or missing")
    pilots = load_specs("pilots")
    if set(lock.get("pilot_artifact_sha256", {})) != {spec["id"] for spec in pilots}:
        raise RuntimeError("Protocol lock does not cover every pilot")
    for pilot in pilots:
        run_dir = NEW_RESULTS / pilot["id"]
        for name, expected in lock["pilot_artifact_sha256"][pilot["id"]].items():
            artifact = run_dir / name
            if not artifact.is_file() or sha256(artifact) != expected:
                raise RuntimeError(f"Pilot artifact changed or missing: {pilot['id']}/{name}")
        assessment = json.loads((run_dir / "execution_assessment.json").read_text())
        if not assessment["execution_valid"]:
            raise RuntimeError(f"Pilot execution invalid: {pilot['id']}")
    if not lock.get("review_notes"):
        raise RuntimeError("Protocol lock lacks scientific review notes")


def compose(spec: dict, *args: str, runtime: Path | None = None,
            profiles: tuple[str, ...] = ("kafka",)) -> None:
    env = os.environ.copy()
    if runtime is not None:
        env["LS_PIPELINES_YML"] = str(runtime / "pipelines.yml")
        env["LS_PIPELINE_DIR"] = str(runtime / "pipeline")
    profile_args = [arg for profile in profiles for arg in ("--profile", profile)]
    proc = subprocess.run(["docker", "compose", *profile_args, *args],
                          cwd=BENCH, env=env, capture_output=True, text=True, timeout=600)
    if proc.returncode:
        raise RuntimeError(f"docker compose {' '.join(args)}: {proc.stdout}\n{proc.stderr}")


def ensure_elastic() -> None:
    legacy.sh(f"cd {legacy.WZ_DIR} && docker compose -f compose-bench.yml stop", check=False)
    if not legacy.es_ok():
        compose({}, "up", "-d", "es")
        legacy.wait(legacy.es_ok, 300, "Elasticsearch")
    pipeline = requests.get(f"{legacy.ES}/_ingest/pipeline/bench-final", timeout=5)
    if pipeline.status_code != 200:
        subprocess.run([legacy.PY, str(BENCH / "es_setup.py")], check=True, timeout=120)


def reset_topics(variant: str) -> None:
    kt = "docker exec bench-kafka kafka-topics.sh --bootstrap-server localhost:9092"
    for topic in ("bench-nginx", "bench-auth", "bench-shared"):
        legacy.sh(f"{kt} --delete --topic {topic}", check=False)
    def absent():
        topics = legacy.sh(f"{kt} --list", check=False).splitlines()
        return not any(x in topics for x in ("bench-nginx", "bench-auth", "bench-shared"))
    legacy.wait(absent, 90, "old revision Kafka topics deleted")
    for topic, partitions in TOPICS[variant]:
        legacy.sh(f"{kt} --create --topic {topic} --partitions {partitions} --replication-factor 1")


def ensure_wazuh() -> None:
    compose({}, "stop", "logstash", "kafka", "es")
    legacy.sh(f"cd {legacy.WZ_DIR} && docker compose -f compose-bench.yml up -d")
    legacy.wait(legacy.wz_ok, 600, "Wazuh indexer")
    legacy.wait(lambda: "wazuh-analysisd is running" in legacy.sh(
        "docker exec bench-wazuh-manager /var/ossec/bin/wazuh-control status", check=False),
        600, "Wazuh manager")
    if not legacy.wazuh_configured():
        legacy.wazuh_setup(preserve_archives=True)
        if not legacy.wazuh_configured():
            raise RuntimeError("Wazuh archives measurement hook missing")


def kibana_ok() -> bool:
    try:
        status = requests.get("http://localhost:5601/api/status", timeout=5).json()
        return status.get("status", {}).get("overall", {}).get("level") == "available"
    except Exception:
        return False


def ensure_extra_services(spec: dict) -> None:
    """Full-stack cost cell: Kibana (same image family, SUT CPUs) idles beside the
    ingestion containers so that its footprint is sampled. Fleet Server and the
    detection rules need Elasticsearch security and are not part of this cell."""
    extra = tuple(spec.get("extra_services", ()))
    if "kibana" in extra:
        compose(spec, "up", "-d", "--no-deps", "kibana", profiles=("kafka", "cost"))
        legacy.wait(kibana_ok, 420, "Kibana")
    else:
        compose(spec, "stop", "kibana", profiles=("kafka", "cost"))


def ensure_stack(spec: dict, runtime: Path | None) -> None:
    variant = spec["variant"]
    if variant == "C":
        ensure_wazuh()
        return
    ensure_elastic()
    if variant == "B-disk":
        compose(spec, "stop", "logstash", "kafka")
        ensure_extra_services(spec)
        return
    compose(spec, "stop", "logstash")
    compose(spec, "up", "-d", "kafka")
    legacy.wait(lambda: "healthy" in legacy.sh(
        "docker inspect -f '{{.State.Health.Status}}' bench-kafka", check=False),
        180, "Kafka")
    reset_topics(variant)
    compose(spec, "up", "-d", "--no-deps", "--force-recreate", "logstash", runtime=runtime)
    legacy.wait(lambda: legacy.logstash_running(PIPELINE_IDS[variant]), 240, "Logstash pipelines")
    ensure_extra_services(spec)


def collector_config(spec: dict, source: str) -> str:
    mapped = dict(spec, variant="A" if spec["variant"] in PIPELINE_IDS else "Bdisk")
    config = legacy.filebeat_config(mapped, source, spec["id"])
    original = f'fields: {{run: "{spec["id"]}"}}'
    if config.count(original) != 1:
        raise ValueError("Filebeat field placement changed")
    config = config.replace(original, f'fields: {{run: "{spec["id"]}", source: "{source}"}}')
    if TOPICS.get(spec["variant"]) == (("bench-shared", 2),):
        config = config.replace(f'topic: "bench-{source}"', 'topic: "bench-shared"')
    return config


def start_collector(spec: dict, source: str, run_dir: Path) -> tuple[str, str]:
    name = f"bench-fb-{source}"
    legacy.sh(f"docker rm -f {name}", check=False)
    path = run_dir / f"filebeat-{source}.yml"
    path.write_text(collector_config(spec, source))
    path.chmod(0o644)
    legacy.sh(f"docker run -d --name {name} --network bench --cpuset-cpus {legacy.SRC_CPUS} "
              f"-v {path}:/usr/share/filebeat/filebeat.yml:ro {legacy.FB_IMAGE} "
              "filebeat -e --strict.perms=false")
    ip = legacy.sh(f"docker inspect -f '{{{{.NetworkSettings.Networks.bench.IPAddress}}}}' {name}")
    legacy.wait(lambda: legacy._try(ip), 120, f"Filebeat {source}")
    return name, ip


def generator_command(spec: dict, run_dir: Path, source: str, tag: str,
                      rate: float, duration: float, start_at: float,
                      seq_start: int, destination: tuple[str, int]) -> list[str]:
    seed = int.from_bytes(hashlib.sha256(f"{spec['id']}:{tag}".encode()).digest()[:4], "big")
    prefix = run_dir / f"gen-{tag}"
    return ["taskset", "-c", legacy.SRC_CPUS, legacy.PY, str(BENCH / "gen.py"),
            "--mode", "udp", "--kind", source, "--rate", str(rate),
            "--duration", str(duration), "--start-at", str(start_at),
            "--seq-start", str(seq_start), "--seed", str(seed),
            "--out", str(prefix), "--events-out", str(prefix) + ".events.bin",
            "--host", destination[0], "--port", str(destination[1])]


def fault_worker(spec: dict, t_start: float, record: dict) -> tuple[threading.Thread, threading.Event]:
    fault = spec["fault"]
    backend = "bench-wazuh-indexer" if spec["variant"] == "C" else "bench-es"
    cancel = threading.Event()
    def work():
        paused = False
        try:
            if cancel.wait(max(0, t_start + fault["at"] - time.time())):
                return
            record["request_start_ns"] = time.time_ns()
            legacy.sh(f"docker pause {backend}")
            paused = True
            record["effective_start_ns"] = time.time_ns()
            cancel.wait(max(0, t_start + fault["at"] + fault["dur"] - time.time()))
            record["request_clear_ns"] = time.time_ns()
            legacy.sh(f"docker unpause {backend}")
            paused = False
            record["effective_end_ns"] = time.time_ns()
            legacy.wait(legacy.wz_ok if spec["variant"] == "C" else legacy.es_ok,
                        180, "backend ready after pause", step=1)
            record["ready_ns"] = time.time_ns()
        except Exception as exc:
            record["error"] = repr(exc)
        finally:
            if paused:
                legacy.sh(f"docker unpause {backend}", check=False)
    thread = threading.Thread(target=work, daemon=True)
    thread.start()
    return thread, cancel


def distinct_complete(data: dict, manifests: dict) -> bool:
    for manifest in manifests.values():
        events = read_events(NEW_RESULTS / manifest["run_id"] / manifest["event_records_file"], manifest)
        sent = events["seq"][events["sent_ok"] == 1]
        found = np.unique(data["seq"][(data["seq"] >= manifest["seq_start"]) &
                                         (data["seq"] < manifest["seq_end"])])
        if len(np.setdiff1d(sent, found, assume_unique=True)):
            return False
    return True


def final_scan(spec: dict, manifests: dict, base: int, es: str,
               index: str, run_dir: Path) -> tuple[dict, dict]:
    total = sum(m["n_sent"] for m in manifests.values())
    deadline = time.monotonic() + spec["drain_timeout"]
    query = {"range": {"bench.seq": {"gte": base, "lt": base + 3_000_000_000}}}
    last_data = None
    while time.monotonic() < deadline:
        if legacy.count(index, es, base) >= total:
            scan_start = time.time_ns()
            last_data = analyze.fetch(es, index, query)
            if distinct_complete(last_data, manifests):
                time.sleep(spec["stable_s"])
                scan_start = time.time_ns()
                last_data = analyze.fetch(es, index, query)
                if distinct_complete(last_data, manifests):
                    return last_data, {"status": "complete", "start_ns": scan_start,
                                       "end_ns": time.time_ns()}
        # Duplicates can make the count threshold true while distinct IDs are
        # absent. Avoid a full scroll every ten seconds in that situation.
        time.sleep(min(60, max(0, deadline - time.monotonic())))
    scan_start = time.time_ns()
    last_data = analyze.fetch(es, index, query)
    return last_data, {"status": "complete" if distinct_complete(last_data, manifests)
                       else "timed_out_incomplete", "start_ns": scan_start,
                       "end_ns": time.time_ns()}


def quality_queries(spec: dict, es: str, base: int) -> dict:
    if spec["variant"] == "C":
        return {"parse_failure_counts": "not_comparable_wazuh_native_analysis"}
    session = analyze.session(es)
    run_id = spec["id"]
    out = {"parse_failure_counts": {}, "wrong_source_index_counts": {}}
    for source in (("nginx", "auth") if spec.get("flood") else ("nginx",)):
        index = f"bench-{run_id}-{source}"
        query = {"query": {"bool": {"filter": [
            {"range": {"bench.seq": {"gte": base, "lt": base + 3_000_000_000}}},
            {"bool": {"should": [
                {"terms": {"tags": ["_grokparsefailure", "_dateparsefailure"]}},
                {"terms": {"tags.keyword": ["_grokparsefailure", "_dateparsefailure"]}}
            ], "minimum_should_match": 1}}
        ]}}}
        response = session.get(f"{es}/{index}/_count", json=query, timeout=30)
        if response.status_code != 404:
            response.raise_for_status()
            out["parse_failure_counts"][source] = response.json()["count"]
        else:
            out["parse_failure_counts"][source] = None
    if spec.get("flood"):
        wrong = (("nginx", base + 2_000_000_000, base + 3_000_000_000),
                 ("auth", base, base + 2_000_000_000))
        for index_source, lo, hi in wrong:
            response = session.get(f"{es}/bench-{run_id}-{index_source}/_count",
                                   json={"query": {"range": {"bench.seq": {"gte": lo, "lt": hi}}}},
                                   timeout=30)
            response.raise_for_status()
            out["wrong_source_index_counts"][index_source] = response.json()["count"]
    return out


def config_manifest(spec: dict, run_dir: Path, runtime_hashes: dict,
                    images: dict) -> dict:
    code = [BENCH / name for name in ("gen.py", "analyze.py", "es_setup.py", "run.py",
                                       "docker-compose.yml")]
    code += sorted(HERE.glob("*.py"))
    code += [BENCH / "wazuh/compose-bench.yml", BENCH / "wazuh/config/wazuh_cluster/wazuh_manager.conf"]
    return {
        "files_sha256": {str(path.relative_to(BENCH)): sha256(path) for path in code},
        "runtime_sha256": runtime_hashes,
        "collector_sha256": {path.name: sha256(path) for path in run_dir.glob("filebeat-*.yml")},
        "images": images,
        "run_spec_sha256": sha256(run_dir / "spec.json"),
    }


def require_telemetry(probe: dict, variant: str, sources: tuple[str, ...]) -> None:
    if not probe["host"]["cpu_khz"] or not all(
            value is not None for value in probe["host"]["cpu_khz"].values()):
        raise RuntimeError("SUT CPU frequencies unavailable")
    for source in (() if variant == "C" else sources):
        record = probe["collectors"].get(source, {})
        if "error" in record or not {"InErrors", "RcvbufErrors"}.issubset(
                record.get("udp_namespace", {})):
            raise RuntimeError(f"Required UDP counters unavailable for {source}: {record}")
        if not record.get("filebeat", {}).get("queue"):
            raise RuntimeError(f"Filebeat queue statistics unavailable for {source}")
    if variant == "C" and ("error" in probe.get("wazuh_udp_namespace", {}) or
                           not {"InErrors", "RcvbufErrors"}.issubset(
                               probe.get("wazuh_udp_namespace", {}))):
        raise RuntimeError("Wazuh manager UDP namespace counters unavailable")
    if variant in PIPELINE_IDS and (
            "error" in probe.get("logstash", {}) or not probe.get("logstash")):
        raise RuntimeError("Logstash pipeline telemetry unavailable")


def container_medians(stats_path: Path) -> dict:
    """Median CPU (cores) and memory (GiB) per container over the sampled run,
    excluding the first and last two samples."""
    import csv
    by_name: dict[str, list[tuple[float, float]]] = {}
    with stats_path.open() as handle:
        for row in csv.DictReader(handle):
            by_name.setdefault(row["name"], []).append((float(row["cpu_pct"]) / 100,
                                                        float(row["mem_mib"]) / 1024))
    out = {}
    for name, samples in sorted(by_name.items()):
        samples = samples[2:-2] or samples
        out[name] = {"cpu_cores": float(np.median([c for c, _ in samples])),
                     "mem_gib": float(np.median([m for _, m in samples])),
                     "samples": len(samples)}
    return out


def udp_counter_deltas(first: dict, last: dict, variant: str,
                       sources: tuple[str, ...]) -> dict:
    names = ("wazuh-manager",) if variant == "C" else sources
    out = {}
    for name in names:
        a = (first["wazuh_udp_namespace"] if variant == "C" else
             first["collectors"][name]["udp_namespace"])
        b = (last["wazuh_udp_namespace"] if variant == "C" else
             last["collectors"][name]["udp_namespace"])
        delta = {key: b[key] - value for key, value in a.items() if key in b}
        if any(value < 0 for value in delta.values()):
            raise RuntimeError(f"UDP namespace counter reset during run: {name}")
        out[name] = delta
    return out


def execute_one(spec: dict) -> dict:
    validate_spec(spec)
    if not static_preflight()["ready_for_pilots"]:
        raise RuntimeError("Host preflight failed: Turbo off, AC and >=20 GiB free required")
    run_dir = NEW_RESULTS / spec["id"]
    run_dir.mkdir(parents=True, exist_ok=False)  # never overwrite a partial run
    (run_dir / "spec.json").write_text(json.dumps(spec, indent=2) + "\n")
    runtime = run_dir / "runtime" if spec["variant"] in PIPELINE_IDS else None
    runtime_hashes = render(spec["variant"], runtime) if runtime else {}
    collectors = {}
    telemetry = sampler = None
    generator_logs = []
    procs = []
    fault_thread = fault_cancel = None
    try:
        images = docker_image_identifiers(spec["variant"], tuple(spec.get("extra_services", ())))
        ensure_stack(spec, runtime)
        is_wazuh = spec["variant"] == "C"
        es = legacy.WZ if is_wazuh else legacy.ES
        index = "wazuh-archives-*" if is_wazuh else f"bench-{spec['id']}-*"
        sources = ("nginx", "auth") if spec.get("flood") else ("nginx",)
        if is_wazuh:
            ip = legacy.sh("docker inspect -f '{{.NetworkSettings.Networks.bench.IPAddress}}' bench-wazuh-manager")
            destinations = {source: (ip, 514) for source in sources}
        else:
            collectors = {source: start_collector(spec, source, run_dir) for source in sources}
            destinations = {source: (collectors[source][1], 5514) for source in sources}
        (run_dir / "config_manifest.json").write_text(
            json.dumps(config_manifest(spec, run_dir, runtime_hashes, images), indent=2) + "\n")
        telemetry = Telemetry(run_dir / "telemetry.jsonl", spec["variant"],
                              {source: ip for source, (_, ip) in collectors.items()})
        probe = telemetry.sample()
        require_telemetry(probe, spec["variant"], sources)
        (run_dir / "telemetry_initial.json").write_text(json.dumps(probe, indent=2) + "\n")
        telemetry.start()
        sampler = legacy.Sampler(str(run_dir / "stats.csv"))
        sampler.start()
        base = (int(time.time()) - 1_700_000_000) * 10_000_000_000
        t_start = time.time() + 5
        jobs = [("nginx", "nginx", spec["rate"], spec["duration"], t_start, base)]
        if spec.get("flood"):
            flood = spec["flood"]
            if flood["rate"]:
                jobs.append(("flood", "nginx", flood["rate"], flood["dur"],
                             t_start + flood["at"], base + 1_000_000_000))
            jobs.append(("auth", "auth", flood["auth_rate"], spec["duration"],
                         t_start, base + 2_000_000_000))
        for tag, source, rate, duration, when, seq_start in jobs:
            handle = (run_dir / f"gen-{tag}.log").open("w")
            generator_logs.append(handle)
            proc = subprocess.Popen(generator_command(spec, run_dir, source, tag, rate,
                                                      duration, when, seq_start,
                                                      destinations[source]),
                                    stdout=handle, stderr=subprocess.STDOUT)
            procs.append((tag, proc))
        fault_record = {}
        if spec.get("fault"):
            fault_thread, fault_cancel = fault_worker(spec, t_start, fault_record)
        exit_codes = {tag: process.wait() for tag, process in procs}
        if fault_thread:
            fault_thread.join()
        if any(code != 0 for code in exit_codes.values()) or fault_record.get("error"):
            raise RuntimeError(f"Generator/fault failure: {exit_codes}; {fault_record}")
        manifests = {tag: json.loads((run_dir / f"gen-{tag}.json").read_text())
                     for tag, _ in procs}
        for tag, manifest in manifests.items():
            manifest["run_id"] = spec["id"]
            event_path = run_dir / manifest["event_records_file"]
            if sha256(event_path) != manifest["event_records_sha256"]:
                raise RuntimeError(f"Generator event-log hash mismatch: {tag}")
            read_events(event_path, manifest)
        data, scan = final_scan(spec, manifests, base, es, index, run_dir)
        # Persist the complete raw snapshot before any ancillary API check can
        # fail; a failed quality query must not destroy the only receipt copy.
        analyze.save_raw(str(run_dir / "raw.npz"), data)
        quality = quality_queries(spec, es, base)
        telemetry.stop.set()
        telemetry.join()
        final_probe = telemetry.sample()
        require_telemetry(final_probe, spec["variant"], sources)
        udp_deltas = udp_counter_deltas(probe, final_probe, spec["variant"], sources)
        (run_dir / "telemetry_final.json").write_text(json.dumps(final_probe, indent=2) + "\n")
        if not (run_dir / "telemetry.jsonl").stat().st_size:
            raise RuntimeError("No periodic telemetry was saved")
        sampler.stop.set()
        sampler.join()
        metrics = {}
        for tag, manifest in manifests.items():
            row, series = summarize_stream(
                data, manifest, run_dir / manifest["event_records_file"], spec,
                fault=fault_record if fault_thread else None,
                cutoff_ns=scan["start_ns"],
                campaign_start_ns=int(t_start * 1e9))
            metrics[tag] = row
            write_backlog(run_dir / f"backlog-{tag}.csv", series)
        result = {"id": spec["id"], "spec": spec, "status": scan["status"],
                  "container_resource_medians": container_medians(run_dir / "stats.csv"),
                  "scheduled_start_ns": int(t_start * 1e9),
                  "scan": scan, "fault": fault_record or None,
                  "quality_queries": quality,
                  "streams": metrics,
                  "udp_namespace_counter_deltas": udp_deltas,
                  "telemetry_file": "telemetry.jsonl",
                  "confirmed_receiver_drop_count": None,
                  "note": "Missing at scan is not automatically a confirmed drop"}
        target = run_dir / "result.json"
        target.with_suffix(".json.tmp").write_text(json.dumps(result, indent=2) + "\n")
        target.with_suffix(".json.tmp").replace(target)
        assessment = assess_saved_run(run_dir)
        (run_dir / "execution_assessment.json").write_text(
            json.dumps(assessment, indent=2) + "\n")
        if not assessment["execution_valid"]:
            raise RuntimeError(f"Predeclared execution check failed: {assessment['invalid_reasons']}")
        if not is_wazuh and not spec.get("keep_index", True):
            cleanup = {}
            for source in sources:
                name = f"bench-{spec['id']}-{source}"
                response = analyze.session(es).delete(f"{es}/{name}", timeout=30)
                cleanup[name] = {"http_status": response.status_code,
                                 "deleted_after_raw_saved": response.ok}
            (run_dir / "index_cleanup.json").write_text(json.dumps(cleanup, indent=2) + "\n")
        return result
    except Exception as exc:
        (run_dir / "failure.json").write_text(json.dumps(
            {"error": repr(exc), "at_ns": time.time_ns()}, indent=2) + "\n")
        raise
    finally:
        if fault_cancel:
            fault_cancel.set()
        if fault_thread and fault_thread.is_alive():
            fault_thread.join(timeout=20)
        for _, process in procs:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        if telemetry and telemetry.is_alive():
            telemetry.stop.set()
            telemetry.join()
        if sampler and sampler.is_alive():
            sampler.stop.set()
            sampler.join()
        for handle in generator_logs:
            handle.close()
        for source, (name, _) in collectors.items():
            legacy.sh(f"docker logs {name} > {run_dir}/filebeat-{source}.log 2>&1", check=False)
            legacy.sh(f"docker rm -f {name}", check=False)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("plan", "preflight", "execute"))
    parser.add_argument("--set", choices=("pilots", "confirmatory", "factorial", "alerts"), default="pilots")
    parser.add_argument("--hours", type=float, default=24)
    parser.add_argument("--id", help="one run ID from the selected set")
    args = parser.parse_args()
    specs = load_specs(args.set)
    if args.id:
        specs = [spec for spec in specs if spec["id"] == args.id]
        if not specs:
            raise ValueError("Requested ID is not in this set")
    if args.command == "plan":
        print(json.dumps({"set": args.set, "runs": len(specs),
                          "production_hours": round(sum(s["duration"] for s in specs) / 3600, 2),
                          "new_results": str(NEW_RESULTS),
                          "order": [s["id"] for s in specs]}, indent=2))
        return
    if args.command == "preflight":
        print(json.dumps(static_preflight(), indent=2))
        return
    if args.set == "confirmatory":
        require_protocol_lock()
    if args.set == "factorial":
        require_factorial_lock()
    if not static_preflight()["ready_for_pilots"]:
        raise RuntimeError("Read-only preflight failed; no OS setting is changed here")
    NEW_RESULTS.mkdir(exist_ok=True)
    started = time.monotonic()
    with (NEW_RESULTS / ".campaign.lock").open("w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("Another revision campaign process is active") from exc
        for spec in specs:
            if (NEW_RESULTS / spec["id"] / "result.json").exists():
                assessment_path = NEW_RESULTS / spec["id"] / "execution_assessment.json"
                if not assessment_path.exists() or not json.loads(
                        assessment_path.read_text()).get("execution_valid"):
                    raise RuntimeError(f"Existing run requires review and a fresh replacement ID: {spec['id']}")
                print(f"skip completed {spec['id']}", flush=True)
                continue
            if time.monotonic() - started + spec["duration"] + spec["drain_timeout"] > args.hours * 3600:
                print(f"stop before {spec['id']}: session time budget", flush=True)
                break
            print(f"starting {spec['id']}", flush=True)
            result = execute_one(spec)
            print(f"finished {spec['id']}: {result['status']}", flush=True)


if __name__ == "__main__":
    main()
