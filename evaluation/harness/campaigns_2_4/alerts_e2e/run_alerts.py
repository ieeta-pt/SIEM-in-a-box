"""End-to-end alert cells (campaign 4): production -> Kibana detection alert.

Reuses run_revision.execute_one unchanged. The only differences from a
campaign-2 cell are the storage side: a secured Elasticsearch (bench-es-sec,
port 9202) with Kibana and two enabled detection rules over bench-*,

  bench-auth-each       query rule, one alert per sshd failed login
                        (equivalent to Wazuh rule 5710)
  bench-auth-threshold  threshold rule, >= 5 failed logins from one source.ip
                        (equivalent to Wazuh rule 5712)

both scheduled every minute with a 6-minute look-back. After the run, every
alert of the run is read from .alerts-security.alerts-default, matched to its
source event through the generator's bseq in `message`, and saved as
alerts_e2e.json; a summary is appended to result.json under "alerts_e2e".

Commands: plan | execute --id RUN_ID | stop (stop the secured pair)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import requests

HERE = Path(__file__).resolve().parent          # alerts_e2e/
REV = HERE.parent                               # campaigns_2_4/
BENCH = REV.parent
sys.path.insert(0, str(BENCH))
sys.path.insert(0, str(REV))

import analyze  # noqa: E402
import es_setup  # noqa: E402
import run as legacy  # noqa: E402
import run_revision as rr  # noqa: E402
from config_revision import PIPELINE_IDS, render  # noqa: E402

ES_SEC = "http://localhost:9202"
ES_SEC_INTERNAL = "http://bench-es-sec:9200"
KIBANA = "http://localhost:5602"
ES_USER = "elastic"
ES_PASSWORD = os.environ.get("BENCH_ES_PASSWORD", "benchsecret")
KIBANA_PASSWORD = os.environ.get("BENCH_KIBANA_PASSWORD", "kibanasecret")
ALERTS_INDEX = ".alerts-security.alerts-default"
SPEC_FILE = REV / "campaign_alerts.json"
LOCK_FILE = REV / "alerts_lock.json"
RULES = {
    "bench-auth-each": {
        "rule_id": "bench-auth-each", "name": "bench: sshd failed login (one alert per event)",
        "description": "Benchmark rule equivalent to Wazuh 5710", "type": "query",
        "query": "fields.source:auth", "language": "kuery", "index": ["bench-*"],
        "risk_score": 21, "severity": "low", "interval": "1m", "from": "now-6m", "to": "now",
        "max_signals": 1000, "enabled": True,
    },
    "bench-auth-threshold": {
        "rule_id": "bench-auth-threshold", "name": "bench: sshd brute force (>= 5 failed logins on one host)",
        "description": "Benchmark rule equivalent to Wazuh 5712", "type": "threshold",
        "query": "fields.source:auth", "language": "kuery", "index": ["bench-*"],
        "threshold": {"field": ["host.name"], "value": 5},
        "risk_score": 73, "severity": "high", "interval": "1m", "from": "now-6m", "to": "now",
        "enabled": True,
    },
}
BSEQ = re.compile(r"bseq=(\d+):(\d+)")


# ----------------------------------------------------------------- helpers
def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def es_session() -> requests.Session:
    s = requests.Session()
    s.auth = (ES_USER, ES_PASSWORD)
    return s


_original_session = analyze.session


def session_with_auth(es: str) -> requests.Session:
    if es.startswith(ES_SEC):
        return es_session()
    return _original_session(es)


def es_sec_ok() -> bool:
    try:
        return es_session().get(f"{ES_SEC}/_cluster/health", timeout=5).json()["status"] in ("green", "yellow")
    except Exception:
        return False


def kibana_ok() -> bool:
    try:
        status = requests.get(f"{KIBANA}/api/status", timeout=5).json()
        return status.get("status", {}).get("overall", {}).get("level") == "available"
    except Exception:
        return False


def kibana_session() -> requests.Session:
    s = requests.Session()
    s.auth = (ES_USER, ES_PASSWORD)
    s.headers.update({"kbn-xsrf": "bench", "Content-Type": "application/json"})
    return s


def compose_sec(*args: str) -> None:
    proc = subprocess.run(["docker", "compose", "-f", str(HERE / "compose-alerts.yml"), *args],
                          cwd=BENCH, capture_output=True, text=True, timeout=600)
    if proc.returncode:
        raise RuntimeError(f"docker compose (benchsec) {' '.join(args)}: {proc.stdout}\n{proc.stderr}")


def require_alerts_lock() -> None:
    if not LOCK_FILE.exists():
        raise RuntimeError("Alert cells are locked until campaign_alerts.json is frozen")
    lock = json.loads(LOCK_FILE.read_text())
    if lock.get("campaign_sha256") != sha256(SPEC_FILE):
        raise RuntimeError("Alert specs changed after their lock")
    if not lock.get("expectations"):
        raise RuntimeError("Alert lock lacks pre-registered expectations")


def load_alert_specs() -> list[dict]:
    specs = json.loads(SPEC_FILE.read_text())
    if len({s["id"] for s in specs}) != len(specs):
        raise ValueError("Duplicate run ID")
    for spec in specs:
        rr.validate_spec(spec)
        if spec["variant"] not in PIPELINE_IDS:
            raise ValueError("Alert cells need a Kafka/Logstash variant")
    return specs


# ----------------------------------------------------------------- stack
def render_secured(variant: str, directory: Path) -> dict[str, str]:
    """Same pipelines as campaign 2/3, with the output pointed at the secured node."""
    hashes = render(variant, directory)
    for conf in (directory / "pipeline").glob("*.conf"):
        text = conf.read_text()
        assert text.count('hosts => ["http://es:9200"]') == 1, conf
        text = text.replace('hosts => ["http://es:9200"]',
                            f'hosts => ["{ES_SEC_INTERNAL}"]\n    user => "{ES_USER}"\n    password => "{ES_PASSWORD}"')
        conf.write_text(text)
    return {str(p.relative_to(directory)): sha256(p)
            for p in [directory / "pipelines.yml", *sorted((directory / "pipeline").iterdir())]}


def install_measurement(s: requests.Session) -> None:
    for name, body in es_setup.PIPELINES.items():
        s.put(f"{ES_SEC}/_ingest/pipeline/{name}", json=body, timeout=30).raise_for_status()
    # Same measurement template as campaign 2, plus keyword mappings for the
    # fields the detection rules filter and aggregate on (dynamic mapping would
    # make host.name a text field, which a threshold rule cannot aggregate).
    template = json.loads(json.dumps(es_setup.TEMPLATE))
    template["template"]["mappings"]["properties"].update({
        "host": {"properties": {"name": {"type": "keyword"}}},
        "source": {"properties": {"ip": {"type": "keyword"}}},
        "user": {"properties": {"name": {"type": "keyword"}}},
        "fields": {"properties": {"source": {"type": "keyword"}, "run": {"type": "keyword"}}},
    })
    s.put(f"{ES_SEC}/_index_template/bench", json=template, timeout=30).raise_for_status()
    s.put(f"{ES_SEC}/_cluster/settings",
          json={"persistent": {"action.destructive_requires_name": False}}, timeout=30).raise_for_status()


def ensure_rules() -> dict:
    k = kibana_session()
    last = None
    for attempt in range(6):
        r = k.post(f"{KIBANA}/api/detection_engine/index", timeout=60)   # idempotent, 409 if present
        if r.status_code in (200, 409):
            break
        last = f"{r.status_code} {r.text[:200]}"
        time.sleep(10)
    else:
        raise RuntimeError(f"Detection engine not ready: {last}")
    installed = {}
    for rule_id, body in RULES.items():
        r = k.get(f"{KIBANA}/api/detection_engine/rules", params={"rule_id": rule_id}, timeout=30)
        if r.status_code == 404:
            r = k.post(f"{KIBANA}/api/detection_engine/rules", json=body, timeout=60)
        else:
            r = k.put(f"{KIBANA}/api/detection_engine/rules", json=body, timeout=60)
        r.raise_for_status()
        installed[rule_id] = {k2: r.json().get(k2) for k2 in ("id", "name", "type", "interval", "from", "enabled", "max_signals", "threshold", "updated_at")}
    return installed


def ensure_stack_secured(spec: dict, runtime: Path | None) -> None:
    variant = spec["variant"]
    # unsecured bench storage off, Kafka + Logstash of the bench project reused
    rr.compose(spec, "stop", "es", "logstash", "kibana", profiles=("kafka", "cost"))
    legacy.sh(f"cd {legacy.WZ_DIR} && docker compose -f compose-bench.yml stop", check=False)
    compose_sec("up", "-d", "es-sec")
    legacy.wait(es_sec_ok, 300, "secured Elasticsearch")
    s = es_session()
    s.post(f"{ES_SEC}/_security/user/kibana_system/_password",
           json={"password": KIBANA_PASSWORD}, timeout=30).raise_for_status()
    install_measurement(s)
    rr.compose(spec, "up", "-d", "kafka")
    legacy.wait(lambda: "healthy" in legacy.sh(
        "docker inspect -f '{{.State.Health.Status}}' bench-kafka", check=False), 180, "Kafka")
    rr.reset_topics(variant)
    rr.compose(spec, "up", "-d", "--no-deps", "--force-recreate", "logstash", runtime=runtime)
    legacy.wait(lambda: legacy.logstash_running(PIPELINE_IDS[variant]), 240, "Logstash pipelines")
    compose_sec("up", "-d", "kibana-sec")
    legacy.wait(kibana_ok, 420, "Kibana")
    rules = ensure_rules()
    (runtime.parent / "detection_rules.json").write_text(json.dumps(rules, indent=2) + "\n")


def stop_secured() -> None:
    compose_sec("stop")


# ----------------------------------------------------------------- alerts
def field(src: dict, dotted: str):
    """Alert documents store ECS and kibana.* fields with dotted keys; accept nested too."""
    if dotted in src:
        return src[dotted]
    node = src
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def collect_alerts(spec: dict, run_dir: Path) -> dict:
    """Match every alert of this run to its source event and summarise."""
    result = json.loads((run_dir / "result.json").read_text())
    manifest = json.loads((run_dir / "gen-auth.json").read_text())
    lo, hi = manifest["seq_start"], manifest["seq_end"]
    t0 = result["scheduled_start_ns"] / 1e9
    s = es_session()
    s.post(f"{ES_SEC}/{ALERTS_INDEX}/_refresh", timeout=30)
    per_event, threshold = {}, []
    body = {"size": 5000, "sort": [{"@timestamp": "asc"}],
            "_source": ["@timestamp", "message", "kibana.alert.rule.rule_id", "kibana.alert.original_time",
                        "kibana.alert.threshold_result", "source.ip"],
            "query": {"range": {"@timestamp": {"gte": int(t0 * 1000) - 5000, "format": "epoch_millis"}}}}
    r = s.get(f"{ES_SEC}/{ALERTS_INDEX}/_search?scroll=2m", json=body, timeout=120).json()
    hits = list(r["hits"]["hits"])
    sid = r.get("_scroll_id")
    while sid and len(r["hits"]["hits"]) == 5000:
        r = s.post(f"{ES_SEC}/_search/scroll", json={"scroll": "2m", "scroll_id": sid}, timeout=120).json()
        hits += r["hits"]["hits"]
    for hit in hits:
        src = hit["_source"]
        t_alert = datetime.fromisoformat(src["@timestamp"].replace("Z", "+00:00")).timestamp()
        rule = field(src, "kibana.alert.rule.rule_id")
        if rule == "bench-auth-threshold":
            threshold.append({"t_rel_s": t_alert - t0, "count": field(src, "kibana.alert.threshold_result.count")})
            continue
        if rule != "bench-auth-each":
            continue
        m = BSEQ.search(str(field(src, "message") or ""))
        if not m:
            continue
        seq, t_prod = int(m.group(1)), int(m.group(2)) / 1e9
        if lo <= seq < hi and seq not in per_event:
            per_event[seq] = (t_alert - t_prod, t_prod - t0)
    lat = np.array([v[0] for v in per_event.values()]) if per_event else np.array([])
    prod = np.array([v[1] for v in per_event.values()]) if per_event else np.array([])
    win = (prod >= 60) & (prod < 240) if len(prod) else np.array([], dtype=bool)
    sent_window = int(round(180 * spec["flood"]["auth_rate"]))
    summary = {
        "rules": list(RULES), "auth_sent": manifest["n_sent"], "alerts_per_event": len(per_event),
        "events_without_alert": manifest["n_sent"] - len(per_event),
        "window_sent": sent_window, "window_alerts": int(win.sum()),
        "window_without_alert_pct": round(100 * (1 - win.sum() / sent_window), 2) if sent_window else None,
        "alert_latency_window_s": ({"p50": float(np.percentile(lat[win], 50)), "p95": float(np.percentile(lat[win], 95)),
                                    "max": float(lat[win].max())} if win.any() else None),
        "alert_latency_all_s": ({"p50": float(np.percentile(lat, 50)), "p95": float(np.percentile(lat, 95)),
                                 "max": float(lat.max())} if len(lat) else None),
        "threshold_alerts_during_production": sorted(round(t["t_rel_s"], 1) for t in threshold
                                                     if 0 <= t["t_rel_s"] <= spec["duration"] + 120),
        "note": "Alert time is Kibana's alert document @timestamp (rule execution), production time comes "
                "from the generator's bseq copied into the alert; rules run every minute, so latency "
                "includes up to one schedule interval.",
    }
    (run_dir / "alerts_e2e.json").write_text(json.dumps(
        {"summary": summary, "per_event": {str(k): [round(v[0], 3), round(v[1], 3)] for k, v in per_event.items()},
         "threshold_alerts": threshold}, indent=1) + "\n")
    result["alerts_e2e"] = summary
    target = run_dir / "result.json"
    target.with_suffix(".json.tmp").write_text(json.dumps(result, indent=2) + "\n")
    target.with_suffix(".json.tmp").replace(target)
    return summary


# ----------------------------------------------------------------- main
def execute(run_id: str) -> None:
    require_alerts_lock()
    specs = [s for s in load_alert_specs() if s["id"] == run_id]
    if not specs:
        raise ValueError("Unknown alert cell")
    spec = specs[0]
    if not rr.static_preflight()["ready_for_pilots"]:
        raise RuntimeError("Host preflight failed")
    # Route every storage access of execute_one to the secured node.
    analyze.session = session_with_auth
    rr.analyze.session = session_with_auth
    legacy.analyze.session = session_with_auth
    legacy.ES = ES_SEC
    legacy.es_ok = es_sec_ok
    rr.ensure_stack = ensure_stack_secured
    rr.render = render_secured
    try:
        print(f"starting {run_id}", flush=True)
        result = rr.execute_one(spec)
        print(f"finished {run_id}: {result['status']}; waiting two rule intervals for late alerts", flush=True)
        time.sleep(150)
        summary = collect_alerts(spec, rr.NEW_RESULTS / run_id)
        print("alerts:", json.dumps(summary), flush=True)
        cleanup = {}
        for source in ("nginx", "auth"):
            name = f"bench-{run_id}-{source}"
            response = es_session().delete(f"{ES_SEC}/{name}", timeout=30)
            cleanup[name] = {"http_status": response.status_code, "deleted_after_alerts_collected": response.ok}
        (rr.NEW_RESULTS / run_id / "index_cleanup.json").write_text(json.dumps(cleanup, indent=2) + "\n")
    finally:
        stop_secured()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("plan", "execute", "stop"))
    parser.add_argument("--id")
    args = parser.parse_args()
    if args.command == "plan":
        specs = load_alert_specs()
        print(json.dumps({"runs": len(specs), "production_hours": round(sum(s["duration"] for s in specs) / 3600, 2),
                          "order": [s["id"] for s in specs]}, indent=2))
    elif args.command == "stop":
        stop_secured()
    else:
        if not args.id:
            parser.error("--id required")
        execute(args.id)


if __name__ == "__main__":
    main()
