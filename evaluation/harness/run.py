"""Run orchestrator for the SIEM-in-a-Box measurement campaign.

Usage:
  run.py campaign <campaign.json>      run every pending run (resumable)
  run.py one '<json run spec>'         run a single spec (smoke tests)

A run spec:
  {"id": "...", "variant": "A|B|Bdisk", "mode": "file|udp", "rate": 1000,
   "duration": 180, "warmup": 30,
   "fault": {"type": "es_pause|kafka_kill", "at": 60, "dur": 300},   (optional)
   "flood": {"rate": 4000, "at": 60, "dur": 180, "auth_rate": 10},   (optional)
   "partitions": 1, "workers": 2, "drain_timeout": 900}

Each run writes results/<id>/{spec,result,gen-*,filebeat-*}.json,
stats.csv and raw.npz. A run whose result.json exists is skipped.
Sanity checks stop the campaign on the first error.
"""
import json
import os
import subprocess
import sys
import threading
import time

import requests

import analyze

HERE = os.path.dirname(os.path.abspath(__file__))
ES = "http://localhost:9200"
WZ = "https://localhost:9201"          # Wazuh indexer (variant C)
WZ_DIR = os.path.join(HERE, "wazuh")
RESULTS = os.path.join(HERE, "results")
GEN_DIR = os.path.join(HERE, "data", "gen")
PY = os.path.join(HERE, ".venv", "bin", "python")
SRC_CPUS = "12-19"            # "source hosts": generator + collectors
FB_IMAGE = "docker.elastic.co/beats/filebeat:8.19.7"


def sh(cmd, check=True, capture=True):
    r = subprocess.run(cmd, shell=True, text=True, capture_output=capture)
    if check and r.returncode != 0:
        raise RuntimeError(f"command failed: {cmd}\n{r.stdout}\n{r.stderr}")
    return r.stdout.strip() if capture else ""


def log(msg):
    print(time.strftime("%H:%M:%S"), msg, flush=True)


# --------------------------------------------------------------------- stack
def es_ok():
    try:
        return requests.get(f"{ES}/_cluster/health", timeout=5).json()["status"] in ("green", "yellow")
    except Exception:
        return False


def wait(pred, timeout, what, step=2):
    t = time.time()
    while time.time() - t < timeout:
        if pred():
            return
        time.sleep(step)
    raise RuntimeError(f"timeout waiting for {what}")


def logstash_running(ids=("nginx", "auth")):
    try:
        p = requests.get("http://localhost:9600/_node/pipelines", timeout=5).json()["pipelines"]
        return all(i in p for i in ids)
    except Exception:
        return False


STATE = {"kafka_cfg": None}


def write_pipelines(workers, batch=125):
    with open(os.path.join(HERE, "configs/logstash/pipelines.yml"), "w") as f:
        f.write(f"""- pipeline.id: nginx
  path.config: "/usr/share/logstash/pipeline/nginx.conf"
  pipeline.workers: {workers}
  pipeline.batch.size: {batch}
- pipeline.id: auth
  path.config: "/usr/share/logstash/pipeline/auth.conf"
  pipeline.workers: 1
  pipeline.batch.size: {batch}
""")


def kafka_topics(partitions):
    kt = "docker exec bench-kafka kafka-topics.sh --bootstrap-server localhost:9092"
    for t in ("bench-nginx", "bench-auth"):
        sh(f"{kt} --delete --topic {t}", check=False)
    time.sleep(3)
    sh(f"{kt} --create --topic bench-nginx --partitions {partitions} --replication-factor 1")
    sh(f"{kt} --create --topic bench-auth --partitions 1 --replication-factor 1")


def ensure_stack(spec):
    """Bring up exactly the containers the variant needs, in a clean state."""
    if spec["variant"] == "C":
        sh(f"cd {HERE} && docker compose --profile kafka stop logstash kafka es", check=False)
        STATE["kafka_cfg"] = None
        running = sh("docker ps --format '{{.Names}}'", check=False).split()
        if "bench-wazuh-manager" not in running or not wz_ok():
            sh(f"cd {WZ_DIR} && docker compose -f compose-bench.yml up -d")
            wait(wz_ok, 600, "wazuh indexer")
            wait(lambda: "wazuh-analysisd is running" in sh("docker exec bench-wazuh-manager /var/ossec/bin/wazuh-control status", check=False), 600, "wazuh manager")
            time.sleep(30)
        if not wazuh_configured():
            wazuh_setup()
            if not wazuh_configured():
                raise RuntimeError("wazuh setup did not take effect")
        return
    sh(f"cd {WZ_DIR} && docker compose -f compose-bench.yml stop", check=False)
    if not es_ok():
        sh(f"cd {HERE} && docker compose up -d es")
        wait(es_ok, 300, "elasticsearch")
        sh(f"{PY} {HERE}/es_setup.py")
    if spec["variant"] == "A":
        cfg = (spec.get("partitions", 1), spec.get("workers", 2))
        running = sh("docker ps --format '{{.Names}}'", check=False).split()
        if STATE["kafka_cfg"] != cfg or "bench-kafka" not in running or "bench-logstash" not in running:
            log(f"(re)configuring Kafka/Logstash partitions={cfg[0]} workers={cfg[1]}")
            sh(f"cd {HERE} && docker compose --profile kafka stop logstash", check=False)
            write_pipelines(cfg[1])
            sh(f"cd {HERE} && docker compose --profile kafka up -d kafka")
            wait(lambda: "healthy" in sh("docker inspect -f '{{.State.Health.Status}}' bench-kafka", check=False), 180, "kafka")
            kafka_topics(cfg[0])
            os.environ["LS_CONSUMER_THREADS"] = str(cfg[0])
            sh(f"cd {HERE} && LS_CONSUMER_THREADS={cfg[0]} docker compose --profile kafka up -d --force-recreate logstash")
            wait(logstash_running, 240, "logstash pipelines")
            STATE["kafka_cfg"] = cfg
    else:
        sh(f"cd {HERE} && docker compose --profile kafka stop logstash kafka", check=False)
        STATE["kafka_cfg"] = None


# ----------------------------------------------------------------- filebeat
def filebeat_config(spec, source, run_id):
    v, mode = spec["variant"], spec["mode"]
    if mode == "file":
        inp = f"""  - type: filestream
    id: gen-{source}
    paths: ["/gen/{run_id}-{source}.log"]
    fields: {{run: "{run_id}"}}"""
        if not spec.get("collector_defaults"):
            inp += "\n    backoff.init: 250ms\n    backoff.max: 1s"
    else:
        inp = f"""  - type: udp
    id: udp-{source}
    host: "0.0.0.0:5514"
    max_message_size: 10KiB
    fields: {{run: "{run_id}"}}"""
    if v == "A":
        out = f"""output.kafka:
  hosts: ["kafka:9092"]
  topic: "bench-{source}"
  required_acks: 1
  compression: gzip"""
    else:
        out = f"""output.elasticsearch:
  hosts: ["http://es:9200"]
  index: "bench-{run_id}-{source}"
  pipeline: "{source}-parse"
  worker: {spec.get("es_workers", 1)}
setup.template.name: "bench"
setup.template.pattern: "bench-*"
setup.template.enabled: false
setup.ilm.enabled: false"""
    queue = ""
    if v == "Bdisk":
        queue = """queue.disk:
  max_size: 2GB"""
    elif not spec.get("collector_defaults"):
        queue = """queue.mem:
  events: 4096
  flush.min_events: 0"""
    return f"""filebeat.inputs:
{inp}
{out}
{queue}
http.enabled: true
http.host: 0.0.0.0
http.port: 5066
logging.level: info
logging.metrics.period: 10s
"""


def start_filebeat(spec, source, run_id, rundir):
    name = f"bench-fb-{source}"
    sh(f"docker rm -f {name}", check=False)
    cfg = os.path.join(rundir, f"filebeat-{source}.yml")
    with open(cfg, "w") as f:
        f.write(filebeat_config(spec, source, run_id))
    os.chmod(cfg, 0o644)
    if spec["mode"] == "file":
        open(os.path.join(GEN_DIR, f"{run_id}-{source}.log"), "a").close()
    sh(f"docker run -d --name {name} --network bench --cpuset-cpus {SRC_CPUS} "
       f"-v {cfg}:/usr/share/filebeat/filebeat.yml:ro -v {GEN_DIR}:/gen:ro "
       f"{FB_IMAGE} filebeat -e --strict.perms=false")
    ip = sh(f"docker inspect -f '{{{{.NetworkSettings.Networks.bench.IPAddress}}}}' {name}")
    wait(lambda: requests.get(f"http://{ip}:5066/stats", timeout=2).ok if _try(ip) else False, 120, f"filebeat {source}")
    time.sleep(2)
    return name, ip


def _try(ip):
    try:
        requests.get(f"http://{ip}:5066/stats", timeout=2)
        return True
    except Exception:
        return False


def filebeat_metrics(ip):
    out = {}
    try:
        st = requests.get(f"http://{ip}:5066/stats", timeout=5).json()
        lb = st["libbeat"]
        out["output_acked"] = lb["output"]["events"]["acked"]
        out["output_failed"] = lb["output"]["events"]["failed"]
        out["output_dropped"] = lb["output"]["events"].get("dropped", 0)
        out["pipeline_dropped"] = lb["pipeline"]["events"].get("dropped", 0)
        out["pipeline_failed"] = lb["pipeline"]["events"].get("failed", 0)
        inp = requests.get(f"http://{ip}:5066/inputs/", timeout=5).json()
        for i in inp:
            for k in ("received_events_total", "system_packet_drops", "receive_queue_length",
                      "events_processed_total"):
                if k in i:
                    out[f"input_{k}"] = i[k]
    except Exception as e:
        out["error"] = str(e)
    return out


# -------------------------------------------------------------------- stats
class Sampler(threading.Thread):
    def __init__(self, path, period=5):
        super().__init__(daemon=True)
        self.path, self.period, self.stop = path, period, threading.Event()

    def run(self):
        with open(self.path, "w") as f:
            f.write("t,name,cpu_pct,mem_mib\n")
            while not self.stop.is_set():
                t = time.time()
                out = sh("docker stats --no-stream --format '{{.Name}};{{.CPUPerc}};{{.MemUsage}}'", check=False)
                for line in out.splitlines():
                    try:
                        n, c, m = line.split(";")
                        mem = m.split("/")[0].strip()
                        mib = float(mem[:-3]) * (1024 if mem.endswith("GiB") else 1 if mem.endswith("MiB") else 1 / 1024)
                        f.write(f"{t:.1f},{n},{float(c.rstrip('%')):.1f},{mib:.0f}\n")
                    except Exception:
                        pass
                f.flush()
                self.stop.wait(max(0.0, self.period - (time.time() - t)))


class StorageSampler(threading.Thread):
    """Index size vs indexed events every 60 s (storage-cost regression)."""
    def __init__(self, path, es, index, period=60):
        super().__init__(daemon=True)
        self.path, self.es, self.index, self.period = path, es, index, period
        self.stop = threading.Event()
        with open(self.path, "w") as f:
            f.write("t,tag,docs,store_bytes,segments\n")

    def sample(self, tag="live"):
        s = analyze.session(self.es)
        try:
            st = s.get(f"{self.es}/{self.index}/_stats/docs,store,segments", timeout=30).json()["_all"]["primaries"]
            with open(self.path, "a") as f:
                f.write(f"{time.time():.0f},{tag},{st['docs']['count']},{st['store']['size_in_bytes']},"
                        f"{st['segments']['count']}\n")
        except Exception:
            pass

    def run(self):
        while not self.stop.wait(self.period):
            self.sample()


# ------------------------------------------------------------------- faults
def fault_thread(spec, t_start, record):
    f = spec["fault"]
    backend = "bench-wazuh-indexer" if spec["variant"] == "C" else "bench-es"
    def go():
        time.sleep(max(0.0, t_start + f["at"] - time.time()))
        record["start_ns"] = time.time_ns()
        if f["type"] == "es_pause":
            sh(f"docker pause {backend}")
        elif f["type"] == "kafka_kill":
            sh("docker kill bench-kafka")
        log(f"fault {f['type']} injected")
        time.sleep(max(0.0, t_start + f["at"] + f["dur"] - time.time()))
        if f["type"] == "es_pause":
            sh(f"docker unpause {backend}")
        elif f["type"] == "kafka_kill":
            sh("docker start bench-kafka")
        record["end_ns"] = time.time_ns()
        log("fault cleared")
    th = threading.Thread(target=go, daemon=True)
    th.start()
    return th


# ---------------------------------------------------------------------- run
def gen_cmd(spec, source, kind, rate, dur, start_at, seq_start, run_id, rundir, dest, tag):
    common = (f"taskset -c {SRC_CPUS} {PY} {HERE}/gen.py --kind {kind} --rate {rate} --duration {dur} "
              f"--start-at {start_at} --seq-start {seq_start} --seed {abs(hash(tag)) % 10000} "
              f"--out {rundir}/gen-{tag}")
    if spec["mode"] == "file":
        return common + f" --mode file --file {GEN_DIR}/{run_id}-{source}.log"
    return common + f" --mode udp --host {dest[0]} --port {dest[1]}"


def count(index, es=None, base=0):
    es = es or ES
    s = analyze.session(es)
    try:
        s.post(f"{es}/{index}/_refresh", timeout=30)
        q = {"query": {"range": {"bench.seq": {"gte": base, "lt": base + 3_000_000_000}}}}
        return s.get(f"{es}/{index}/_count", json=q, timeout=30).json().get("count", 0)
    except Exception:
        return -1


def wz_ok():
    try:
        return analyze.session(WZ).get(f"{WZ}/_cluster/health", timeout=5).json()["status"] in ("green", "yellow")
    except Exception:
        return False


def wazuh_configured():
    """True only if archiving is on and the measurement hook is installed."""
    fb = sh("docker exec bench-wazuh-manager cat /etc/filebeat/filebeat.yml", check=False)
    if "archives:\n      enabled: true" not in fb:
        return False
    r = analyze.session(WZ).get(f"{WZ}/_ingest/pipeline/filebeat-7.10.2-wazuh-archives-pipeline")
    if r.status_code != 200:
        return False
    procs = r.json()["filebeat-7.10.2-wazuh-archives-pipeline"]["processors"]
    return any(p.get("pipeline", {}).get("name") == "bench-final" for p in procs)


def wazuh_setup(preserve_archives=False):
    """Full archiving on, measurement step in the archives pipeline, mapping."""
    import es_setup
    s = analyze.session(WZ)
    # 1) the manager's Filebeat ships archives only when enabled in its module
    fb = sh("docker exec bench-wazuh-manager cat /etc/filebeat/filebeat.yml")
    if "archives:\n      enabled: false" in fb or "archives:\n    enabled: false" in fb:
        sh("docker exec bench-wazuh-manager sed -i '/archives:/{n;s/enabled: false/enabled: true/}' /etc/filebeat/filebeat.yml")
        sh("docker restart bench-wazuh-manager")
        wait(lambda: "wazuh-analysisd is running" in sh("docker exec bench-wazuh-manager /var/ossec/bin/wazuh-control status", check=False), 300, "wazuh manager restart")
    # 2) measurement pipeline, appended to Wazuh's archives pipeline. Wazuh
    #    reroutes documents (date_index_name), so a final_pipeline would not
    #    run; the processors are identical to variants A/B.
    r = s.put(f"{WZ}/_ingest/pipeline/bench-final", json=es_setup.PIPELINES["bench-final"])
    r.raise_for_status()
    name = "filebeat-7.10.2-wazuh-archives-pipeline"
    wait(lambda: s.get(f"{WZ}/_ingest/pipeline/{name}").ok, 300, "wazuh archives pipeline")
    pl = s.get(f"{WZ}/_ingest/pipeline/{name}").json()[name]
    if not any(p.get("pipeline", {}).get("name") == "bench-final"
               for p in pl["processors"]):
        pl["processors"].append({"pipeline": {"name": "bench-final"}})
        r = s.put(f"{WZ}/_ingest/pipeline/{name}", json=pl)
        r.raise_for_status()
    # 3) mapping for the measurement fields (legacy template, merged over Wazuh's)
    tmpl = {"index_patterns": ["wazuh-archives-*"], "order": 100,
            "settings": {"index.refresh_interval": "1s"},
            "mappings": es_setup.TEMPLATE["template"]["mappings"]}
    r = s.put(f"{WZ}/_template/bench-wazuh", json=tmpl)
    r.raise_for_status()
    r = s.put(f"{WZ}/_cluster/settings", json={"persistent": {"action.destructive_requires_name": False}})
    r.raise_for_status()
    # Revision runs use unique sequence ranges and preserve historical
    # archives; the legacy campaign retains its original reset behavior.
    if not preserve_archives:
        s.delete(f"{WZ}/wazuh-archives-*")
        time.sleep(10)


def run_one(spec):
    spec["id"] = spec["id"].lower()      # Elasticsearch/Filebeat lowercase index names
    run_id = spec["id"]
    rundir = os.path.join(RESULTS, run_id)
    if os.path.exists(os.path.join(rundir, "result.json")):
        log(f"skip {run_id} (done)")
        return json.load(open(os.path.join(rundir, "result.json")))
    os.makedirs(rundir, exist_ok=True)
    json.dump(spec, open(os.path.join(rundir, "spec.json"), "w"), indent=1)
    log(f"=== run {run_id}: {json.dumps(spec)}")
    ensure_stack(spec)
    is_c = spec["variant"] == "C"
    es = WZ if is_c else ES
    index = "wazuh-archives-*" if is_c else f"bench-{run_id}-*"
    if not is_c:
        analyze.session(es).delete(f"{es}/{index}")

    flood = spec.get("flood")
    sources = ["nginx", "auth"] if flood else ["nginx"]
    if is_c:
        # appliances send syslog straight to the Wazuh manager (UDP 514)
        mip = sh("docker inspect -f '{{.NetworkSettings.Networks.bench.IPAddress}}' bench-wazuh-manager")
        fbs = {}
        dest = {s: (mip, 514) for s in sources}
    else:
        fbs = {s: start_filebeat(spec, s, run_id, rundir) for s in sources}
        dest = {s: (fbs[s][1], 5514) for s in sources}

    dur = spec["duration"]
    base = (int(time.time()) - 1_700_000_000) * 10_000_000_000   # unique seq range per run
    t_start = time.time() + 3
    gens = []
    # main nginx stream
    gens.append(("nginx", subprocess.Popen(gen_cmd(spec, "nginx", "nginx", spec["rate"], dur, t_start, base,
                                                    run_id, rundir, dest["nginx"], "nginx"), shell=True,
                                            stdout=subprocess.DEVNULL)))
    if flood and flood["rate"] > 0:
        gens.append(("flood", subprocess.Popen(gen_cmd(spec, "nginx", "nginx", flood["rate"], flood["dur"],
                                                        t_start + flood["at"], base + 1_000_000_000, run_id, rundir,
                                                        dest["nginx"], "flood"), shell=True,
                                                stdout=subprocess.DEVNULL)))
    if flood:
        gens.append(("auth", subprocess.Popen(gen_cmd(spec, "auth", "auth", flood["auth_rate"], dur, t_start,
                                                       base + 2_000_000_000, run_id, rundir, dest["auth"], "auth"),
                                               shell=True, stdout=subprocess.DEVNULL)))
    sampler = Sampler(os.path.join(rundir, "stats.csv"))
    sampler.start()
    stor = None
    if spec.get("storage"):
        stor = StorageSampler(os.path.join(rundir, "storage.csv"), es, index)
        stor.start()
    frec = {}
    fth = fault_thread(spec, t_start, frec) if spec.get("fault") else None
    for _, p in gens:
        p.wait()
    if fth:
        fth.join()
    log("generation finished; draining")

    # drain: wait until every emitted event is indexed, or the count is stable
    manifests = {tag: json.load(open(f"{rundir}/gen-{tag}.json")) for tag, _ in gens}
    n_sent_total = sum(m["n_sent"] for m in manifests.values())
    t_drain, last, last_change = time.time(), -1, time.time()
    stable_s = spec.get("stable_s", 60)
    drained = False
    while time.time() - t_drain < spec.get("drain_timeout", 900):
        c = count(index, es, base)
        if c >= n_sent_total:
            # the count includes duplicates, so reaching n_sent does not mean
            # every unique event is in: also require the count to be stable
            time.sleep(15)
            if count(index, es, base) == c:
                drained = True
                break
            continue
        if c != last:
            last, last_change = c, time.time()
        elif time.time() - last_change > stable_s:
            break
        time.sleep(5)
    drain_s = time.time() - t_drain
    fb_metrics = {s: filebeat_metrics(ip) for s, (name, ip) in fbs.items()}
    sampler.stop.set()
    sampler.join()
    if stor:
        stor.stop.set()
        stor.join()
        stor.sample()                                   # final pre-merge point
        analyze.session(es).post(f"{es}/{index}/_forcemerge?max_num_segments=1", timeout=3600)
        time.sleep(10)
        stor.sample(tag="merged")

    # analysis
    data = analyze.fetch(es, index, {"range": {"bench.seq": {"gte": base, "lt": base + 3_000_000_000}}})
    analyze.save_raw(os.path.join(rundir, "raw.npz"), data)
    fault = (frec["start_ns"], frec["end_ns"]) if frec else None
    res = {"id": run_id, "spec": spec, "drained": drained, "drain_s": drain_s,
           "filebeat": fb_metrics, "fault_ns": fault, "streams": {}}
    for tag, man in manifests.items():
        res["streams"][tag] = analyze.summarize(data, man, spec.get("warmup", 0) if tag != "flood" else 0, fault,
                                                cooldown_s=spec.get("cooldown", 5))
    res["containers"] = container_health()
    res["checks"] = checks(spec, res, manifests)
    json.dump(res, open(os.path.join(rundir, "result.json"), "w"), indent=1)

    # cleanup
    for s, (name, ip) in fbs.items():
        sh(f"docker logs {name} > {rundir}/filebeat-{s}.log 2>&1", check=False)
        sh(f"docker rm -f {name}", check=False)
        try:
            os.remove(os.path.join(GEN_DIR, f"{run_id}-{s}.log"))
        except FileNotFoundError:
            pass
    if not spec.get("keep_index") and not is_c:
        analyze.session(es).delete(f"{es}/{index}")
    if spec["variant"] == "A" and not drained:
        STATE["kafka_cfg"] = None      # force a clean topic before the next run
    s = res["streams"]["nginx"]
    log(f"--- {run_id}: sent={s['n_sent']} loss={s['loss_pct']:.3f}% dup={s['dup_pct']:.3f}% "
        f"p50={s['lat_p50_ms']:.0f} p95={s['lat_p95_ms']:.0f} p99={s['lat_p99_ms']:.0f} ms "
        f"ingest={s.get('ingest_rate', 0):.0f}/s drained={drained} "
        f"checks={[c for c in res['checks'] if c['level'] != 'ok']}")
    return res


def container_health():
    out = {}
    for n in sh("docker ps -a --filter name=bench- --format '{{.Names}}'", check=False).split():
        if n.startswith("bench-fb-"):
            continue
        st = sh(f"docker inspect -f '{{{{.State.Status}}}} {{{{.RestartCount}}}} {{{{.State.OOMKilled}}}}' {n}", check=False)
        out[n] = st
    return out


def checks(spec, res, manifests):
    c = []
    def add(level, what):
        c.append({"level": level, "check": what})
    for tag, m in manifests.items():
        if abs(m["achieved_rate"] - m["target_rate"]) > 0.01 * m["target_rate"]:
            add("error", f"generator {tag} achieved {m['achieved_rate']:.0f} vs target {m['target_rate']}")
        if m.get("send_errors"):
            add("warn", f"generator {tag} send errors {m['send_errors']}")
    needed = ({"bench-wazuh-manager", "bench-wazuh-indexer"} if spec["variant"] == "C" else
              {"bench-es"} | ({"bench-kafka", "bench-logstash"} if spec["variant"] == "A" else set()))
    for n, st in res["containers"].items():
        if n not in needed:
            continue
        if "true" in st.split()[-1:]:
            add("error", f"{n} OOM-killed")
        if not st.startswith("running") and not (spec.get("fault", {}).get("type") == "kafka_kill" and "kafka" in n):
            add("error", f"{n} not running: {st}")
    for tag, s in res["streams"].items():
        if s["n_indexed"] == 0:
            add("error", f"stream {tag}: nothing indexed")
            continue
        if s["lat_p50_ms"] < 0:
            add("error", f"stream {tag}: negative latency")
        if spec["mode"] == "file" and not spec.get("fault") and res["drained"] and s["loss_pct"] > 0:
            add("error", f"stream {tag}: loss {s['loss_pct']:.4f}% in file mode without fault")
        if s["dup_pct"] > 0 and not spec.get("fault"):
            add("warn", f"stream {tag}: duplicates {s['dup_pct']:.4f}% without fault")
    if not res["drained"] and not spec.get("expect_overload"):
        add("warn", "not fully drained (loss or overload)")
    if not (wz_ok() if spec["variant"] == "C" else es_ok()):
        add("error", "indexing backend unhealthy after run")
    if not c:
        add("ok", "all checks passed")
    return c


def estimate_s(spec):
    """Conservative wall-clock estimate of one run (setup + run + drain)."""
    setup = 150 if spec["variant"] in ("A", "C") else 60
    drain = 60 + spec["duration"] * 0.15
    if spec.get("fault"):
        drain += spec["fault"]["dur"] * 0.6
    if spec.get("expect_overload"):
        drain = spec.get("drain_timeout", 300)
    return setup + spec["duration"] + drain


def main():
    if sys.argv[1] == "one":
        spec = json.loads(sys.argv[2])
        res = run_one(spec)
        print(json.dumps(res["checks"]))
        return
    specs = json.load(open(sys.argv[2]))
    if "--phases" in sys.argv:
        wanted = sys.argv[sys.argv.index("--phases") + 1].split(",")
        specs = [sp for sp in specs if sp["phase"] in wanted]
    hours = float(sys.argv[sys.argv.index("--hours") + 1]) if "--hours" in sys.argv else 1e9
    t_session = time.time()
    stop_file = os.path.join(RESULTS, "STOP")
    for spec in specs:
        if os.path.exists(os.path.join(RESULTS, spec["id"].lower(), "result.json")):
            continue
        if os.path.exists(stop_file):
            log("STOP file found: ending session cleanly")
            os.remove(stop_file)
            break
        est = estimate_s(spec)
        if time.time() - t_session + est > hours * 3600:
            log(f"session limit reached ({hours} h): next run {spec['id']} needs ~{est / 60:.0f} min")
            break
        res = run_one(spec)
        errs = [c for c in res["checks"] if c["level"] == "error"]
        if errs:
            log(f"STOPPING CAMPAIGN: errors in {spec['id']}: {errs}")
            sys.exit(2)
    left = [sp["id"] for sp in specs if not os.path.exists(os.path.join(RESULTS, sp["id"].lower(), "result.json"))]
    log(f"session finished: {len(specs) - len(left)}/{len(specs)} runs done, {len(left)} remaining")
    if not left:
        log("all runs of the selected phase(s) complete")


if __name__ == "__main__":
    main()
