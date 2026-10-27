"""Collect every number used in the paper from the raw per-run results."""
import csv, glob, json, os, statistics as st
from collections import defaultdict
import numpy as np

R = "results"
def load(phase):
    out = []
    for p in glob.glob(f"{R}/*/result.json"):
        r = json.load(open(p))
        if r["spec"]["phase"] == phase:
            r["_dir"] = os.path.dirname(p); out.append(r)
    return out
def ms(v, d=1):
    v = [x for x in v if x == x]
    if not v: return "-"
    return f"{st.mean(v):.{d}f}" + (f" ± {st.stdev(v):.{d}f}" if len(v) > 1 else "")
def res_usage(r, names):
    """median CPU (cores) and memory (GiB) of the given containers during the run."""
    rows = list(csv.DictReader(open(f"{r['_dir']}/stats.csv")))
    by_t = defaultdict(lambda: [0.0, 0.0])
    for x in rows:
        if any(x["name"] == n for n in names):
            by_t[x["t"]][0] += float(x["cpu_pct"]) / 100; by_t[x["t"]][1] += float(x["mem_mib"]) / 1024
    v = list(by_t.values())[2:-2] or list(by_t.values())
    return (float(np.median([a for a, b in v])), float(np.median([b for a, b in v]))) if v else (float("nan"),) * 2
SUT = {"A": ["bench-es", "bench-kafka", "bench-logstash"], "B": ["bench-es"], "Bdisk": ["bench-es"],
       "C": ["bench-wazuh-manager", "bench-wazuh-indexer"]}
COL = ["bench-fb-nginx"]

print("== P1 outages (UDP 500 EPS)")
g = defaultdict(list)
for r in load("outage"): g[(r["spec"]["variant"], r["spec"]["fault"]["dur"])].append(r["streams"]["nginx"])
for k in sorted(g):
    s = g[k]
    print(k, "n", len(s), "loss", ms([x["loss_pct"] for x in s], 2), "lossIn", ms([x["loss_during_fault_pct"] for x in s], 2),
          "dup", ms([x["dup_pct"] for x in s], 2), "rec", ms([x["recovery_s"] for x in s], 0),
          "p95pre", ms([x["lat_p95_pre_fault_ms"] for x in s], 0), "lost_outside", [x["lost_outside_fault"] for x in s])
print("== P9 outage-load (UDP 2000 EPS, 10 min)")
for r in sorted(load("outage-load"), key=lambda r: r["id"]):
    s = r["streams"]["nginx"]; print(r["id"], "loss", round(s["loss_pct"], 3), "lossIn", round(s["loss_during_fault_pct"], 2),
          "outside", s["lost_outside_fault"], "rec", round(s["recovery_s"]), "dup", round(s["dup_pct"], 3), "p95pre", round(s["lat_p95_pre_fault_ms"]))
print("== P8 outage-file (file 500 EPS, 10 min)")
for r in sorted(load("outage-file"), key=lambda r: r["id"]):
    s = r["streams"]["nginx"]; print(r["id"], "loss", s["loss_pct"], "rec", round(s["recovery_s"]), "dup", round(s["dup_pct"], 3), "p95pre", round(s["lat_p95_pre_fault_ms"]))
print("== P4 kafka kill")
for r in sorted(load("kafka-kill"), key=lambda r: r["id"]):
    d = dict(np.load(f"{r['_dir']}/raw.npz")); m = json.load(open(f"{r['_dir']}/gen-nginx.json")); fs, fe = r["fault_ns"]
    miss = np.setdiff1d(np.arange(m["seq_start"], m["seq_end"]), np.unique(d["seq"])); tm = (miss - m["seq_start"]) / m["target_rate"]
    s = r["streams"]["nginx"]
    print(r["id"], "loss", round(s["loss_pct"], 2), "dup", round(s["dup_pct"], 2), "lost_window", round(tm.min(), 1), round(tm.max(), 1),
          "extra_after_restart", round(tm.max() - (fe - m["start_ns"]) / 1e9, 1))
print("== P5 latency (file 1000 EPS)")
g = defaultdict(list)
for r in load("latency") + load("latency-defaults"):
    g[(r["spec"]["variant"], bool(r["spec"].get("collector_defaults")))].append(r)
for k in sorted(g):
    s = [r["streams"]["nginx"] for r in g[k]]
    u = [res_usage(r, SUT[k[0]]) for r in g[k]]; c = [res_usage(r, COL) for r in g[k]]
    print(k, "n", len(s), "p50", ms([x["lat_p50_ms"] for x in s], 0), "p95", ms([x["lat_p95_ms"] for x in s], 0),
          "p99", ms([x["lat_p99_ms"] for x in s], 0), "max", ms([x["lat_max_ms"] for x in s], 0),
          "SUTcpu", ms([a for a, b in u], 2), "SUTmemGiB", ms([b for a, b in u], 2), "collector_cpu", ms([a for a, b in c], 2))
print("== P3 ramp (file)")
g = defaultdict(list)
for r in load("ramp"): g[(r["spec"]["variant"], r["spec"]["rate"])].append(r)
for k in sorted(g):
    s = [r["streams"]["nginx"] for r in g[k]]; u = [res_usage(r, SUT[k[0]]) for r in g[k]]
    print(k, "loss", ms([x["loss_pct"] for x in s], 3), "p50", ms([x["lat_p50_ms"] for x in s], 0), "p95", ms([x["lat_p95_ms"] for x in s], 0),
          "p99", ms([x["lat_p99_ms"] for x in s], 0), "ingest", ms([x["ingest_rate"] for x in s], 0), "SUTcpu", ms([a for a, b in u], 2), "mem", ms([b for a, b in u], 2))
print("== P7 ramp (UDP)")
g = defaultdict(list)
for r in load("ramp-udp"): g[(r["spec"]["variant"], r["spec"]["rate"])].append(r)
for k in sorted(g):
    s = [r["streams"]["nginx"] for r in g[k]]; u = [res_usage(r, SUT[k[0]]) for r in g[k]]
    print(k, "loss", ms([x["loss_pct"] for x in s], 2), [round(x["loss_pct"], 2) for x in s], "p50", ms([x["lat_p50_ms"] for x in s], 0),
          "p95", ms([x["lat_p95_ms"] for x in s], 0), "ingest", ms([x["ingest_rate"] for x in s], 0), "SUTcpu", ms([a for a, b in u], 2), "mem", ms([b for a, b in u], 2))
print("== P6 grid")
for r in sorted(load("grid"), key=lambda r: r["id"]):
    s = r["streams"]["nginx"]; u = res_usage(r, SUT["A"])
    print(r["id"], "p95", round(s["lat_p95_ms"]), "ingest", round(s["ingest_rate"]), "loss", s["loss_pct"], "cpu", round(u[0], 2))
print("== P2 flood")
fl = json.load(open(f"{R}/flood_summary.json")) if os.path.exists(f"{R}/flood_summary.json") else []
g = defaultdict(list)
for x in fl: g[(x["variant"], x["flood"])].append(x)
for k in sorted(g):
    a = [x["auth"] for x in g[k]]
    print(k, "n", len(a), "atk_lost", ms([x["lost_pct"] for x in a], 2), [round(x["lost_pct"], 2) for x in a], "p50", ms([x["p50_ms"] / 1e3 for x in a], 2),
          "p95", ms([x["p95_ms"] / 1e3 for x in a], 2), "max", ms([x["max_ms"] / 1e3 for x in a], 2), "flood_lost", ms([x.get("flood_lost_pct", 0) for x in g[k]], 2))
print("== P10 storage")
rows = list(csv.DictReader(open(f"{R}/p7-storage-a/storage.csv")))
live = [(int(x["docs"]), int(x["store_bytes"])) for x in rows if x["tag"] == "live"]
d_, b_ = np.array(live).T
# lower envelope (exclude transient merge peaks): fit through samples below the running fit
a = np.sum(d_ * b_) / np.sum(d_ * d_); res = b_ - a * d_; keep = res <= np.percentile(res, 60)
a2 = np.sum(d_[keep] * b_[keep]) / np.sum(d_[keep] ** 2)
fin = [x for x in rows if x["tag"] == "merged"][0]
print("slope all", round(a, 1), "slope envelope", round(a2, 1), "final B/ev", round(int(fin["store_bytes"]) / int(fin["docs"]), 1), "docs", fin["docs"])
