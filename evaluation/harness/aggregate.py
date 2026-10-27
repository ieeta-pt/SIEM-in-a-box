"""Aggregate per-run results into the paper's tables (mean +- sample SD).

Usage: aggregate.py [phase ...]   -> prints tables, writes results/summary.json

Also joins the host log (results/host.csv) to each run window and reports
the thermal-throttle events that occurred during the run.
"""
import csv
import glob
import json
import os
import statistics as st
import sys
from collections import defaultdict

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))


def load():
    rs = []
    for p in glob.glob(os.path.join(HERE, "results", "*", "result.json")):
        r = json.load(open(p))
        r["_dir"] = os.path.dirname(p)
        rs.append(r)
    return rs


def host_rows():
    p = os.path.join(HERE, "results", "host.csv")
    if not os.path.exists(p):
        return []
    return [{k: float(v) for k, v in row.items()} for row in csv.DictReader(open(p))]


def throttle_during(r, hrows):
    man = json.load(open(os.path.join(r["_dir"], "gen-nginx.json")))
    t0, t1 = man["start_ns"] / 1e9, man["end_ns"] / 1e9
    win = [h for h in hrows if t0 - 30 <= h["t"] <= t1 + 30]
    if len(win) < 2:
        return None, None
    return win[-1]["pkg_throttle"] - win[0]["pkg_throttle"], max(h["pkg_temp_c"] for h in win)


def ms(vals, fmt="{:.0f}"):
    vals = [v for v in vals if v == v]
    if not vals:
        return "-"
    if len(vals) == 1:
        return fmt.format(vals[0])
    return f"{fmt.format(st.mean(vals))} ± {fmt.format(st.stdev(vals))}"


def key(r):
    sp = r["spec"]
    k = [sp["phase"], sp["variant"], sp["mode"], sp["rate"]]
    if sp.get("fault"):
        k += [sp["fault"]["type"], sp["fault"]["dur"]]
    if sp.get("flood"):
        k += ["flood", sp["flood"]["rate"]]
    if sp["phase"] == "grid":
        k += [f"p{sp.get('partitions', 1)}w{sp.get('workers', 2)}"]
    return tuple(k)


def main():
    phases = set(sys.argv[1:])
    rs = [r for r in load() if not phases or r["spec"]["phase"] in phases]
    hrows = host_rows()
    groups = defaultdict(list)
    for r in rs:
        groups[key(r)].append(r)
    summary = {}
    for k in sorted(groups, key=lambda x: [str(y) for y in x]):
        g = groups[k]
        s = [r["streams"]["nginx"] for r in g]
        row = {
            "n": len(g),
            "loss_pct": ms([x["loss_pct"] for x in s], "{:.3f}"),
            "dup_pct": ms([x["dup_pct"] for x in s], "{:.3f}"),
            "p50": ms([x["lat_p50_ms"] for x in s]),
            "p95": ms([x["lat_p95_ms"] for x in s]),
            "p99": ms([x["lat_p99_ms"] for x in s]),
            "ingest": ms([x.get("ingest_rate", float("nan")) for x in s]),
            "drained": sum(r["drained"] for r in g),
        }
        if g[0]["spec"].get("fault"):
            row["loss_in_fault_pct"] = ms([x.get("loss_during_fault_pct", float("nan")) for x in s], "{:.2f}")
            row["recovery_s"] = ms([x.get("recovery_s", float("nan")) for x in s])
            row["p95_pre"] = ms([x.get("lat_p95_pre_fault_ms", float("nan")) for x in s])
            row["p95_post"] = ms([x.get("lat_p95_post_fault_ms", float("nan")) for x in s])
        if "auth" in g[0]["streams"]:
            a = [r["streams"]["auth"] for r in g]
            row["auth_loss_pct"] = ms([x["loss_pct"] for x in a], "{:.2f}")
            row["auth_p95"] = ms([x["lat_p95_ms"] for x in a])
            row["auth_max"] = ms([x["lat_max_ms"] for x in a])
        th = [throttle_during(r, hrows) for r in g]
        th = [t for t in th if t[0] is not None]
        if th:
            row["throttle_events"] = ms([t[0] for t in th])
            row["max_temp_c"] = max(t[1] for t in th)
        summary["|".join(map(str, k))] = row
        print(" | ".join(map(str, k)), "->", json.dumps(row))
    json.dump(summary, open(os.path.join(HERE, "results", "summary.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
