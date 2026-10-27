"""Production-to-alert latency of the Wazuh attack stream (campaign 2, E1 C cells).

Wazuh's analysisd stamps every alert with its own generation time. The sshd
"Failed password" lines of the attack stream raise rule 5710 once per event,
and rule 5712 (brute force, frequency based) when enough of them arrive in its
timeframe. Both carry the generator's `bseq=<seq>:<t_produce_ns>` in
`full_log`, so each alert can be matched to its production time without any
new run. The Wazuh indexer (bench-wazuh-indexer) must be running.

Writes wazuh_alert_latency.csv (one row per run) next to this script.
"""

from __future__ import annotations

import csv
import datetime as dt
import json
import re
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
BENCH = HERE.parents[1]
sys.path.insert(0, str(BENCH))
import analyze  # noqa: E402

WZ = "https://localhost:9201"
NEW_RESULTS = HERE.parent / "new_results"
RUNS = ["rev27-e1-c-f0-r1", "rev27-e1-c-f0-r2", "rev27-e1-c-f0-r3",
        "rev27-e1-c-f6000-r1-rep1", "rev27-e1-c-f6000-r2", "rev27-e1-c-f6000-r3"]
WINDOW = (60.0, 240.0)          # same production window as paper_e1_exposure.csv
BSEQ = re.compile(r"bseq=(\d+):(\d+)")


def parse_ts(value: str) -> float:
    return dt.datetime.strptime(value.replace("+0000", "+00:00"),
                                "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()


def alerts_between(session, t_lo: float, t_hi: float) -> list[dict]:
    iso = lambda t: dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    query = {"size": 5000, "_source": ["timestamp", "rule.id", "full_log"],
             "sort": [{"timestamp": "asc"}],
             "query": {"bool": {"filter": [
                 {"terms": {"rule.id": ["5710", "5712"]}},
                 {"range": {"timestamp": {"gte": iso(t_lo), "lte": iso(t_hi)}}}]}}}
    response = session.get(f"{WZ}/wazuh-alerts-4.x-*/_search?scroll=2m", json=query, timeout=120).json()
    hits = list(response["hits"]["hits"])
    scroll_id = response.get("_scroll_id")
    while scroll_id and len(response["hits"]["hits"]) == 5000:
        response = session.post(f"{WZ}/_search/scroll", json={"scroll": "2m", "scroll_id": scroll_id},
                                timeout=120).json()
        hits += response["hits"]["hits"]
    return [hit["_source"] for hit in hits]


def main() -> None:
    session = analyze.session(WZ)
    rows = []
    for run_id in RUNS:
        run_dir = NEW_RESULTS / run_id
        manifest = json.loads((run_dir / "gen-auth.json").read_text())
        result = json.loads((run_dir / "result.json").read_text())
        spec = result["spec"]
        t0 = result["scheduled_start_ns"] / 1e9
        lo, hi = manifest["seq_start"], manifest["seq_end"]
        horizon = spec["duration"] + spec["drain_timeout"]
        per_event = {}
        brute_force = []
        for alert in alerts_between(session, t0 - 5, t0 + horizon):
            t_alert = parse_ts(alert["timestamp"])
            if alert["rule"]["id"] == "5712":
                if t_alert - t0 <= spec["duration"]:
                    brute_force.append(t_alert - t0)
                continue
            match = BSEQ.search(alert.get("full_log", ""))
            if not match:
                continue
            seq, t_produce = int(match.group(1)), int(match.group(2)) / 1e9
            if lo <= seq < hi and seq not in per_event:
                per_event[seq] = (t_alert - t_produce, t_produce - t0)
        lat = np.array([v[0] for v in per_event.values()])
        produced = np.array([v[1] for v in per_event.values()])
        in_window = (produced >= WINDOW[0]) & (produced < WINDOW[1])
        sent_in_window = int(round((WINDOW[1] - WINDOW[0]) * spec["flood"]["auth_rate"]))
        receipt = result["streams"]["auth"]["flood_window"]
        rows.append({
            "run_id": run_id, "flood_eps": spec["flood"]["rate"],
            "auth_sent": manifest["n_sent"], "alerts_5710": len(per_event),
            "events_without_alert": manifest["n_sent"] - len(per_event),
            "window_sent": sent_in_window, "window_alerts": int(in_window.sum()),
            "window_without_alert_pct": round(100 * (1 - in_window.sum() / sent_in_window), 2),
            "alert_p50_s": round(float(np.percentile(lat[in_window], 50)), 3),
            "alert_p95_s": round(float(np.percentile(lat[in_window], 95)), 3),
            "alert_max_s": round(float(lat[in_window].max()), 3),
            "indexer_receipt_p95_s": round(receipt["p95_ms"] / 1000, 3),
            "brute_force_alerts_5712": len(brute_force),
            "brute_force_times_s": " ".join(f"{t:.0f}" for t in sorted(brute_force)),
        })
        print(rows[-1])
    with (HERE / "wazuh_alert_latency.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print("written", HERE / "wazuh_alert_latency.csv")


if __name__ == "__main__":
    main()
