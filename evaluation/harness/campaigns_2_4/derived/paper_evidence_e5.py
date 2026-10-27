"""Campaign 4 derived table: production-to-alert latency in the Elastic variants (E5).

One row per run, from the alerts_e2e summary that run_alerts.py appended to
result.json (alert @timestamp minus the generator's production time, matched
through bseq; window = events produced during seconds 60-240). Threshold
firings are counted as distinct execution times, because Kibana writes the
threshold alert document twice per execution in this setup.
"""
import csv, json, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REV = HERE.parent
sys.path.insert(0, str(REV)); sys.path.insert(0, str(REV / "alerts_e2e")); sys.path.insert(0, str(REV.parent))
from run_alerts import load_alert_specs, require_alerts_lock  # noqa: E402
from run_revision import NEW_RESULTS  # noqa: E402

require_alerts_lock()
rows = []
for spec in load_alert_specs():
    folder = NEW_RESULTS / spec["id"]
    result = json.loads((folder / "result.json").read_text())
    assessment = json.loads((folder / "execution_assessment.json").read_text())
    assert assessment["execution_valid"], spec["id"]
    al = result["alerts_e2e"]
    auth = result["streams"]["auth"]["flood_window"]
    web = [result["streams"][t]["flood_window"] for t in ("nginx", "flood") if t in result["streams"]]
    firings = sorted({round(t) for t in al["threshold_alerts_during_production"] if t <= spec["duration"]})
    lat = al["alert_latency_window_s"]
    rows.append(dict(run_id=spec["id"], variant=spec["variant"], repetition=spec["repetition"], flood=spec["flood"]["rate"],
                     status=result["status"], auth_sent=al["auth_sent"], alerts_per_event=al["alerts_per_event"],
                     events_without_alert=al["events_without_alert"], window_sent=al["window_sent"],
                     window_alerts=al["window_alerts"], window_without_alert_pct=al["window_without_alert_pct"],
                     alert_p50_s=round(lat["p50"], 2), alert_p95_s=round(lat["p95"], 2), alert_max_s=round(lat["max"], 2),
                     indexer_receipt_p95_s=round(auth["p95_ms"] / 1000, 3),
                     web_missing=sum(w["n_missing_at_cutoff"] for w in web),
                     udp_rcvbuf_errors=result["udp_namespace_counter_deltas"]["nginx"]["RcvbufErrors"],
                     brute_force_firings=len(firings), brute_force_times_s=" ".join(str(t) for t in firings)))
with (HERE / "paper_e5_alerts.csv").open("w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
print("written paper_e5_alerts.csv", len(rows), "rows")
