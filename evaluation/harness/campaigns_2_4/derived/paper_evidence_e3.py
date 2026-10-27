"""Campaign 3 derived tables: factorial flood cells (E3) and the full-stack cost cell (E4).

Same window and reduction as paper_evidence.py for E1 (events produced during
seconds 60-240 of the run, first receipt per ID, missing = absent at the final
scan), recomputed from raw.npz and the generator event records.
"""
import csv, json, sys
from pathlib import Path
import numpy as np

HERE = Path(__file__).resolve().parent
REV = HERE.parent
sys.path.insert(0, str(REV)); sys.path.insert(0, str(REV.parent))
from eventlog import read as read_events  # noqa: E402
from run_revision import NEW_RESULTS, require_factorial_lock  # noqa: E402

require_factorial_lock()
specs = json.loads((REV / "campaign_factorial.json").read_text())
exposure, cost = [], []
for spec in specs:
    folder = NEW_RESULTS / spec["id"]
    result = json.loads((folder / "result.json").read_text())
    assessment = json.loads((folder / "execution_assessment.json").read_text())
    assert assessment["execution_valid"], spec["id"]
    if spec["phase"] == "E4-cost":
        for name, v in result["container_resource_medians"].items():
            cost.append(dict(run_id=spec["id"], container=name, cpu_cores=round(v["cpu_cores"], 3),
                             mem_gib=round(v["mem_gib"], 3), samples=v["samples"]))
        s = result["streams"]["nginx"]; w = s["full_window"]
        cost.append(dict(run_id=spec["id"], container="(stream nginx)", cpu_cores=None, mem_gib=None,
                         samples=f"lost={s['n_missing_at_cutoff']} p50_ms={w['p50_ms']:.0f} p95_ms={w['p95_ms']:.0f}"))
        continue
    with np.load(folder / "raw.npz") as raw:
        seq, received = raw["seq"], raw["t_ing"]
    ids, inverse = np.unique(seq, return_inverse=True)
    first = np.full(len(ids), np.iinfo(np.int64).max, dtype=np.int64)
    np.minimum.at(first, inverse, received)
    start = result["scheduled_start_ns"] + 60_000_000_000
    end = result["scheduled_start_ns"] + 240_000_000_000
    windows = {}
    for tag in result["streams"]:
        manifest = json.loads((folder / f"gen-{tag}.json").read_text())
        events = read_events(folder / manifest["event_records_file"], manifest)
        sent = events[events["sent_ok"] == 1]
        mask = (ids >= manifest["seq_start"]) & (ids < manifest["seq_end"])
        got, arrival = ids[mask], first[mask]
        where = np.searchsorted(sent["seq"], got)
        assert np.array_equal(sent["seq"][where], got)
        times = sent["wall_ns"][where]
        expected = int(((sent["wall_ns"] >= start) & (sent["wall_ns"] < end)).sum())
        in_window = (times >= start) & (times < end)
        latency = (arrival[in_window] - times[in_window]) / 1e6
        saved = result["streams"][tag]["flood_window"]
        assert expected == saved["n_sent_ok"] and expected - len(latency) == saved["n_missing_at_cutoff"], (spec["id"], tag)
        assert np.isclose(np.percentile(latency, 95), saved["p95_ms"], rtol=1e-9)
        windows[tag] = (expected, latency)
    udp = sum(x.get("RcvbufErrors", 0) for x in result["udp_namespace_counter_deltas"].values())
    for source, tags in (("auth", ["auth"]), ("web", ["nginx", "flood"])):
        n = sum(windows[t][0] for t in tags if t in windows)
        lat = np.concatenate([windows[t][1] for t in tags if t in windows])
        exposure.append(dict(run_id=spec["id"], variant=spec["variant"], repetition=spec["repetition"],
                             flood=spec["flood"]["rate"], source=source, sent=n, missing=n - len(lat),
                             missing_pct=100 * (n - len(lat)) / n, p95_s=float(np.percentile(lat, 95) / 1000),
                             max_s=float(lat.max() / 1000), status=result["status"], udp_rcvbuf_errors=udp))
for name, rows in (("paper_e3_exposure.csv", exposure), ("paper_e4_cost.csv", cost)):
    with (HERE / name).open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    print("written", name, len(rows), "rows")
