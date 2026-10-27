"""Read-only reanalysis of the 2026-10-19 benchmark corpus.

Run from any directory with ``bench/.venv/bin/python campaigns_2_4/reanalyse.py``.
Only files inside this script's directory are written. Original results are
never modified. All latency metrics use the *first* indexer-receipt stamp of
each distinct event ID; later receipts count as duplicates.
"""

from __future__ import annotations

import csv
import hashlib
import json
import math
from pathlib import Path

import numpy as np


ROOT = Path(__file__).resolve().parents[1]
OUT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
SUT = {
    "A": ("bench-es", "bench-kafka", "bench-logstash"),
    "B": ("bench-es",),
    "Bdisk": ("bench-es",),
    "C": ("bench-wazuh-manager", "bench-wazuh-indexer"),
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_csv(name: str, rows: list[dict], fields: list[str]) -> None:
    target = OUT / name
    with target.with_suffix(target.suffix + ".tmp").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    target.with_suffix(target.suffix + ".tmp").replace(target)


def first_receipts(seq, produced, received, lo, hi):
    """Return first receipt per in-range ID, with duplicates kept as a count."""
    valid = (seq >= lo) & (seq < hi)
    seq, produced, received = seq[valid], produced[valid], received[valid]
    if not len(seq):
        return seq, produced, received, 0
    order = np.lexsort((received, seq))
    seq, produced, received = seq[order], produced[order], received[order]
    first = np.r_[True, seq[1:] != seq[:-1]]
    return seq[first], produced[first], received[first], len(seq) - int(first.sum())


def missing_ids(lo: int, hi: int, present: np.ndarray) -> np.ndarray:
    # The generator's sequential IDs are the reference even for missing events.
    return np.setdiff1d(np.arange(lo, hi, dtype=np.int64), present, assume_unique=True)


def latency_stats(ms: np.ndarray) -> dict:
    if not len(ms):
        return {key: "" for key in ("p50_ms", "p95_ms", "p99_ms", "max_ms")}
    return {
        "p50_ms": float(np.percentile(ms, 50)),
        "p95_ms": float(np.percentile(ms, 95)),
        "p99_ms": float(np.percentile(ms, 99)),
        "max_ms": float(ms.max()),
    }


def derive_stream(seq, produced, received, manifest, *, warmup_s, cooldown_s,
                  fault_ns=None, observation_end_ns=None):
    """Compute one stream without equating missing at scan with confirmed loss.

    Production times for absent IDs are reconstructed from nominal generator
    rate and the start stamp, with an uncertain boundary of at least 5 ms.
    Exact original production times exist only for events that were received.
    """
    lo, hi = int(manifest["seq_start"]), int(manifest["seq_end"])
    sent = int(manifest["n_sent"])
    send_errors = int(manifest.get("send_errors", 0))
    if hi - lo != sent + send_errors:
        raise ValueError("Manifest sequence range, sent and send errors disagree")
    # Existing corpus has zero send_errors. For nonzero errors, all-IDs missing
    # is not a delivery-loss denominator, so fail rather than misclassify.
    if send_errors:
        raise ValueError("Generator send errors require emitted-ID manifest")
    ids, tprod, trecv, dup = first_receipts(seq, produced, received, lo, hi)
    missing = missing_ids(lo, hi, ids)
    start, end = int(manifest["start_ns"]), int(manifest["end_ns"])
    window = (tprod >= start + round(warmup_s * 1e9)) & (tprod <= end - round(cooldown_s * 1e9))
    lat = (trecv[window] - tprod[window]) / 1e6
    if len(lat) and np.any(lat < 0):
        raise ValueError("Negative first-receipt latency")
    row = {
        "n_sent": sent,
        "n_unique_receipts": len(ids),
        "n_duplicate_receipts": dup,
        "n_missing_at_scan": len(missing),
        "missing_pct_at_scan": 100.0 * len(missing) / sent if sent else "",
        "window_n_unique_receipts": int(window.sum()),
        **latency_stats(lat),
    }
    loss = []
    recovery = None
    if fault_ns is not None:
        fs, fe = map(int, fault_ns)
        rate = float(manifest["target_rate"])
        estimated = start + (missing - lo).astype(np.float64) / rate * 1e9
        precision_ns = max(5e6, 1e9 / rate)
        windows = (("before_fault", -math.inf, fs),
                   ("during_fault", fs, fe),
                   ("after_fault", fe, math.inf))
        for name, lower, upper in windows:
            n = int(((estimated >= lower) & (estimated < upper)).sum())
            uncertain = int((np.abs(estimated - fs) <= precision_ns).sum() +
                            (np.abs(estimated - fe) <= precision_ns).sum())
            loss.append({"window": name, "n_missing_at_scan": n,
                         "boundary_uncertain_ids": uncertain,
                         "timestamp_method": "seq/target_rate ± max(5ms,1/rate)"})
        # The old analyzer used the last *received* pre-clearance event even
        # when other pre-clearance events were never observed. Preserve that
        # number only as a diagnostic, not as completed recovery.
        cohort = tprod <= fe
        pre_missing = int((estimated <= fe).sum())
        last_pre = max(0.0, (int(trecv[cohort].max()) - fe) / 1e9) if np.any(cohort) else None
        last_all = max(0.0, (int(trecv.max()) - fe) / 1e9) if len(trecv) else None
        complete = pre_missing == 0 and np.any(cohort)
        recovery = {
            "pre_clearance_cohort_status": "complete_at_scan" if complete else "incomplete_at_scan",
            "pre_clearance_missing_at_scan": pre_missing,
            "pre_clearance_boundary_uncertain_ids": int((np.abs(estimated - fe) <= precision_ns).sum()),
            "last_observed_pre_clearance_s": last_pre,
            "recovery_pre_clearance_s": last_pre if complete else None,
            "last_observed_any_s": last_all,
            "catchup_steady_s": None,
            "catchup_status": "not_identifiable_offline",
            "generator_stop_after_clearance_s": (end - fe) / 1e9,
            # No final index-scan timestamp was saved: this is the latest
            # request-receipt stamp observed in the run, not observation end.
            "latest_receipt_after_clearance_s": ((observation_end_ns - fe) / 1e9
                                                 if observation_end_ns is not None else None),
        }
    return row, loss, recovery


def resource_metrics(stats_file: Path, variant: str):
    if not stats_file.exists():
        return None
    by_time = {}
    with stats_file.open(newline="") as handle:
        for x in csv.DictReader(handle):
            if x["name"] in SUT[variant]:
                cpu, mem = by_time.get(x["t"], (0.0, 0.0))
                by_time[x["t"]] = (cpu + float(x["cpu_pct"]) / 100,
                                  mem + float(x["mem_mib"]) / 1024)
    values = list(by_time.values())
    # Match the original published window; label exactly what was aggregated.
    values = values[2:-2] or values
    if not values:
        return None
    a = np.asarray(values)
    return {"component_set": "+".join(SUT[variant]),
            "samples_after_trim": len(a),
            "cpu_median_sampled": float(np.median(a[:, 0])),
            "cpu_max_sampled": float(a[:, 0].max()),
            "mem_gib_median_sampled": float(np.median(a[:, 1])),
            "mem_gib_max_sampled": float(a[:, 1].max())}


def flood_window_metrics(seq, produced, received, manifest, start_s, duration_s):
    """Attack-source metrics during a scheduled flood; missing-ID timing is estimated."""
    lo, hi = int(manifest["seq_start"]), int(manifest["seq_end"])
    ids, tprod, trecv, dup = first_receipts(seq, produced, received, lo, hi)
    start = int(manifest["start_ns"])
    rate = float(manifest["target_rate"])
    w0, w1 = start + int(start_s * 1e9), start + int((start_s + duration_s) * 1e9)
    # Use exact production time for received IDs and nominal schedule only for
    # absent IDs. This avoids treating a delayed generator tick as a lost ID.
    present = (tprod >= w0) & (tprod < w1)
    missing = missing_ids(lo, hi, ids)
    estimated_missing = start + (missing - lo).astype(np.float64) / rate * 1e9
    absent = (estimated_missing >= w0) & (estimated_missing < w1)
    n_received = int(present.sum())
    n_missing = int(absent.sum())
    lat = (trecv[present] - tprod[present]) / 1e6
    return {
        "window_start_s": start_s, "window_duration_s": duration_s,
        "n_received_distinct": n_received, "n_missing_at_scan_estimated": n_missing,
        "n_expected_estimated": n_received + n_missing,
        "missing_pct_at_scan_estimated": 100 * n_missing / (n_received + n_missing)
                                         if n_received + n_missing else "",
        "n_duplicate_receipts_all_run": dup,
        "missing_boundary_uncertain_ids": int(((np.abs(estimated_missing - w0) <= max(5e6, 1e9/rate)) |
                                               (np.abs(estimated_missing - w1) <= max(5e6, 1e9/rate))).sum()),
        **latency_stats(lat),
    }


def run_corpus():
    OUT.mkdir(exist_ok=True)
    files, runs, streams, losses, recoveries, resources, flood_rows, comparisons = [], [], [], [], [], [], [], []
    paths = sorted(RESULTS.glob("*/result.json"))
    if len(paths) != 193:
        raise ValueError(f"Expected 193 historical runs, found {len(paths)}")
    for result_path in paths:
        folder = result_path.parent
        result = json.loads(result_path.read_text())
        run_id, spec = result["id"], result["spec"]
        if run_id != folder.name:
            raise ValueError(f"Folder/result ID mismatch: {folder}")
        raw_path = folder / "raw.npz"
        source_paths = [result_path, raw_path, folder / "spec.json"]
        source_paths += sorted(folder.glob("gen-*.json"))
        for path in source_paths:
            if not path.is_file():
                raise FileNotFoundError(path)
        with np.load(raw_path) as raw:
            seq, produced, received = raw["seq"], raw["t_ns"], raw["t_ing"]
        run_row = {
            "run_id": run_id, "phase": spec["phase"], "variant": spec["variant"],
            "mode": spec["mode"], "rate_eps": spec["rate"], "duration_s": spec["duration"],
            "flood_extra_eps": spec.get("flood", {}).get("rate", ""),
            "fault_type": spec.get("fault", {}).get("type", ""),
            "fault_duration_s": spec.get("fault", {}).get("dur", ""),
            "turbo_controlled_in_original_campaign": spec["phase"] in
                {"ramp", "ramp-udp", "grid", "outage-load", "outage-file", "storage"},
            "original_drained_flag": result["drained"],
            "original_check_levels": ",".join(x["level"] for x in result.get("checks", [])),
            "stream_count": len(result["streams"]),
            "source_result": str(result_path.relative_to(ROOT)),
            "source_raw": str(raw_path.relative_to(ROOT)),
        }
        runs.append(run_row)
        usage = resource_metrics(folder / "stats.csv", spec["variant"])
        if usage:
            resources.append({"run_id": run_id, "phase": spec["phase"],
                              "variant": spec["variant"], **usage})
        for tag, old in result["streams"].items():
            manifest_path = folder / f"gen-{tag}.json"
            manifest = json.loads(manifest_path.read_text())
            metrics, windows, recovery = derive_stream(
                seq, produced, received, manifest,
                warmup_s=spec.get("warmup", 0) if tag != "flood" else 0,
                cooldown_s=spec.get("cooldown", 5),
                fault_ns=result.get("fault_ns"),
                observation_end_ns=int(received.max()) if len(received) else None,
            )
            # Structural accounting can be checked without re-running a system.
            if metrics["n_sent"] != old["n_sent"] or metrics["n_unique_receipts"] != old["n_unique"]:
                raise ValueError(f"Historical accounting mismatch: {run_id}/{tag}")
            if metrics["n_duplicate_receipts"] != old["n_indexed"] - old["n_unique"]:
                raise ValueError(f"Historical duplicate mismatch: {run_id}/{tag}")
            streams.append({"run_id": run_id, "stream": tag, "phase": spec["phase"],
                            "variant": spec["variant"], "mode": manifest["mode"],
                            "original_drained_flag": result["drained"],
                            "received_at_scan_status": "complete" if metrics["n_missing_at_scan"] == 0
                                                       else "incomplete",
                            "confirmed_drop_count": "", "confirmed_drop_note": "not established by raw index snapshot",
                            "source_manifest": str(manifest_path.relative_to(ROOT)), **metrics})
            comparisons.append({
                "run_id": run_id, "stream": tag, "phase": spec["phase"],
                "n_duplicate_receipts": metrics["n_duplicate_receipts"],
                "old_p95_ms": old.get("lat_p95_ms", ""),
                "first_receipt_p95_ms": metrics["p95_ms"],
                "p95_change_ms": (metrics["p95_ms"] - old["lat_p95_ms"]
                                  if metrics["p95_ms"] != "" and old.get("lat_p95_ms") is not None else ""),
                "old_max_ms": old.get("lat_max_ms", ""),
                "first_receipt_max_ms": metrics["max_ms"],
            })
            for window in windows:
                losses.append({"run_id": run_id, "stream": tag, **window})
            if recovery:
                recoveries.append({"run_id": run_id, "stream": tag, "variant": spec["variant"],
                                   "target_rate_eps": manifest["target_rate"],
                                   "fault_duration_s": spec["fault"]["dur"], **recovery,
                                   "old_recovery_s": old.get("recovery_s", "")})
            if spec.get("flood") and tag == "auth":
                flood_rows.append({"run_id": run_id, "variant": spec["variant"],
                                   "flood_extra_eps": spec["flood"]["rate"],
                                   **flood_window_metrics(seq, produced, received, manifest,
                                                         spec["flood"]["at"], spec["flood"]["dur"])})
    run_ids = {row["run_id"] for row in runs}
    for path in sorted(x for x in RESULTS.rglob("*") if x.is_file()):
        relative = path.relative_to(RESULTS)
        files.append({"run_id": relative.parts[0] if relative.parts[0] in run_ids else "",
                      "path": str(path.relative_to(ROOT)),
                      "bytes": path.stat().st_size, "sha256": sha256(path)})
    incomplete_runs = {row["run_id"] for row in streams if row["n_missing_at_scan"] > 0}
    for row in runs:
        row["analysis_status"] = ("incomplete_id_set_at_scan" if row["run_id"] in incomplete_runs
                                  else "complete_id_set_at_scan")
        # A warning or an incomplete scan does not invalidate the observation;
        # all historical runs remain in this descriptive reanalysis.
        row["excluded_from_offline_analysis"] = False
        row["exclusion_reason"] = ""
    write_csv("source_inventory.csv", files, ["run_id", "path", "bytes", "sha256"])
    write_csv("runs.csv", runs, list(runs[0]))
    write_csv("per_run_metrics.csv", streams, list(streams[0]))
    write_csv("loss_windows.csv", losses, list(losses[0]))
    write_csv("recovery.csv", recoveries, list(recoveries[0]))
    write_csv("resource_summary.csv", resources, list(resources[0]))
    write_csv("flood_windows.csv", flood_rows, list(flood_rows[0]))
    write_csv("comparison_old_new.csv", comparisons, list(comparisons[0]))
    summary = {
        "run_count": len(runs), "stream_count": len(streams),
        "n_sent_total": sum(x["n_sent"] for x in streams),
        "runs_original_drained_false": sum(x["original_drained_flag"] is False for x in runs),
        "streams_incomplete_at_scan": sum(x["n_missing_at_scan"] > 0 for x in streams),
        "source_files_hashed": len(files),
        "definitions": {
            "t_ing": "Elasticsearch/OpenSearch _ingest.timestamp: request receipt, not search visibility",
            "latency": "first receipt per distinct ID minus exact production time, after warmup/cooldown",
            "missing": "manifest sent IDs absent in the index snapshot after the harness observation window",
            "confirmed_drop": "unavailable from the raw index snapshot alone",
            "recovery_pre_clearance": "last first receipt for cohort produced through fault end, if all cohort IDs observed",
            "catchup_steady": "not identifiable from these timestamps after the generator stops",
        },
    }
    target = OUT / "summary.json"
    target.write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({k: v for k, v in summary.items() if k != "definitions"}, indent=2))


if __name__ == "__main__":
    run_corpus()
