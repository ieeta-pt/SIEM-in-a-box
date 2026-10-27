"""Exact first-receipt and backlog analysis for proposed new runs.

This operates on a saved generator-attempt log and an index snapshot. It
never infers a production timestamp for an absent event from target rate.
"""

from __future__ import annotations

import csv
import math
from pathlib import Path

import numpy as np

from eventlog import read as read_events
from reanalyse import first_receipts, latency_stats


def _window(ids: np.ndarray, produced: np.ndarray, received: np.ndarray,
            sent_ids: np.ndarray, sent_times: np.ndarray, start_ns: int,
            end_ns: int) -> dict:
    sent_in = (sent_times >= start_ns) & (sent_times < end_ns)
    seen_in = (produced >= start_ns) & (produced < end_ns)
    expected = sent_ids[sent_in]
    observed = ids[seen_in]
    missing = np.setdiff1d(expected, observed, assume_unique=True)
    lat = (received[seen_in] - produced[seen_in]) / 1e6
    return {"n_sent_ok": len(expected), "n_first_receipts": len(observed),
            "n_missing_at_cutoff": len(missing),
            "missing_pct_at_cutoff": 100 * len(missing) / len(expected) if len(expected) else None,
            **latency_stats(lat)}


def backlog_series(sent_times: np.ndarray, receipts: np.ndarray, start_ns: int,
                   end_ns: int) -> list[dict]:
    sent = np.sort(sent_times)
    got = np.sort(receipts)
    grid = np.arange(start_ns, end_ns + 1, 1_000_000_000, dtype=np.int64)
    made = np.searchsorted(sent, grid, side="right")
    arrived = np.searchsorted(got, grid, side="right")
    return [{"time_ns": int(t), "seconds_from_start": (int(t) - start_ns) / 1e9,
             "sent_cumulative": int(m), "first_receipts_cumulative": int(a),
             "backlog_to_request_receipt": int(m - a)}
            for t, m, a in zip(grid, made, arrived)]


def stable_catchup(series: list[dict], fault_start_ns: int, ready_ns: int,
                   generator_end_ns: int, rate_eps: float) -> dict:
    baseline = [row["backlog_to_request_receipt"] for row in series
                if fault_start_ns - 40_000_000_000 <= row["time_ns"] <
                   fault_start_ns - 10_000_000_000]
    if len(baseline) < 20:
        return {"catchup_status": "invalid_baseline", "catchup_steady_s": None}
    level = float(np.median(baseline))
    tolerance = max(50, math.ceil(0.1 * rate_eps))
    after = [row for row in series if ready_ns <= row["time_ns"] <= generator_end_ns]
    for i in range(max(0, len(after) - 30)):
        if all(row["backlog_to_request_receipt"] <= level + tolerance
               for row in after[i:i+31]):
            return {"catchup_status": "observed", "catchup_steady_s":
                    (after[i]["time_ns"] - ready_ns) / 1e9,
                    "baseline_backlog": level, "tolerance_events": tolerance,
                    "stable_window_s": 30}
    return {"catchup_status": "censored_before_generator_stop", "catchup_steady_s": None,
            "baseline_backlog": level, "tolerance_events": tolerance,
            "stable_window_s": 30}


def summarize_stream(raw: dict, manifest: dict, event_path: Path, spec: dict,
                     *, fault: dict | None = None, cutoff_ns: int,
                     campaign_start_ns: int | None = None) -> tuple[dict, list[dict]]:
    events = read_events(event_path, manifest)
    sent = events[events["sent_ok"] == 1]
    sent_ids = sent["seq"]
    sent_times = sent["wall_ns"]
    ids, produced, received, duplicates = first_receipts(
        raw["seq"], raw["t_ns"], raw["t_ing"],
        manifest["seq_start"], manifest["seq_end"])
    locations = np.searchsorted(sent_ids, ids)
    if np.any(locations >= len(sent_ids)) or not np.array_equal(sent_ids[locations], ids):
        raise ValueError("Indexer has an ID absent from successful sends")
    if not np.array_equal(sent_times[locations], produced):
        raise ValueError("Generator and indexed production timestamps disagree")
    if np.any(received < produced):
        raise ValueError("Negative production-to-request-receipt latency")
    missing = np.setdiff1d(sent_ids, ids, assume_unique=True)
    offsets = events["wall_ns"].astype(np.int64) - events["monotonic_ns"]
    offset_span = (float(np.percentile(offsets, 99) - np.percentile(offsets, 1))
                   if len(offsets) else None)
    if offset_span is not None and offset_span > 5_000_000:
        raise ValueError("Wall/monotonic offset changed by >5 ms (p99-p1)")
    full = _window(ids, produced, received, sent_ids, sent_times,
                   manifest["start_ns"] + int(spec.get("warmup", 0) * 1e9),
                   manifest["end_ns"] - int(spec.get("cooldown", 0) * 1e9))
    row = {
        "n_attempted": len(events), "n_sent_ok": len(sent),
        "n_send_errors": int(len(events) - len(sent)),
        "n_first_receipts": len(ids), "n_duplicate_receipts": duplicates,
        "n_missing_at_cutoff": len(missing),
        "received_at_cutoff_status": "complete" if not len(missing) else "incomplete",
        "confirmed_receiver_drop_count": None,
        "clock_offset_p99_p01_span_ns": offset_span,
        "cutoff_ns": cutoff_ns, "full_window": full,
    }
    if spec.get("flood"):
        flood = spec["flood"]
        start = (campaign_start_ns if campaign_start_ns is not None else manifest["start_ns"])
        start += int(flood["at"] * 1e9)
        row["flood_window"] = _window(ids, produced, received, sent_ids, sent_times,
                                      start, start + int(flood["dur"] * 1e9))
    end_series_ns = max(cutoff_ns, int(manifest["end_ns"]))
    series = backlog_series(sent_times, received, int(manifest["start_ns"]), end_series_ns)
    if fault:
        ready_ns = int(fault["ready_ns"])
        cohort = sent_times <= ready_ns
        pre_ids = sent_ids[cohort]
        pre_missing = np.setdiff1d(pre_ids, ids, assume_unique=True)
        pre_seen = np.isin(ids, pre_ids, assume_unique=True)
        last_seen = (max(0.0, (int(received[pre_seen].max()) - ready_ns) / 1e9)
                     if np.any(pre_seen) else None)
        row["pre_clearance"] = {
            "status": "complete_at_cutoff" if not len(pre_missing) else "incomplete_at_cutoff",
            "n_missing_at_cutoff": len(pre_missing),
            "last_observed_s": last_seen,
            "recovery_s": last_seen if not len(pre_missing) else None,
        }
        row["catchup"] = (
            {"catchup_status": "incomplete_at_cutoff", "catchup_steady_s": None}
            if len(missing) else stable_catchup(
                series, int(fault["effective_start_ns"]), ready_ns,
                int(manifest["end_ns"]), float(manifest["target_rate"])))
    return row, series


def write_backlog(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
