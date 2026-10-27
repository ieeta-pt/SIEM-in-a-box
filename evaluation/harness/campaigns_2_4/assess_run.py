"""Predeclared, outcome-blind execution checks for a saved revision run.

An incomplete receipt set is an experimental outcome, not an exclusion.
This module checks whether the offered load and instrumentation were valid.
It reads only the new run directory and never modifies historical results.
"""

from __future__ import annotations

import json
import statistics
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def assess(run_dir: Path) -> dict:
    result = json.loads((run_dir / "result.json").read_text())
    spec = result["spec"]
    reasons, review = [], []
    records = [json.loads(line) for line in (run_dir / "telemetry.jsonl").read_text().splitlines()]
    if not records:
        reasons.append("no_periodic_telemetry")
    sources = ("nginx", "auth") if spec.get("flood") else ("nginx",)
    def incomplete_probe(row: dict) -> bool:
        if row.get("error") or not row.get("host"):
            return True
        if spec["variant"] == "C":
            udp = row.get("wazuh_udp_namespace", {})
            return "error" in udp or not {"InErrors", "RcvbufErrors"}.issubset(udp)
        if any("error" in row.get("collectors", {}).get(source, {}) or
               not {"InErrors", "RcvbufErrors"}.issubset(
                   row.get("collectors", {}).get(source, {}).get("udp_namespace", {})) or
               not row.get("collectors", {}).get(source, {}).get("filebeat", {}).get("queue")
               for source in sources):
            return True
        return spec["variant"] in {"A-sep", "A-shared", "A-topics", "A-pipelines"} and \
            ("error" in row.get("logstash", {}) or not row.get("logstash"))
    bad = [row for row in records if incomplete_probe(row)]
    if records and len(bad) / len(records) > 0.05:
        reasons.append("periodic_telemetry_failure_above_5_percent")
    offsets = sorted(row["wall_ns"] - row["monotonic_ns"] for row in records
                     if "wall_ns" in row and "monotonic_ns" in row)
    if len(offsets) != len(records):
        reasons.append("telemetry_clock_pair_missing")
    offset_span_ns = (offsets[round(0.99 * (len(offsets) - 1))] -
                      offsets[round(0.01 * (len(offsets) - 1))]) if offsets else None
    if offset_span_ns is not None and offset_span_ns > 5_000_000:
        reasons.append("host_wall_monotonic_offset_span_above_5ms")
    if any(row.get("host", {}).get("no_turbo") != "1" for row in records):
        reasons.append("turbo_policy_changed_or_unobserved")
    if any(not row.get("host", {}).get("ac_online") or
           not all(value == "1" for value in row["host"]["ac_online"])
           for row in records if row.get("host")):
        reasons.append("ac_power_changed_or_unobserved")
    for tag, metrics in result["streams"].items():
        manifest = json.loads((run_dir / f"gen-{tag}.json").read_text())
        duration = spec["flood"]["dur"] if tag == "flood" else spec["duration"]
        nominal = (spec["flood"]["rate"] if tag == "flood" else
                   spec["flood"]["auth_rate"] if tag == "auth" else spec["rate"])
        attempted_eps = metrics["n_attempted"] / duration
        if abs(attempted_eps / nominal - 1) > 0.05:
            reasons.append(f"{tag}:offered_rate_outside_5_percent")
        if metrics["n_send_errors"]:
            review.append(f"{tag}:sender_errors_{metrics['n_send_errors']}")
        if metrics["clock_offset_p99_p01_span_ns"] is None or \
                metrics["clock_offset_p99_p01_span_ns"] > 5_000_000:
            reasons.append(f"{tag}:clock_offset_span_above_5ms")
        if manifest["n_attempted"] != metrics["n_attempted"]:
            reasons.append(f"{tag}:attempt_count_mismatch")
        if metrics["n_missing_at_cutoff"]:
            review.append(f"{tag}:missing_at_cutoff_{metrics['n_missing_at_cutoff']}")
    if spec.get("fault") and not result.get("fault", {}).get("ready_ns"):
        reasons.append("fault_clearance_not_observed")
    quality = result.get("quality_queries", {})
    parse_counts = quality.get("parse_failure_counts", {})
    if isinstance(parse_counts, dict) and any(
            value is None or value > 0 for value in parse_counts.values()):
        reasons.append("parser_failure_or_missing_index")
    if any(quality.get("wrong_source_index_counts", {}).values()):
        reasons.append("source_routing_failure")
    if result["status"] != "complete":
        review.append("drain_timed_out_distinct_ids_incomplete")
    frequencies = [value for row in records if row.get("host")
                   for value in row["host"].get("cpu_khz", {}).values()
                   if value is not None]
    frequency_summary = None
    if frequencies:
        frequency_summary = {"median_khz": statistics.median(frequencies),
                             "minimum_khz": min(frequencies),
                             "maximum_khz": max(frequencies)}
    else:
        reasons.append("cpu_frequency_unobserved")
    initial = json.loads((run_dir / "telemetry_initial.json").read_text())
    final = json.loads((run_dir / "telemetry_final.json").read_text())
    for name, row in (("initial", initial), ("final", final)):
        if row["host"]["no_turbo"] != "1" or not row["host"]["ac_online"] or \
                not all(value == "1" for value in row["host"]["ac_online"]):
            reasons.append(f"{name}:host_power_policy_not_met")
    throttles = {}
    for cpu, value in initial["host"].get("core_throttle_count", {}).items():
        later = final["host"].get("core_throttle_count", {}).get(cpu)
        if value is not None and later is not None:
            throttles[cpu] = later - value
    if any(value > 0 for value in throttles.values()):
        review.append("cpu_thermal_throttle_recorded")
    return {"run_id": result["id"], "execution_valid": not reasons,
            "invalid_reasons": reasons, "review_flags": review,
            "frequency_summary": frequency_summary,
            "host_clock_offset_p99_p01_span_ns": offset_span_ns,
            "thermal_throttle_deltas": throttles,
            "note": "Missing at cutoff and sender errors are reported, never silently reclassified as confirmed receiver loss."}


if __name__ == "__main__":
    directory = Path(sys.argv[1])
    print(json.dumps(assess(directory), indent=2))
