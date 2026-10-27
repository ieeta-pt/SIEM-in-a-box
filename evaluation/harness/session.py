#!/usr/bin/env python3
"""List or run ICISSP 2027 confirmatory cells from the frozen matrices.

Usage: ./session.py list   or   ./session.py NUMBER [NUMBER ...]
Numbers 1-51 are the frozen confirmatory matrix (campaign 2); numbers from 52
on are the pre-registered factorial and cost cells (campaign 3,
campaign_factorial.json). A reviewed replacement keeps the original row number
and uses a fresh run ID.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

BENCH = Path(__file__).resolve().parent
VENV = BENCH / ".venv"
PYTHON = VENV / "bin/python"
if Path(sys.prefix) != VENV:
    os.execv(str(PYTHON), [str(PYTHON), str(Path(__file__).resolve()), *sys.argv[1:]])

import json
import re
import signal
import subprocess
import time

sys.path.insert(0, str(BENCH / "campaigns_2_4"))
from campaign_session import effective_spec, saved_run_state  # noqa: E402
from replacements import load_replacements  # noqa: E402
from run_revision import NEW_RESULTS, load_specs, require_factorial_lock, require_protocol_lock  # noqa: E402

CONTROLLER = BENCH / "campaigns_2_4/campaign_session.py"
INTER_RUN_SECONDS = 90
# Observed wall-clock minutes per cell in campaign 2 (startup + production + drain),
# used only for the time estimates printed by `list`.
OBSERVED_MINUTES = {("flood", True): (8, 16), ("flood", False): (7, 8), ("cost", None): (14, 20),
                    ("alerts", True): (12, 20), ("alerts", False): (11, 13)}


def condition_key(spec: dict) -> str:
    return re.sub(r"-r[0-9]+$", "", spec["id"])


CONFIRMATORY_CELLS = 51
FACTORIAL_CELLS = 13


def selected_rows() -> list[tuple[dict, dict, bool, str]]:
    require_protocol_lock()
    base_specs = load_specs("confirmatory")
    replacements = load_replacements(base_specs)
    rows = []
    for original in base_specs:
        try:
            actual, is_replacement = effective_spec(original, replacements)
            state = saved_run_state(actual)
        except RuntimeError:
            actual, is_replacement, state = original, False, "invalid_needs_review"
        rows.append((original, actual, is_replacement, state))
    assert len(rows) == CONFIRMATORY_CELLS
    require_factorial_lock()
    for spec in load_specs("factorial"):
        state = saved_run_state(spec)
        rows.append((spec, spec, False, state if state != "partial_or_invalid" else "invalid_needs_review"))
    sys.path.insert(0, str(BENCH / "campaigns_2_4/alerts_e2e"))
    from run_alerts import load_alert_specs, require_alerts_lock  # noqa: E402
    require_alerts_lock()
    for spec in load_alert_specs():
        state = saved_run_state(spec)
        rows.append((spec, spec, False, state if state != "partial_or_invalid" else "invalid_needs_review"))
    return rows


def campaign_of(number: int) -> tuple[str, int]:
    """Spec set and 1-based index inside that set for a global row number."""
    if number <= CONFIRMATORY_CELLS:
        return "confirmatory", number
    if number <= CONFIRMATORY_CELLS + FACTORIAL_CELLS:
        return "factorial", number - CONFIRMATORY_CELLS
    return "alerts", number - CONFIRMATORY_CELLS - FACTORIAL_CELLS


def estimate_text(spec: dict) -> str:
    if spec.get("detection_rules"):
        lo, hi = OBSERVED_MINUTES[("alerts", bool(spec["flood"]["rate"]))]
        return f"~{lo}–{hi} min"
    if spec.get("extra_services"):
        lo, hi = OBSERVED_MINUTES[("cost", None)]
    elif spec.get("flood"):
        lo, hi = OBSERVED_MINUTES[("flood", bool(spec["flood"]["rate"]))]
    else:
        return duration_text(spec)
    return f"~{lo}–{hi} min"


def duration_text(spec: dict) -> str:
    production = spec["duration"] / 60
    maximum = (spec["duration"] + spec["drain_timeout"]) / 60
    return f"{production:g}–{maximum:g} min + start-up"


def result_feedback(spec: dict) -> str:
    run_dir = NEW_RESULTS / spec["id"]
    result_file = run_dir / "result.json"
    assessment_file = run_dir / "execution_assessment.json"
    if not result_file.is_file() or not assessment_file.is_file():
        return f"{spec['id']}: ainda sem resultado final"
    result = json.loads(result_file.read_text())
    assessment = json.loads(assessment_file.read_text())
    missing = {tag: row["n_missing_at_cutoff"] for tag, row in result["streams"].items()}
    errors = {name: row.get("InErrors") for name, row in
              result["udp_namespace_counter_deltas"].items()}
    auth = result["streams"].get("auth", {})
    window = auth.get("flood_window") or auth.get("full_window") or {}
    auth_p95 = window.get("p95_ms")
    p95_text = (f"; auth p95={auth_p95:.1f} ms (received)"
                if auth_p95 is not None and assessment["execution_valid"] else "")
    reasons = assessment.get("invalid_reasons", [])
    alerts = result.get("alerts_e2e")
    if alerts:
        lat = alerts.get("alert_latency_window_s") or {}
        p95_text += (f"; alerts: {alerts['window_alerts']}/{alerts['window_sent']} in window, "
                     f"latency p95={lat.get('p95', float('nan')):.1f} s, brute force={len(alerts['threshold_alerts_during_production'])}x")
    return (f"{spec['id']}: {result['status']}; execution valid="
            f"{assessment['execution_valid']}; missing at cutoff={missing}; "
            f"UDP InErrors={errors}{p95_text}"
            + (f"; invalid reasons={reasons}" if reasons else ""))


def list_runs(rows: list[tuple[dict, dict, bool, str]]) -> None:
    print("Campaign 2 (frozen matrix, 1–51), campaign 3 (topic × pipeline factorial and cost, 52–64) and campaign 4 (end-to-end alerts, 65–76).")
    by_condition = {}
    for original, _, _, _ in rows:
        by_condition.setdefault(condition_key(original), []).append(original["id"])
    complete = {}
    for original, _, _, state in rows:
        if state == "complete_valid":
            key = condition_key(original)
            complete[key] = complete.get(key, 0) + 1
    print(f"{'No':>2}  {'Run':<52}  {'Done/total':>16}  {'State':<28}  Estimated time")
    print("-" * 131)
    for number, (original, actual, is_replacement, state) in enumerate(rows, 1):
        key = condition_key(original)
        progress = f"{complete.get(key, 0)}/{len(by_condition[key])}"
        if state == "complete_valid":
            status = json.loads((NEW_RESULTS / actual["id"] / "result.json").read_text())["status"]
            status = "valid; drain incomplete" if status == "timed_out_incomplete" else "valid"
        elif state == "new":
            status = "replacement pending" if is_replacement else "pending"
        else:
            status = "invalid; review"
        if number in (CONFIRMATORY_CELLS + 1, CONFIRMATORY_CELLS + FACTORIAL_CELLS + 1):
            print("-" * 131)
        print(f"{number:>2}  {actual['id']:<52}  {progress:>16}  "
              f"{status:<28}  {estimate_text(actual) if number > CONFIRMATORY_CELLS else duration_text(actual)}")
    valid = sum(state == "complete_valid" for _, _, _, state in rows)
    pending = [actual for _, actual, _, state in rows if state == "new"]
    production_min = sum(spec["duration"] for spec in pending) / 60
    drain_max_min = sum(spec["drain_timeout"] for spec in pending) / 60
    print(f"\nTotal: {valid}/{len(rows)} valid; {len(pending)} to run; "
          f"{int(production_min//60)} h {int(production_min%60)} min of generation + "
          f"up to {int(drain_max_min//60)} h {int(drain_max_min%60)} min of drain, "
          "plus start-up. Missing at cutoff is not confirmed loss.")


def run_one(number: int, rows: list[tuple[dict, dict, bool, str]]) -> int:
    if not 1 <= number <= len(rows):
        raise ValueError(f"Choose a number from 1 to {len(rows)}")
    original, spec, is_replacement, state = rows[number - 1]
    if state == "complete_valid":
        print(f"Run {number} already complete and valid. {result_feedback(spec)}", flush=True)
        return 0
    if state != "new":
        raise RuntimeError(f"Run {number} needs review; existing data will not be overwritten")
    if number > 1:
        previous = rows[number - 2]
        print("Resultado da run anterior: " + result_feedback(previous[1]), flush=True)
    if is_replacement:
        print(f"Replaces {original['id']}; the invalid execution and its raw data are preserved.",
              flush=True)
    campaign, index = campaign_of(number)
    print(f"Starting run {number}/{len(rows)}: {spec['id']}. Estimate: "
          f"{estimate_text(spec)} (start-up + generation + drain).", flush=True)
    check = subprocess.run([str(PYTHON), str(CONTROLLER), "--set", campaign, "--check-only"], cwd=BENCH)
    if check.returncode:
        print("Preflight falhou; nenhuma run foi iniciada.", flush=True)
        return check.returncode
    command = [str(PYTHON), str(CONTROLLER), "--set", campaign, "--only-index", str(index),
               "--max-hours", "4"]
    # Keep the caller's controlling terminal so sudo can request a password
    # when Turbo must be disabled. The controller puts load workers in their
    # own process groups and handles stop signals itself.
    process = subprocess.Popen(command, cwd=BENCH)
    stop_requested = False
    def request_stop(signum, _frame):
        nonlocal stop_requested
        stop_requested = True
        print(f"Signal {signum}: the current run will finish before stopping.", flush=True)
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
    old_int = signal.signal(signal.SIGINT, request_stop)
    old_term = signal.signal(signal.SIGTERM, request_stop)
    try:
        code = process.wait()
    finally:
        signal.signal(signal.SIGINT, old_int)
        signal.signal(signal.SIGTERM, old_term)
    print("Resultado: " + result_feedback(spec), flush=True)
    state_after = saved_run_state(spec)
    if code:
        if state_after == "new":
            print("The run did not start; the same number can be repeated after fixing "
                  "the start-up problem.", flush=True)
        else:
            print("The execution stopped with an error; review the log and the assessment before repeating "
                  "with a new ID.", flush=True)
    elif state_after != "complete_valid":
        print("The session ended without a valid run; batch stopped for review.", flush=True)
        return 1
    if stop_requested:
        print("Stop request received; no further run will start.", flush=True)
        return 130
    return code


def wait_between_runs(seconds: int = INTER_RUN_SECONDS) -> None:
    for remaining in range(seconds, 0, -30):
        print(f"Pause between runs: next run in {remaining} s. "
              "Ctrl-C stops the batch before the next run.", flush=True)
        time.sleep(min(30, remaining))


def run_batch(numbers: list[int], rows: list[tuple[dict, dict, bool, str]]) -> int:
    if any(number < 1 or number > len(rows) for number in numbers):
        raise ValueError(f"Choose numbers from 1 to {len(rows)}")
    if len(numbers) != len(set(numbers)):
        raise ValueError("The batch contains repeated numbers")
    if len(numbers) > 1 and numbers != sorted(numbers):
        raise ValueError("Give the numbers in increasing order")
    blocked = [number for number in numbers if rows[number - 1][3] not in
               ("new", "complete_valid")]
    if blocked:
        raise RuntimeError(f"Runs {blocked} need review; batch not started")
    pending = [number for number in numbers if rows[number - 1][3] == "new"]
    if len(numbers) > 1:
        production = sum(rows[number - 1][1]["duration"] for number in pending)
        drain = sum(rows[number - 1][1]["drain_timeout"] for number in pending)
        pauses = max(0, len(pending) - 1) * INTER_RUN_SECONDS
        print(f"Batch {numbers}: {len(pending)} pending runs; "
              f"estimate {((production + pauses) / 60):g}–"
              f"{((production + drain + pauses) / 60):g} min + start-ups. "
              "Runs one at a time; stops on failure or invalid execution.", flush=True)
    completed = 0
    for number in numbers:
        if completed and rows[number - 1][3] == "new":
            wait_between_runs()
        code = run_one(number, rows)
        if code:
            print(f"Batch stopped after position {number}; "
                  f"positions {numbers[numbers.index(number)+1:]} will not start.", flush=True)
            return code
        if rows[number - 1][3] == "new":
            completed += 1
    if len(numbers) > 1:
        print(f"Batch finished: {completed} new valid runs. "
              "See ./session.py list for the updated state.", flush=True)
    return 0


def main() -> int:
    args = sys.argv[1:]
    if not args or (args[0] == "list" and len(args) != 1) or \
            (args[0] != "list" and not all(re.fullmatch(r"[0-9]+", arg) for arg in args)):
        print("Usage: ./session.py list  or  ./session.py NUMBER [NUMBER ...]",
              file=sys.stderr)
        return 2
    rows = selected_rows()
    if args[0] == "list":
        list_runs(rows)
        return 0
    return run_batch([int(arg) for arg in args], rows)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("Batch stopped before the next run.", file=sys.stderr, flush=True)
        sys.exit(130)
    except Exception as exc:
        print(f"ERRO: {exc}", file=sys.stderr, flush=True)
        sys.exit(1)
