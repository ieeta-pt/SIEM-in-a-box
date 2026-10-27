"""Run the reviewed confirmatory matrix or one numbered cell.

This program collects data only. It requires a scientifically reviewed
protocol_lock.json, never chooses treatments or changes the manuscript, and
never overwrites a run directory. A failed/partial run stops the session.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import signal
import statistics
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from host_affinity import (apply as apply_affinity, own_threads,
                           restore as restore_affinity, sudo_set_affinity)
from replacements import load_replacements
from run_revision import (BENCH, HERE, NEW_RESULTS, load_specs, require_factorial_lock,
                          require_protocol_lock, static_preflight)
from telemetry import host_snapshot

TURBO_PATH = Path("/sys/devices/system/cpu/intel_pstate/no_turbo")
PACKAGE_THROTTLE = Path("/sys/devices/system/cpu/cpu0/thermal_throttle/package_throttle_count")
SUT_CPUS = set(range(8))
DESKTOP_CPUS = set(range(8, 12))
BENCH_CONTAINERS = {"bench-es", "bench-kafka", "bench-logstash", "bench-kibana",
                    "bench-es-sec", "bench-kibana-sec",
                    "bench-wazuh-manager", "bench-wazuh-indexer",
                    "bench-fb-nginx", "bench-fb-auth"}


def is_docker_cgroup(cgroup: str) -> bool:
    return any("/docker-" in line or "/docker/" in line
               for line in cgroup.splitlines())


def is_container_thread(tid: int) -> bool:
    try:
        return is_docker_cgroup(Path(f"/proc/{tid}/cgroup").read_text())
    except OSError:
        return False


def say(message: str) -> None:
    print(f"[{datetime.now().astimezone().isoformat(timespec='seconds')}] {message}",
          flush=True)


def free_gib() -> float:
    stat = os.statvfs(BENCH)
    return stat.f_bavail * stat.f_frsize / 1024**3


def package_temp_c(host: dict | None = None) -> float | None:
    host = host or host_snapshot()
    values = list(host.get("package_temp_c", {}).values())
    return max(values) if values else None


def docker_names() -> list[str]:
    proc = subprocess.run(["docker", "ps", "--format", "{{.Names}}"],
                          capture_output=True, text=True, timeout=20)
    if proc.returncode:
        raise RuntimeError(f"Docker unavailable: {proc.stderr.strip()}")
    return proc.stdout.splitlines()


def ntp_synced() -> bool:
    proc = subprocess.run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"],
                          capture_output=True, text=True, timeout=10)
    if proc.returncode:
        raise RuntimeError(f"Clock synchronization status unavailable: {proc.stderr.strip()}")
    return proc.stdout.strip() == "yes"


def cpu_ticks() -> dict[int, tuple[int, int]]:
    out = {}
    for line in Path("/proc/stat").read_text().splitlines():
        parts = line.split()
        if not parts or not parts[0].startswith("cpu") or not parts[0][3:].isdigit():
            continue
        values = list(map(int, parts[1:]))
        idle = values[3] + (values[4] if len(values) > 4 else 0)
        out[int(parts[0][3:])] = (sum(values), idle)
    return out


def cpu_busy_fraction(before: dict, after: dict, cpus: set[int]) -> list[float]:
    result = []
    for cpu in sorted(cpus):
        total = after[cpu][0] - before[cpu][0]
        idle = after[cpu][1] - before[cpu][1]
        result.append((total - idle) / total if total > 0 else 0.0)
    return result


def check_user_affinity() -> None:
    # The controller, desktop and fresh user threads should be off SUT CPUs.
    # Threads created after apply_affinity() (by a process whose mask could
    # not be changed, or by a root-owned launcher) are moved here first;
    # only threads that still overlap the SUT after that stop the session.
    offenders = []
    for tid in own_threads():
        # Wazuh's non-root processes can have the same host UID, but their
        # container cgroup is deliberately pinned to the SUT CPUs.
        if is_container_thread(tid):
            continue
        try:
            if not os.sched_getaffinity(tid) & SUT_CPUS:
                continue
            try:
                os.sched_setaffinity(tid, DESKTOP_CPUS)
            except PermissionError:
                try:
                    sudo_set_affinity(tid, DESKTOP_CPUS)
                except (OSError, RuntimeError, subprocess.SubprocessError):
                    pass
            except OSError:
                pass
            if os.sched_getaffinity(tid) & SUT_CPUS:
                offenders.append(tid)
        except OSError:
            pass
    if offenders:
        details = []
        for tid in offenders[:10]:
            try:
                status = Path(f"/proc/{tid}/status").read_text()
                fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
                pid = fields["Tgid"].strip()
                cmd = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")[:80]
                details.append(f"{tid} ({fields['Name'].strip()}, pid {pid}, ppid {fields['PPid'].strip()}, "
                               f"cpus {fields['Cpus_allowed_list'].strip()}): {cmd}")
            except OSError:
                details.append(f"{tid} (gone)")
        raise RuntimeError("User threads still allowed on SUT CPUs:\n  " + "\n  ".join(details))


def host_guard(*, between_runs: bool = False) -> dict:
    preflight = static_preflight()
    host = host_snapshot()
    temp = package_temp_c(host)
    names = docker_names()
    foreign = [name for name in names if name not in BENCH_CONTAINERS]
    if foreign:
        raise RuntimeError(f"Other Docker containers active: {foreign}")
    if not preflight["ready_for_pilots"]:
        raise RuntimeError(f"Host preflight failed: {preflight}")
    if not ntp_synced():
        raise RuntimeError("Host clock is not synchronized")
    if temp is None or temp >= 80:
        raise RuntimeError(f"Host too warm or temperature unavailable: {temp} C")
    if between_runs:
        check_user_affinity()
    return {"temp_c": temp, "free_gib": round(free_gib(), 1), "ntp_synced": True,
            "no_turbo": host["no_turbo"], "ac_online": host["ac_online"],
            "docker_containers": names}


def idle_guard(duration_s: int) -> dict:
    first = cpu_ticks()
    first_throttle = int(PACKAGE_THROTTLE.read_text())
    time.sleep(duration_s)
    second = cpu_ticks()
    values = cpu_busy_fraction(first, second, SUT_CPUS | set(range(12, 20)))
    delta = int(PACKAGE_THROTTLE.read_text()) - first_throttle
    if delta:
        raise RuntimeError(f"Thermal throttle increased during idle guard: {delta}")
    if statistics.mean(values) > 0.20 or max(values) > 0.45:
        raise RuntimeError(f"Reserved CPUs busy before campaign: mean={statistics.mean(values):.2f}, max={max(values):.2f}")
    return {"duration_s": duration_s, "cpu_busy_mean": round(statistics.mean(values), 3),
            "cpu_busy_max": round(max(values), 3), "package_throttle_delta": delta}


def write_turbo(value: str) -> None:
    proc = subprocess.run(["sudo", "-n", "tee", str(TURBO_PATH)], input=value + "\n",
                          capture_output=True, text=True, timeout=20)
    if proc.returncode or TURBO_PATH.read_text().strip() != value:
        raise RuntimeError(f"Could not set no_turbo={value}: {proc.stderr.strip()}")


def sudo_keepalive(stop: threading.Event, failed: threading.Event) -> None:
    while not stop.wait(60):
        proc = subprocess.run(["sudo", "-n", "-v"], capture_output=True, timeout=20)
        if proc.returncode:
            failed.set()
            return


def stop_stacks() -> None:
    commands = [(["docker", "compose", "--profile", "kafka", "--profile", "cost", "stop"], BENCH),
                (["docker", "compose", "-f", "campaigns_2_4/alerts_e2e/compose-alerts.yml", "stop"], BENCH),
                (["docker", "compose", "-f", "compose-bench.yml", "stop"],
                 BENCH / "wazuh")]
    for cmd, cwd in commands:
        try:
            proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                                  timeout=180)
            if proc.returncode:
                say(f"WARNING: stack stop failed: {proc.stderr[-500:]}")
        except Exception as exc:
            say(f"WARNING: stack stop failed: {exc}")


def saved_run_state(spec: dict) -> str:
    directory = NEW_RESULTS / spec["id"]
    if not directory.exists():
        return "new"
    result = directory / "result.json"
    assessment = directory / "execution_assessment.json"
    saved_spec = directory / "spec.json"
    raw = directory / "raw.npz"
    if all(path.is_file() for path in (result, assessment, saved_spec, raw)):
        try:
            if json.loads(saved_spec.read_text()) == spec and \
                    json.loads(result.read_text()).get("id") == spec["id"] and \
                    json.loads(assessment.read_text()).get("execution_valid"):
                return "complete_valid"
        except (OSError, ValueError):
            pass
    return "partial_or_invalid"


def effective_spec(spec: dict, replacements: dict[str, dict]) -> tuple[dict, bool]:
    if saved_run_state(spec) != "partial_or_invalid":
        return spec, False
    replacement = replacements.get(spec["id"])
    if replacement is None:
        raise RuntimeError(f"Unreviewed invalid/partial run: {spec['id']}")
    return replacement, True


def log_summary(spec: dict, number: int, total: int) -> dict:
    directory = NEW_RESULTS / spec["id"]
    result = json.loads((directory / "result.json").read_text())
    assessment = json.loads((directory / "execution_assessment.json").read_text())
    record = {"index": number, "total": total, "id": spec["id"],
              "phase": spec["phase"], "status": result["status"],
              "execution_valid": assessment["execution_valid"],
              "review_flags": assessment["review_flags"],
              "thermal_throttle_deltas": assessment["thermal_throttle_deltas"],
              "missing_at_cutoff": {tag: row["n_missing_at_cutoff"]
                                    for tag, row in result["streams"].items()},
              "udp_in_errors": {name: counters.get("InErrors") for name, counters in
                                result["udp_namespace_counter_deltas"].items()}}
    return record


def execute(args: argparse.Namespace) -> None:
    specs = load_specs(args.set)
    replacements = load_replacements(specs) if args.set == "confirmatory" else {}
    if args.only_index is not None and not 1 <= args.only_index <= len(specs):
        raise ValueError(f"Run number must be between 1 and {len(specs)}")
    if args.dry_run:
        say(f"DRY RUN: {len(specs)} confirmatory cells; production "
            f"{sum(s['duration'] for s in specs)/3600:.2f} h; "
            f"protocol lock present={(HERE/'protocol_lock.json').exists()}")
        for i, spec in enumerate(specs, 1):
            run_spec, is_replacement = effective_spec(spec, replacements)
            say(f"{i:02d}/{len(specs)} {run_spec['phase']} {run_spec['id']} "
                f"{run_spec['duration']} s; {saved_run_state(run_spec)}"
                f"{' (replacement for '+spec['id']+')' if is_replacement else ''}")
        return

    if args.set == "confirmatory":
        require_protocol_lock()  # scientific review happens before host mutation
    elif args.set == "alerts":
        sys.path.insert(0, str(HERE / "alerts_e2e"))
        from run_alerts import require_alerts_lock
        require_alerts_lock()
    else:
        require_factorial_lock()
    if os.geteuid() == 0:
        raise RuntimeError("Run as your normal user, not root")
    names = docker_names()
    foreign = [name for name in names if name not in BENCH_CONTAINERS]
    if foreign:
        raise RuntimeError(f"Other Docker containers active: {foreign}")
    if args.check_only:
        host = host_snapshot()
        preflight = static_preflight()
        counts = {state: 0 for state in ("new", "complete_valid", "partial_or_invalid")}
        for spec in specs:
            run_spec, _ = effective_spec(spec, replacements)
            counts[saved_run_state(run_spec)] += 1
        say(f"CHECK ONLY: lock valid; run states={counts}; docker={names}; "
            f"TurboOff={host['no_turbo']}; AC={host['ac_online']}; "
            f"temp={package_temp_c(host)} C; free={free_gib():.1f} GiB; "
            f"CPU allocation available={preflight['required_cpu_affinity_available']}; "
            f"NTP synchronized={ntp_synced()}")
        if counts["partial_or_invalid"]:
            raise RuntimeError("Existing partial/invalid runs need scientific review")
        if names:
            raise RuntimeError("Benchmark containers are active before campaign launch")
        if not preflight["required_cpu_affinity_available"] or \
                not preflight["cpu_freq_samples_present"] or free_gib() < 20 or \
                not host["ac_online"] or any(x != "1" for x in host["ac_online"]) or \
                package_temp_c(host) is None or package_temp_c(host) >= 80:
            raise RuntimeError("Host is not ready for the campaign")
        if not ntp_synced():
            raise RuntimeError("Host clock is not synchronized")
        say("CHECK ONLY passed; Turbo will be disabled automatically at launch if needed")
        return
    if names:
        raise RuntimeError(f"Benchmark containers already active before launch: {names}")
    NEW_RESULTS.mkdir(exist_ok=True)
    session = NEW_RESULTS / ("campaign-session-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
    session.mkdir(exist_ok=False)
    with (NEW_RESULTS / ".session.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        original_turbo = TURBO_PATH.read_text().strip()
        affinity_path = session / "affinity-before.json"
        changed_turbo = False
        changed_affinity = False
        keepalive_stop = threading.Event()
        keepalive_failed = threading.Event()
        stopping = threading.Event()
        records = []
        start = time.monotonic()
        started_at = datetime.now(timezone.utc).isoformat()
        outcome = "aborted"
        error = None
        active_process = None
        active_run_id = None
        def request_stop(signum, _frame):
            say(f"Signal {signum} received; stop after the current run")
            stopping.set()
        signal.signal(signal.SIGINT, request_stop)
        signal.signal(signal.SIGTERM, request_stop)
        try:
            if original_turbo not in {"0", "1"}:
                raise RuntimeError(f"Unknown original Turbo state: {original_turbo}")
            if original_turbo == "0":
                say("Requesting sudo once to disable Turbo and restore it at exit")
                subprocess.run(["sudo", "-v"], check=True)
                changed_turbo = True
                write_turbo("1")
                threading.Thread(target=sudo_keepalive,
                                 args=(keepalive_stop, keepalive_failed),
                                 daemon=True).start()
            changed_affinity = True
            privileged_affinity = apply_affinity(affinity_path, DESKTOP_CPUS)
            if privileged_affinity and original_turbo == "1":
                threading.Thread(target=sudo_keepalive,
                                 args=(keepalive_stop, keepalive_failed),
                                 daemon=True).start()
            say(f"Host: {host_guard(between_runs=True)}")
            say(f"Idle guard: {idle_guard(args.idle_seconds)}")
            if stopping.is_set():
                raise RuntimeError("Session stopped before first run")
            previous_phase = None
            for i, spec in enumerate(specs, 1):
                if args.only_index is not None and i != args.only_index:
                    continue
                if stopping.is_set() or keepalive_failed.is_set():
                    raise RuntimeError("Session stopped before next run")
                run_spec, is_replacement = effective_spec(spec, replacements)
                state = saved_run_state(run_spec)
                if state == "complete_valid":
                    say(f"skip {i}/{len(specs)} {run_spec['id']}: already complete and valid")
                    continue
                if state != "new":
                    raise RuntimeError(f"Existing partial/invalid run requires review and a new ID: {run_spec['id']}")
                elapsed_h = (time.monotonic() - start) / 3600
                needed_h = (run_spec["duration"] + run_spec["drain_timeout"] + 600) / 3600
                if elapsed_h + needed_h > args.max_hours:
                    say(f"Session time limit reached before {run_spec['id']}; safe to resume later")
                    outcome = "time_limit"
                    break
                if records and args.inter_run_seconds:
                    previous = records[-1]
                    say(f"PREVIOUS {previous['id']}: status={previous['status']}, "
                        f"missing={previous['missing_at_cutoff']}; next {run_spec['id']} "
                        f"in {args.inter_run_seconds} s")
                    stopping.wait(args.inter_run_seconds)
                    if stopping.is_set() or keepalive_failed.is_set():
                        raise RuntimeError("Session stopped before next run")
                if run_spec["phase"] != previous_phase:
                    say(f"Starting phase {run_spec['phase']}")
                    previous_phase = run_spec["phase"]
                say(f"Preflight {i}/{len(specs)} {run_spec['id']}: {host_guard(between_runs=True)}")
                if free_gib() < 20:
                    raise RuntimeError("Less than 20 GiB free before run")
                throttle_before = int(PACKAGE_THROTTLE.read_text())
                if is_replacement:
                    command = [str(BENCH / ".venv/bin/python"),
                               str(HERE / "run_replacement.py"), "--id", run_spec["id"]]
                else:
                    command = [str(BENCH / ".venv/bin/python"), str(HERE / "run_revision.py"),
                               "execute", "--set", args.set, "--id", run_spec["id"],
                               "--hours", str(args.max_hours)]
                    if args.set == "alerts":
                        command = [str(BENCH / ".venv/bin/python"), str(HERE / "alerts_e2e/run_alerts.py"),
                                   "execute", "--id", run_spec["id"]]
                log_path = session / f"{i:02d}-{run_spec['id']}.log"
                say(f"START {i}/{len(specs)} {run_spec['id']} "
                    f"({run_spec['duration']/60:g} min production + up to "
                    f"{run_spec['drain_timeout']/60:g} min drain + startup); log={log_path}")
                with log_path.open("w") as log:
                    # Own process group: a Ctrl-C in the terminal reaches only
                    # this controller, which then waits for the run to finish.
                    run_started = time.monotonic()
                    process = subprocess.Popen(command, cwd=BENCH, stdout=log,
                                               stderr=subprocess.STDOUT,
                                               process_group=0)
                    active_process = process
                    active_run_id = run_spec["id"]
                    stop_after = []
                    while True:
                        try:
                            code = process.wait(timeout=args.heartbeat_seconds)
                            break
                        except subprocess.TimeoutExpired:
                            try:
                                host = host_snapshot()
                                temp = package_temp_c(host)
                                throttle_delta = int(PACKAGE_THROTTLE.read_text()) - throttle_before
                                free = free_gib()
                                say(f"RUN {i}/{len(specs)} {run_spec['id']}: "
                                    f"elapsed_this_run={(time.monotonic()-run_started)/60:.1f} min, "
                                    f"temp={temp} C, TurboOff={host['no_turbo']}, "
                                    f"AC={host['ac_online']}, free={free:.1f} GiB, "
                                    f"throttle_delta={throttle_delta}")
                                if host["no_turbo"] != "1" or not host["ac_online"] or \
                                        any(x != "1" for x in host["ac_online"]):
                                    stop_after.append("AC/Turbo changed")
                                if temp is None or temp >= 90 or throttle_delta or free < 10:
                                    stop_after.append("temperature/throttle/disk guard")
                                if any(name not in BENCH_CONTAINERS for name in docker_names()):
                                    stop_after.append("foreign Docker container started")
                                check_user_affinity()
                            except Exception as exc:
                                stop_after.append(f"host monitoring failed: {exc}")
                                say(f"WARNING: {stop_after[-1]}; finishing current run")
                    active_process = None
                    active_run_id = None
                if code:
                    tail = log_path.read_text(errors="replace")[-2500:]
                    raise RuntimeError(f"Run failed ({code}): {run_spec['id']}\n{tail}")
                record = log_summary(run_spec, i, len(specs))
                if is_replacement:
                    record["replaces"] = spec["id"]
                records.append(record)
                with (session / "progress.jsonl").open("a") as progress:
                    progress.write(json.dumps(record) + "\n")
                say(f"DONE {i}/{len(specs)} {run_spec['id']}: {record['status']}; "
                    f"valid={record['execution_valid']}; "
                    f"missing={record['missing_at_cutoff']}; "
                    f"flags={record['review_flags']}")
                if not record["execution_valid"]:
                    raise RuntimeError(f"Execution invalid: {run_spec['id']}")
                if any(record["thermal_throttle_deltas"].values()) or stop_after:
                    raise RuntimeError(f"Host guard flagged {run_spec['id']}: {stop_after}")
            if outcome == "aborted":
                outcome = "completed"
            say(f"Session finished; {len(records)} runs executed; report={session/'summary.json'}")
        except Exception as exc:
            error = str(exc)
            raise
        finally:
            keepalive_stop.set()
            if active_process is not None and active_process.poll() is None:
                say(f"Waiting for active run {active_run_id} to finish before stack cleanup")
                while active_process.poll() is None:
                    try:
                        active_process.wait(timeout=60)
                    except subprocess.TimeoutExpired:
                        say(f"Still waiting for {active_run_id}; its data are being preserved")
            stop_stacks()
            if changed_affinity and affinity_path.exists():
                try:
                    restore_affinity(affinity_path)
                except Exception as exc:
                    say(f"WARNING: affinity restoration failed: {exc}")
            if changed_turbo:
                try:
                    write_turbo(original_turbo)
                    say(f"Restored original no_turbo={original_turbo}")
                except Exception as exc:
                    say(f"WARNING: Turbo restoration failed: {exc}; run: "
                        f"echo {original_turbo} | sudo tee {TURBO_PATH}")
            (session / "summary.json").write_text(json.dumps({
                "started_at": started_at,
                "ended_at": datetime.now(timezone.utc).isoformat(),
                "outcome": outcome, "error": error,
                "completed_this_session": len(records),
                "total_specs": len(specs), "records": records}, indent=2) + "\n")
            say(f"Session artifacts: {session}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="show plan; no host changes")
    parser.add_argument("--check-only", action="store_true", help="validate lock and host; no host changes")
    parser.add_argument("--max-hours", type=float, default=36)
    parser.add_argument("--heartbeat-seconds", type=int, default=30)
    parser.add_argument("--idle-seconds", type=int, default=15)
    parser.add_argument("--only-index", type=int, help="execute only this numbered cell")
    parser.add_argument("--set", choices=("confirmatory", "factorial", "alerts"), default="confirmatory")
    parser.add_argument("--inter-run-seconds", type=int, default=90,
                        help="time to inspect/report a result before the next run")
    options = parser.parse_args()
    if options.max_hours <= 0 or options.heartbeat_seconds < 10 or \
            options.idle_seconds < 5 or options.inter_run_seconds < 0:
        parser.error("positive max-hours, heartbeat >=10 s, idle >=5 s, and nonnegative inter-run delay required")
    try:
        execute(options)
    except Exception as exc:
        say(f"STOPPED: {exc}")
        sys.exit(1)
