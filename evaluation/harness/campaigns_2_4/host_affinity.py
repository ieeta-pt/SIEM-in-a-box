"""Temporarily keep same-user host tasks off benchmark CPUs.

Saves per-thread affinity and Linux start time before applying the mask.
Restore skips exited or reused TIDs. Containers and root-owned tasks are not
modified. This is an operational aid, not part of a run's measured data.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from pathlib import Path


def start_ticks(tid: int) -> int:
    stat = Path(f"/proc/{tid}/stat").read_text()
    return int(stat.rsplit(") ", 1)[1].split()[19])


def own_threads():
    uid = os.getuid()
    for proc in Path("/proc").iterdir():
        if not proc.name.isdecimal():
            continue
        try:
            status = (proc / "status").read_text()
            owner = next(line for line in status.splitlines() if line.startswith("Uid:"))
            if int(owner.split()[1]) != uid:
                continue
            for task in (proc / "task").iterdir():
                if task.name.isdecimal():
                    yield int(task.name)
        except (FileNotFoundError, PermissionError, StopIteration):
            continue


def sudo_set_affinity(tid: int, cpus: set[int]) -> None:
    """Use the existing sudo ticket for a same-user task that rejects setaffinity."""
    cpu_list = ",".join(map(str, sorted(cpus)))
    proc = subprocess.run(["sudo", "-n", "taskset", "-pc", cpu_list, str(tid)],
                          capture_output=True, text=True, timeout=20)
    if proc.returncode:
        raise RuntimeError(f"sudo taskset failed for TID {tid}: {proc.stderr.strip()}")


def apply(path: Path, cpus: set[int]) -> bool:
    if path.exists():
        raise FileExistsError(f"Snapshot already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    records = []
    for tid in own_threads():
        try:
            records.append({"tid": tid, "start_ticks": start_ticks(tid),
                            "affinity": sorted(os.sched_getaffinity(tid))})
        except (OSError, ValueError):
            continue
    snapshot = {"created_ns": time.time_ns(), "target_cpus": sorted(cpus),
                "threads": records}
    path.write_text(json.dumps(snapshot, indent=2) + "\n")
    changed = 0
    privileged_changed = 0
    skipped = 0
    failures = []
    sudo_ready = False
    for item in records:
        try:
            if start_ticks(item["tid"]) != item["start_ticks"]:
                skipped += 1
                continue
            try:
                os.sched_setaffinity(item["tid"], cpus)
                changed += 1
            except PermissionError:
                if not sudo_ready:
                    subprocess.run(["sudo", "-v"], check=True)
                    sudo_ready = True
                # Do not target a newly reused TID with elevated privileges.
                if start_ticks(item["tid"]) != item["start_ticks"]:
                    skipped += 1
                    continue
                sudo_set_affinity(item["tid"], cpus)
                privileged_changed += 1
        except (FileNotFoundError, ProcessLookupError):
            skipped += 1
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            failures.append(f"{item['tid']}: {exc}")
    print(json.dumps({"snapshot": str(path), "recorded": len(records),
                      "changed": changed, "privileged_changed": privileged_changed,
                      "skipped": skipped, "failed": len(failures),
                      "failure_details": failures[:10], "target_cpus": sorted(cpus)}))
    if failures:
        raise RuntimeError("Could not isolate all recorded user threads: " +
                           "; ".join(failures[:10]))
    return privileged_changed > 0


def restore(path: Path) -> None:
    snapshot = json.loads(path.read_text())
    restored = 0
    privileged_restored = 0
    already_restored = 0
    skipped = 0
    failures = []
    original = {(item["tid"], item["start_ticks"]) for item in snapshot["threads"]}
    for item in snapshot["threads"]:
        try:
            if start_ticks(item["tid"]) != item["start_ticks"]:
                skipped += 1
                continue
            original_mask = set(item["affinity"])
            if os.sched_getaffinity(item["tid"]) == original_mask:
                already_restored += 1
                continue
            try:
                os.sched_setaffinity(item["tid"], original_mask)
                restored += 1
            except PermissionError:
                sudo_set_affinity(item["tid"], original_mask)
                privileged_restored += 1
        except (FileNotFoundError, ProcessLookupError):
            skipped += 1
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            failures.append(f"{item['tid']}: {exc}")
    # Threads born while their parent was temporarily pinned inherit the
    # campaign mask. Release only those still carrying that exact mask.
    inherited_released = 0
    privileged_released = 0
    full = set(range(os.cpu_count() or 0))
    target = set(snapshot["target_cpus"])
    for tid in own_threads():
        try:
            if (tid, start_ticks(tid)) not in original and \
                    os.sched_getaffinity(tid) == target:
                try:
                    os.sched_setaffinity(tid, full)
                    inherited_released += 1
                except PermissionError:
                    sudo_set_affinity(tid, full)
                    privileged_released += 1
        except (FileNotFoundError, ProcessLookupError):
            continue
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            failures.append(f"inherited {tid}: {exc}")
    print(json.dumps({"snapshot": str(path), "restored": restored,
                      "privileged_restored": privileged_restored,
                      "already_restored": already_restored, "skipped": skipped,
                      "failed": len(failures), "failure_details": failures[:10],
                      "inherited_released": inherited_released,
                      "privileged_released": privileged_released}))
    if failures:
        raise RuntimeError("Could not restore all recorded user threads: " +
                           "; ".join(failures[:10]))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("apply", "restore"))
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--cpus", default="8-11")
    args = parser.parse_args()
    if args.action == "apply":
        lo, hi = map(int, args.cpus.split("-"))
        apply(args.snapshot, set(range(lo, hi + 1)))
    else:
        restore(args.snapshot)
