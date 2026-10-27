"""Read-only host and pipeline telemetry for future revision runs.

All records include both wall and monotonic clocks. UDP kernel counters are
read from the receiving container's network namespace, not the host's.
Failures are saved in the JSONL record instead of silently becoming zero.
"""

from __future__ import annotations

import json
import subprocess
import threading
import time
from pathlib import Path

import requests


def udp_counters(snmp: str) -> dict[str, int]:
    lines = [line.split() for line in snmp.splitlines() if line.startswith("Udp:")]
    if len(lines) < 2 or len(lines[0]) != len(lines[1]):
        raise ValueError("UDP /proc/net/snmp header/value pair missing")
    return {key: int(value) for key, value in zip(lines[0][1:], lines[1][1:])
            if key in {"InDatagrams", "InErrors", "RcvbufErrors", "SndbufErrors", "NoPorts"}}


def read_text(path: Path) -> str | None:
    try:
        return path.read_text().strip()
    except OSError:
        return None


def host_snapshot() -> dict:
    cpus = {}
    throttles = {}
    for cpu in range(8):
        root = Path(f"/sys/devices/system/cpu/cpu{cpu}")
        value = read_text(root / "cpufreq/scaling_cur_freq")
        cpus[str(cpu)] = int(value) if value and value.isdigit() else None
        value = read_text(root / "thermal_throttle/core_throttle_count")
        throttles[str(cpu)] = int(value) if value and value.isdigit() else None
    thermal = {}
    for zone in Path("/sys/class/thermal").glob("thermal_zone*"):
        if read_text(zone / "type") == "x86_pkg_temp":
            raw = read_text(zone / "temp")
            thermal[zone.name] = int(raw) / 1000 if raw and raw.isdigit() else None
    ac = [read_text(path) for path in Path("/sys/class/power_supply").glob("AC*/online")]
    return {
        "cpu_khz": cpus, "core_throttle_count": throttles,
        "package_temp_c": thermal,
        "no_turbo": read_text(Path("/sys/devices/system/cpu/intel_pstate/no_turbo")),
        "ac_online": ac,
        "io_pressure": read_text(Path("/proc/pressure/io")),
    }


def container_udp(name: str) -> dict:
    proc = subprocess.run(["docker", "exec", name, "cat", "/proc/net/snmp"],
                          capture_output=True, text=True, timeout=8)
    if proc.returncode:
        raise RuntimeError(proc.stderr.strip() or f"docker exec {name} failed")
    return udp_counters(proc.stdout)


def filebeat_snapshot(ip: str) -> dict:
    stats = requests.get(f"http://{ip}:5066/stats", timeout=4).json()
    inputs = requests.get(f"http://{ip}:5066/inputs/", timeout=4).json()
    libbeat = stats.get("libbeat", {})
    return {
        "queue": libbeat.get("pipeline", {}).get("queue", {}),
        "pipeline_events": libbeat.get("pipeline", {}).get("events", {}),
        "output_events": libbeat.get("output", {}).get("events", {}),
        "inputs": [{key: row.get(key) for key in
                    ("id", "received_events_total", "system_packet_drops",
                     "receive_queue_length", "events_processed_total") if key in row}
                   for row in inputs],
    }


def logstash_snapshot() -> dict:
    stats = requests.get("http://localhost:9600/_node/stats/pipelines", timeout=4).json()
    return {name: {"events": value.get("events", {}), "queue": value.get("queue", {})}
            for name, value in stats.get("pipelines", {}).items()}


class Telemetry(threading.Thread):
    def __init__(self, path: Path, variant: str, collectors: dict[str, str], period=5):
        super().__init__(daemon=True)
        self.path, self.variant, self.collectors, self.period = path, variant, collectors, period
        self.stop = threading.Event()

    def sample(self) -> dict:
        row = {"wall_ns": time.time_ns(), "monotonic_ns": time.monotonic_ns(),
               "host": host_snapshot(), "collectors": {}}
        for source, ip in self.collectors.items():
            try:
                row["collectors"][source] = {
                    "udp_namespace": container_udp(f"bench-fb-{source}"),
                    "filebeat": filebeat_snapshot(ip),
                }
            except Exception as exc:
                row["collectors"][source] = {"error": str(exc)}
        if self.variant == "C":
            try:
                row["wazuh_udp_namespace"] = container_udp("bench-wazuh-manager")
            except Exception as exc:
                row["wazuh_udp_namespace"] = {"error": str(exc)}
        if self.variant in {"A-sep", "A-shared", "A-topics", "A-pipelines"}:
            try:
                row["logstash"] = logstash_snapshot()
            except Exception as exc:
                row["logstash"] = {"error": str(exc)}
        return row

    def run(self) -> None:
        with self.path.open("w") as handle:
            while not self.stop.is_set():
                started = time.monotonic()
                try:
                    record = self.sample()
                except Exception as exc:
                    record = {"wall_ns": time.time_ns(),
                              "monotonic_ns": time.monotonic_ns(),
                              "error": repr(exc)}
                handle.write(json.dumps(record, separators=(",", ":")) + "\n")
                handle.flush()
                self.stop.wait(max(0, self.period - (time.monotonic() - started)))
