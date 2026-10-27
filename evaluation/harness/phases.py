"""Phase table (numbers match the plan table) with progress and time left."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PHASES = {
    1: ("outage", "Outages: ES/indexer pause 1/5/10 min (A, B, B-disk, Wazuh)"),
    2: ("flood", "Flooding: attack events under a log flood"),
    3: ("ramp", "Throughput ramps 1k-8k EPS (A, B, B-disk)"),
    4: ("kafka-kill", "Kafka crash (SIGKILL)"),
    5: ("latency,latency-defaults", "Latency (10 min) + default-settings runs"),
    6: ("grid", "Partitions x workers grid (A)"),
    7: ("ramp-udp", "UDP ramp (A and Wazuh)"),
    8: ("outage-file", "File-source outages"),
    9: ("outage-load", "Outage at 2,000 EPS"),
    10: ("storage", "Storage growth"),
}
# measured minutes per run (from today's calibration), by phase
PER_RUN = {"outage": None, "flood": 6.5, "ramp": None, "kafka-kill": None, "latency": 11.5,
           "latency-defaults": 6.5, "grid": 8, "ramp-udp": 5, "outage-file": 14, "outage-load": 15,
           "storage": 35}


def minutes(spec):
    ph = spec["phase"]
    if ph in ("outage", "kafka-kill"):
        return {60: 5, 300: 8.5, 600: 13.5}[spec["fault"]["dur"]]
    if ph == "ramp":
        return 8 if spec.get("expect_overload") else 4.2
    return PER_RUN[ph]


def main():
    specs = json.load(open(os.path.join(HERE, "campaign.json")))
    if len(sys.argv) > 1:
        n = int(sys.argv[1])
        print(PHASES[n][0])
        return
    print(f"{'#':>2}  {'phase':40s} {'done':>9}  {'time left':>9}")
    tot = 0
    for n, (names, desc) in PHASES.items():
        sel = [s for s in specs if s["phase"] in names.split(",")]
        done = sum(os.path.exists(os.path.join(HERE, "results", s["id"].lower(), "result.json")) for s in sel)
        left = sum(minutes(s) for s in sel
                   if not os.path.exists(os.path.join(HERE, "results", s["id"].lower(), "result.json")))
        tot += left
        print(f"{n:>2}  {desc:40.40s} {done:>3}/{len(sel):<4}  {left / 60:6.1f} h")
    print(f"    {'TOTAL':40s} {'':9}  {tot / 60:6.1f} h")


if __name__ == "__main__":
    main()
