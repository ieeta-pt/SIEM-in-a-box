#!/bin/bash
# Run ONE phase of the measurement campaign (numbers from the plan table).
#   ./session.sh list     # show phases, progress and time left
#   ./session.sh 3        # run phase 3 (resumes where it stopped)
cd "$(dirname "$0")"
if [ -z "$1" ] || [ "$1" = "list" ]; then .venv/bin/python phases.py; exit 0; fi
PH=$(.venv/bin/python phases.py "$1") || { echo "unknown phase: $1"; exit 1; }
if pgrep -f "run\.py campaign" >/dev/null; then echo "a session is already running"; exit 1; fi
# CPU speed must be fixed for reproducible measurements: Turbo Boost OFF
if [ "$(cat /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null)" != "1" ]; then
  echo "Turbo Boost is ON. Turn it off first (needed after every reboot):"
  echo "  echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo"
  exit 1
fi
if [ "$(cat /sys/class/power_supply/AC*/online 2>/dev/null | head -1)" != "1" ]; then
  echo "The laptop is on battery. Plug in the charger first."; exit 1
fi
# keep desktop processes off the SUT cores (0-7)
for p in $(ps -u "$USER" -o pid=); do grep -q docker /proc/$p/cgroup 2>/dev/null || taskset -a -cp 8-19 $p >/dev/null 2>&1; done
pgrep -f hostlog.sh >/dev/null || (nohup setsid ./hostlog.sh results/host.csv >/dev/null 2>&1 </dev/null &)
rm -f results/STOP          # a stop request belongs to the previous session only
echo "$(date +%T) session start: phase $1 ($PH)" >> results/campaign.log
nohup setsid systemd-inhibit --what=sleep:idle:handle-lid-switch --who=siem-bench \
  --why="measurement campaign" --mode=block \
  .venv/bin/python run.py campaign campaign.json --phases "$PH" >> results/campaign.log 2>&1 < /dev/null &
echo "phase $1 ($PH) started. Progress: tail -f results/campaign.log  |  stop: ./stop.sh"
