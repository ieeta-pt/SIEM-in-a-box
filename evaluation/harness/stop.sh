#!/bin/bash
# Stop the campaign. Default: finish the current run, then stop (clean).
#   ./stop.sh          # graceful: stop after the run in progress
#   ./stop.sh now      # immediate: abort the current run (it will be redone)
cd "$(dirname "$0")"
if [ "$1" != "now" ]; then
  touch results/STOP; echo "will stop after the current run finishes"; exit 0
fi
pkill -f "run.py campaign"; sleep 1
ps -eo pid,args | awk '/[g]en\.py --kind/{print $1}' | xargs -r kill
for c in bench-es bench-wazuh-indexer; do
  [ "$(docker inspect -f '{{.State.Paused}}' $c 2>/dev/null)" = "true" ] && docker unpause $c
done
[ "$(docker inspect -f '{{.State.Status}}' bench-kafka 2>/dev/null)" = "exited" ] && docker start bench-kafka >/dev/null
docker rm -f bench-fb-nginx bench-fb-auth >/dev/null 2>&1
for d in results/*/; do [ -f "$d/spec.json" ] && [ ! -f "$d/result.json" ] && rm -rf "$d"; done
echo "stopped; the interrupted run will be redone next session"
