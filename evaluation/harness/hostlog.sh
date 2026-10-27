#!/bin/bash
# Host-condition log (30 s): CPU package temp, mean SUT-core MHz (CPUs 0-7),
# cumulative package/core throttle counters, IO pressure. Joined to runs
# afterwards to flag thermally throttled measurement windows.
out=${1:-results/host.csv}
[ -f "$out" ] || echo "t,pkg_temp_c,sut_mhz,pkg_throttle,core_throttle,io_some_avg10,no_turbo,ac" > "$out"
while true; do
  t=$(date +%s)
  temp=$(for z in /sys/class/thermal/thermal_zone*; do [ "$(cat $z/type)" = x86_pkg_temp ] && echo $(( $(cat $z/temp)/1000 )); done | head -1)
  mhz=$(awk '/MHz/{n++; if(n<=8){s+=$4}} END{printf "%d", s/8}' /proc/cpuinfo)
  pt=$(cat /sys/devices/system/cpu/cpu0/thermal_throttle/package_throttle_count)
  ct=$(cat /sys/devices/system/cpu/cpu*/thermal_throttle/core_throttle_count | awk '{s+=$1} END{print s}')
  io=$(awk '/some/{split($2,a,"="); print a[2]}' /proc/pressure/io)
  nt=$(cat /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null)
  ac=$(cat /sys/class/power_supply/AC*/online 2>/dev/null | head -1)
  echo "$t,$temp,$mhz,$pt,$ct,$io,$nt,$ac" >> "$out"
  sleep 30
done
