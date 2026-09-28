#!/bin/sh
# Measure the peak resident memory and wall time of a command, without GNU time.
#
#   scripts/footprint.sh <command> [args...]
set -eu

if [ "$#" -lt 1 ]; then
    echo "usage: $0 <command> [args...]" >&2
    exit 2
fi

"$@" >/dev/null 2>&1 &
pid=$!

start=$(date +%s%N 2>/dev/null || date +%s)
peak=0
while kill -0 "$pid" 2>/dev/null; do
    rss=$(awk '/^VmRSS:/ {print $2}' "/proc/$pid/status" 2>/dev/null || echo 0)
    [ -n "${rss:-}" ] || rss=0
    [ "$rss" -gt "$peak" ] && peak=$rss
    sleep 0.05
done
set +e
wait "$pid"
status=$?
set -e
end=$(date +%s%N 2>/dev/null || date +%s)

echo "  command   : $*"
echo "  exit      : $status"
echo "  peak RSS  : $((peak / 1024)) MB"
if [ "$start" -gt 1000000000000 ]; then
    echo "  wall time : $(( (end - start) / 1000000 )) ms"
else
    echo "  wall time : $((end - start)) s"
fi
