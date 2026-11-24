#!/usr/bin/env bash
#
# run_one.sh -- run ONE self-contained scenario end to end: load, compile root
# node and attacker, run headless, and write the trace and the metrics CSV.
#
# Usage (from examples/rpl-security):
#   bash tools/run_one.sh <scenario.csc> [name] [attacker_id]
# Examples:
#   bash tools/run_one.sh sim_single.csc
#   bash tools/run_one.sh attack_blackhole.csc blackhole 6
#
# Writes:
#   results/<name>_log.txt   full trace
#   results/<name>.csv       one header + one metrics row
# and prints the full report.
set -u

HERE="$(cd "$(dirname "$0")/.." && pwd)"
CONTIKI="${CONTIKI:-$(cd "$HERE/../.." && pwd)}"
COOJA="$CONTIKI/tools/cooja"
RESULTS="$HERE/results"
TESTLOG="$COOJA/COOJA.testlog"

csc="${1:?usage: run_one.sh <scenario.csc> [name] [attacker_id]}"
name="${2:-$(basename "$csc" .csc)}"
atk="${3:-6}"
mkdir -p "$RESULTS"

# scenario path may be given bare (in this folder) or as a full path; make it
# absolute, because we launch Cooja from a different directory below.
[ -f "$csc" ] || csc="$HERE/$csc"
if [ ! -f "$csc" ]; then echo "ERROR: scenario not found: $csc"; exit 1; fi
csc="$(cd "$(dirname "$csc")" && pwd)/$(basename "$csc")"

echo "building attacker fresh and running $name headless..."
( cd "$HERE/attacker" && make clean TARGET=cooja ) > /dev/null 2>&1
rm -f "$TESTLOG"
( cd "$COOJA" && ./gradlew run --args="--no-gui $csc" ) \
    > "$RESULTS/${name}_cooja.out" 2>&1

if [ ! -s "$TESTLOG" ]; then
  echo "ERROR: no trace produced. See $RESULTS/${name}_cooja.out"
  exit 1
fi

cp "$TESTLOG" "$RESULTS/${name}_log.txt"
echo "scenario,attacker,captured,capture_pct,pdr_pct,rtt_mean_ms,lat_mean_ms,atk_dio_tx,total_ctrl" \
    > "$RESULTS/${name}.csv"
python3 "$HERE/tools/analyze_log.py" "$RESULTS/${name}_log.txt" \
    --attacker "$atk" --csv "$name" >> "$RESULTS/${name}.csv"

echo
python3 "$HERE/tools/analyze_log.py" "$RESULTS/${name}_log.txt" --attacker "$atk"
echo
echo "saved: results/${name}_log.txt and results/${name}.csv"
