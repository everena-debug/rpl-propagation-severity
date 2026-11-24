#!/usr/bin/env bash
#
# run_matrix2.sh -- run the manifest-driven experiment matrix headless.
#
# Reads scenarios_manifest.csv (from gen_matrix2.py), runs each scenario, and
# passes that scenario's attacker id to the analyzer. The attacker firmware is
# rebuilt only when the attack changes, so the sweep stays fast. Rows are
# processed in manifest order; gen_matrix2 groups by attack.
#
# Usage (from examples/rpl-security):
#   python3 tools/gen_matrix2.py
#   bash    tools/run_matrix2.sh
set -u

HERE="$(cd "$(dirname "$0")/.." && pwd)"
CONTIKI="${CONTIKI:-$(cd "$HERE/../.." && pwd)}"
COOJA="$CONTIKI/tools/cooja"
RESULTS="$HERE/results"
TESTLOG="$COOJA/COOJA.testlog"
MAN="$HERE/scenarios_manifest.csv"

[ -f "$MAN" ] || { echo "no scenarios_manifest.csv; run python3 tools/gen_matrix2.py"; exit 1; }
mkdir -p "$RESULTS"
SUMMARY="$RESULTS/summary.csv"
PROP="$RESULTS/prop_summary.csv"
echo "scenario,attacker,captured,capture_pct,pdr_pct,rtt_mean_ms,lat_mean_ms,atk_dio_tx,total_ctrl" > "$SUMMARY"
echo "scenario,AR,T50_s,T90_s,depth,DDR,RIR,PSR,persistence_s" > "$PROP"

prev_attack=""; count=0; ok=0
# Read the manifest from a file (not a pipe) so the loop runs in this shell, and
# feed Cooja </dev/null so gradlew does not consume the manifest from stdin.
while IFS=, read -r name attack nodes placement loss seed atkid; do
  [ -n "$name" ] || continue
  count=$((count+1))
  if [ "$attack" != "$prev_attack" ]; then
    echo "--- attacker build for: $attack ---"
    ( cd "$HERE/attacker" && make clean TARGET=cooja ) > /dev/null 2>&1
    prev_attack="$attack"
  fi
  rm -f "$TESTLOG"
  ( cd "$COOJA" && ./gradlew run --args="--no-gui $HERE/${name}.csc" < /dev/null ) \
      > "$RESULTS/${name}_cooja.out" 2>&1
  if [ ! -s "$TESTLOG" ]; then
    echo "  [$count] WARNING: no trace for $name"
    continue
  fi
  cp "$TESTLOG" "$RESULTS/${name}_log.txt"
  python3 "$HERE/tools/analyze_log.py" "$RESULTS/${name}_log.txt" \
      --attacker "${atkid:-0}" --csv "$name" >> "$SUMMARY" 2>/dev/null
  python3 "$HERE/tools/propagation.py" "$RESULTS/${name}_log.txt" \
      --attacker "${atkid:-0}" --csv "$name" >> "$PROP" 2>/dev/null
  rm -f "$RESULTS/${name}_cooja.out"
  ok=$((ok+1))
  echo "  [$count] $name (attacker=$atkid) ok"
done < <(tail -n +2 "$MAN")

echo
echo "=== done -> $SUMMARY ==="
echo "aggregate with: python3 tools/aggregate2.py results/summary.csv scenarios_manifest.csv"
