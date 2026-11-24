#!/usr/bin/env bash
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
CONTIKI="${CONTIKI:-$(cd "$HERE/../.." && pwd)}"
COOJA="$CONTIKI/tools/cooja"
RESULTS="$HERE/results"
TESTLOG="$COOJA/COOJA.testlog"
MAN="$HERE/scenarios_extra.csv"
[ -f "$MAN" ] || { echo "no scenarios_extra.csv"; exit 1; }
SUMMARY="$RESULTS/summary.csv"; PROP="$RESULTS/prop_summary.csv"
prev_attack=""; count=0; ok=0
while IFS=, read -r name attack nodes placement loss seed atkid; do
  [ -n "$name" ] || continue
  count=$((count+1))
  if [ "$attack" != "$prev_attack" ]; then
    echo "--- attacker build for: $attack ---"
    ( cd "$HERE/attacker" && make clean TARGET=cooja ) > /dev/null 2>&1
    prev_attack="$attack"
  fi
  rm -f "$TESTLOG"
  ( cd "$COOJA" && ./gradlew run --args="--no-gui $HERE/${name}.csc" < /dev/null ) > "$RESULTS/${name}_cooja.out" 2>&1
  if [ ! -s "$TESTLOG" ]; then echo "  [$count] WARNING: no trace for $name"; continue; fi
  cp "$TESTLOG" "$RESULTS/${name}_log.txt"
  python3 "$HERE/tools/analyze_log.py" "$RESULTS/${name}_log.txt" --attacker "${atkid:-0}" --csv "$name" >> "$SUMMARY" 2>/dev/null
  python3 "$HERE/tools/propagation.py" "$RESULTS/${name}_log.txt" --attacker "${atkid:-0}" --csv "$name" >> "$PROP" 2>/dev/null
  rm -f "$RESULTS/${name}_cooja.out"
  ok=$((ok+1)); echo "  [$count] $name (attacker=$atkid) ok"
done < <(tail -n +2 "$MAN")
echo; echo "=== extra done: $ok/$count appended ==="
