#!/usr/bin/env bash
#
# run_matrix.sh -- run the whole Objective 1 scenario matrix headless and
# collect every run's trace and metrics.
#
# For each scenario .csc it: runs Cooja headless (no window), copies the trace
# that Cooja writes to tools/cooja/COOJA.testlog into results/<name>_log.txt,
# and runs the analyzer to append one row to results/summary.csv.
#
# Usage (from examples/rpl-security):
#   bash tools/run_matrix.sh
#
# Environment:
#   CONTIKI   path to contiki-ng (default: three levels up)
#   SCENARIOS space-separated list of .csc basenames to run
#             (default: every *.csc that carries a ScriptRunner timeout)
set -u

HERE="$(cd "$(dirname "$0")/.." && pwd)"          # examples/rpl-security
CONTIKI="${CONTIKI:-$(cd "$HERE/../.." && pwd)}"   # contiki-ng
COOJA="$CONTIKI/tools/cooja"
RESULTS="$HERE/results"
TESTLOG="$COOJA/COOJA.testlog"
ATTACKER="${ATTACKER:-6}"

mkdir -p "$RESULTS"
SUMMARY="$RESULTS/summary.csv"

# Scenarios: any headless (*-hl.csc) files, else all attack_*/baseline*.csc that
# have a TIMEOUT script. Override with SCENARIOS="a.csc b.csc".
if [ -z "${SCENARIOS:-}" ]; then
  SCENARIOS="$(cd "$HERE" && ls matrix_*.csc 2>/dev/null | tr '\n' ' ')"
fi

if [ -z "$SCENARIOS" ]; then
  echo "No headless scenarios (with a TIMEOUT script) found in $HERE."
  echo "Generate them with: python3 tools/gen_matrix_cscs.py"
  exit 1
fi

echo "scenario,attacker,captured,capture_pct,pdr_pct,rtt_mean_ms,lat_mean_ms,atk_dio_tx,total_ctrl" > "$SUMMARY"

for csc in $SCENARIOS; do
  name="$(basename "$csc" .csc)"
  echo "=== running $name ==="
  rm -f "$TESTLOG"
  # Force a fresh attacker build so each scenario gets its own ATTACK type
  # (the object files are cached and would otherwise reuse the previous attack).
  ( cd "$HERE/attacker" && make clean TARGET=cooja ) > /dev/null 2>&1
  ( cd "$COOJA" && ./gradlew run --args="--no-gui $HERE/$csc" ) \
      > "$RESULTS/${name}_cooja.out" 2>&1
  if [ ! -s "$TESTLOG" ]; then
    echo "  WARNING: no trace produced for $name (see ${name}_cooja.out)"
    continue
  fi
  cp "$TESTLOG" "$RESULTS/${name}_log.txt"
  # full human-readable report
  python3 "$HERE/tools/analyze_log.py" "$RESULTS/${name}_log.txt" \
      --attacker "$ATTACKER" > "$RESULTS/${name}_report.txt" 2>&1
  # one CSV row for the summary
  python3 "$HERE/tools/analyze_log.py" "$RESULTS/${name}_log.txt" \
      --attacker "$ATTACKER" --csv "$name" >> "$SUMMARY" 2>/dev/null
  echo "  -> results/${name}_log.txt, ${name}_report.txt"
done

echo
echo "=== summary (results/summary.csv) ==="
column -s, -t "$SUMMARY" 2>/dev/null || cat "$SUMMARY"
