#!/usr/bin/env bash
#
# mayhem/test.sh — RUN Tcl's own tcltest suite (tests/*.test) with the `tcltest` that mayhem/build.sh
# built with normal flags in mayhem/build-test. The files cover the code the fuzz targets reach.
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

TCLTEST="$SRC/mayhem/build-test/tcltest"
if [ ! -x "$TCLTEST" ]; then
  echo "test.sh: $TCLTEST missing — mayhem/build.sh must build it" >&2
  emit_ctrf "tcltest" 0 1 0
  exit 1
fi
# zipfs.test is left out: its `zipfs list` cases expect the Tcl library zip mounted, which only an
# installed/zip-attached tclsh has, not the build-tree tcltest.
FILES="regexp.test regexpComp.test reg.test binary.test format.test scan.test encoding.test
utf.test string.test stringObj.test list.test listObj.test lseq.test dict.test expr.test expr-old.test
parse.test parseExpr.test zlib.test clock.test util.test obj.test"
LOG=$(mktemp)
# all.tcl prints: "all.tcl:<TAB>Total<TAB>N<TAB>Passed<TAB>P<TAB>Skipped<TAB>S<TAB>Failed<TAB>F"
(cd "$SRC/mayhem/build-test" && TCL_LIBRARY="$SRC/library" "$TCLTEST" "$SRC/tests/all.tcl" \
    -file "$(echo $FILES)" -singleproc 1 -tmpdir "$(mktemp -d)") 2>&1 | tee "$LOG"
line=$(grep -E '^all\.tcl:[[:space:]]+Total' "$LOG" | tail -1 || true)
rm -f "$LOG"
if [ -z "$line" ]; then
  echo "test.sh: no tcltest summary line — the suite did not run" >&2
  emit_ctrf "tcltest" 0 1 0
  exit 1
fi
read -r _ _ total _ passed _ skipped _ failed <<<"$line"
if [ "$total" -lt 1000 ]; then
  echo "test.sh: only $total tests ran (expected thousands)" >&2
  failed=$((failed + 1))
fi
emit_ctrf "tcltest" "$passed" "$failed" "$skipped"
