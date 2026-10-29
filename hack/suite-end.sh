# Sourced by the suites that count checks (pass, fail): how a run ends, so that a run which
# stopped early or left sections out never looks like a full one.
#   skip "what was left out and why"   before a section the run does not make
#   suite_summary                       last line of the script: the counts, the skipped sections;
#                                       fails on a failed check or a skipped section (ALLOW_SKIPPED=1
#                                       accepts the skipped ones: a fleet that cannot run them)
#   rc=$?; ...; suite_early_end "$rc"   last line of the EXIT trap: a run that never reached
#                                       suite_summary says so, with a status that is not 0
SKIPPED=
SUITE_DONE=
skip() { SKIPPED="${SKIPPED:+$SKIPPED; }$1"; echo "  skipped: $1"; }
suite_summary() {
  SUITE_DONE=1
  echo
  echo "passed $pass, failed $fail"
  [ -z "$SKIPPED" ] || echo "NOT A FULL RUN, skipped: $SKIPPED"
  [ "$fail" = 0 ] && { [ -z "$SKIPPED" ] || [ -n "${ALLOW_SKIPPED:-}" ]; }
}
suite_early_end() {
  [ -n "$SUITE_DONE" ] && return 0
  echo "ENDED EARLY after $pass ok, $fail failed: the run stopped before its last check"
  exit $(( ${1:-0} != 0 ? $1 : 1 ))
}
