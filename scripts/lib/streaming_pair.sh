# The paired measurement of one round: the current build and the pinned
# reference build, measured next to each other against the same origin. The
# plan in scripts/lib/streaming_pair.py owns the round's identity and the
# order of its members; this library applies it, so the lane and the
# committed fixture measure the same pairing.

QPX_STREAMING_PAIR_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

streaming_pair_plan() {
  local round="$1"
  local reference_available="${2:-true}"
  python3 "$QPX_STREAMING_PAIR_ROOT/scripts/lib/streaming_pair.py" \
    "$round" "$reference_available"
}

# Every member of the pair is measured in the plan's order and carries the
# plan's round, so the report can pair the members of a round afterwards.
run_qpxd_pair() {
  local read_mode="$1"
  local plan_line round member
  local -a fields=()
  plan_line="$(streaming_pair_plan "${CURRENT_SAMPLE_ROUND:-0}" "${PREVIOUS_REFERENCE_AVAILABLE:-false}")"
  read -r -a fields <<<"$plan_line"
  if [ "${#fields[@]}" -lt 1 ]; then
    echo "the round plan is empty" >&2
    exit 1
  fi
  round="${fields[0]}"
  for member in "${fields[@]:1}"; do
    run_pair_member "$member" "$round" "$read_mode"
  done
}

run_pair_member() {
  local member="$1"
  local round="$2"
  local read_mode="$3"
  case "$member" in
    qpxd)
      run_one "qpxd" "$QPX_PORT" "$QPXD_PID" "$read_mode" "$round"
      ;;
    qpxd-previous)
      run_one "qpxd-previous" "$PREVIOUS_PORT" "$PREVIOUS_QPXD_PID" "$read_mode" "$round"
      ;;
    *)
      echo "unknown pair member: ${member}" >&2
      exit 1
      ;;
  esac
}
