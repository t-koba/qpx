# The paired measurement of one round: the current build and the pinned
# reference build, measured next to each other against the same origin. The
# plan in scripts/lib/streaming_pair.py owns the round's identity and the
# order inside the pair; this library holds that plan for the round being
# measured, so the pair's members and the records the lane writes all carry
# the same round.

QPX_STREAMING_PAIR_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# The round being measured: its number and the order of the pair's members.
STREAMING_PAIR_ROUND=""
STREAMING_PAIR_MEMBERS=""

streaming_pair_plan() {
  local round="$1"
  local reference_available="${2:-true}"
  python3 "$QPX_STREAMING_PAIR_ROOT/scripts/lib/streaming_pair.py" \
    "$round" "$reference_available"
}

# The round has to be a begun one: a lane that measures without a plan has
# no round to carry, and says so instead of stamping one of its own.
streaming_require_round() {
  if ! [[ "${STREAMING_PAIR_ROUND:-}" =~ ^[1-9][0-9]*$ ]]; then
    echo "no round was begun" >&2
    exit 1
  fi
}

# Begins a round. The plan's round and its members become the round the lane
# measures and the round the lane's records carry.
streaming_begin_round() {
  local round="$1"
  local plan_line
  local -a fields=()
  plan_line="$(streaming_pair_plan "$round" "${PREVIOUS_REFERENCE_AVAILABLE:-false}")"
  read -r -a fields <<<"$plan_line"
  if [ "${#fields[@]}" -lt 1 ]; then
    echo "the round plan is empty" >&2
    exit 1
  fi
  STREAMING_PAIR_ROUND="${fields[0]}"
  STREAMING_PAIR_MEMBERS="${fields[*]:1}"
  export STREAMING_PAIR_ROUND STREAMING_PAIR_MEMBERS
}

# Every member of the pair is measured in the plan's order, and the members
# carry the plan's round, so the report can pair them afterwards.
run_qpxd_pair() {
  local read_mode="$1"
  local member
  streaming_require_round
  for member in $STREAMING_PAIR_MEMBERS; do
    run_pair_member "$member" "$read_mode"
  done
}

run_pair_member() {
  local member="$1"
  local read_mode="$2"
  case "$member" in
    qpxd)
      run_one "qpxd" "$QPX_PORT" "$QPXD_PID" "$read_mode"
      ;;
    qpxd-previous)
      run_one "qpxd-previous" "$PREVIOUS_PORT" "$PREVIOUS_QPXD_PID" "$read_mode"
      ;;
    *)
      echo "unknown pair member: ${member}" >&2
      exit 1
      ;;
  esac
}

# Writes one proxy's measurement of the current round. The round is the
# plan's round, so the record carries the round the report pairs on and the
# lane has no way to state a round of its own.
streaming_write_round_record() {
  local out_json="$1"
  local sample="$2"
  local stream_bytes="$3"
  local chunk_bytes="$4"
  local attempts="$5"
  local valid_samples="$6"
  local commit="$7"
  streaming_require_round
  python3 "$QPX_STREAMING_PAIR_ROOT/scripts/lib/streaming_records.py" \
    "$out_json" "$sample" "$stream_bytes" "$chunk_bytes" "$attempts" \
    "$valid_samples" "$commit" "$STREAMING_PAIR_ROUND"
}
