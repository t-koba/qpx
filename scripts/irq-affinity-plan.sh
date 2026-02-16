#!/usr/bin/env bash
set -euo pipefail

iface=""
cpus=""
apply=0

usage() {
  cat <<USAGE
Usage: $0 --iface <name> --cpus <list> [--apply]

Examples:
  $0 --iface eth0 --cpus 0-15
  $0 --iface eno1 --cpus 0-7,16-23 --apply
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --iface)
      iface="${2:-}"
      shift 2
      ;;
    --cpus)
      cpus="${2:-}"
      shift 2
      ;;
    --apply)
      apply=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$iface" || -z "$cpus" ]]; then
  usage
  exit 1
fi

expand_cpu_list() {
  local input="$1"
  local out=()
  IFS=',' read -r -a parts <<< "$input"
  for part in "${parts[@]}"; do
    if [[ "$part" == *-* ]]; then
      local start="${part%-*}"
      local end="${part#*-}"
      if ! [[ "$start" =~ ^[0-9]+$ && "$end" =~ ^[0-9]+$ ]]; then
        echo "invalid cpu range: $part" >&2
        exit 1
      fi
      if (( end < start )); then
        echo "invalid cpu range: $part" >&2
        exit 1
      fi
      local i
      for ((i=start; i<=end; i++)); do
        out+=("$i")
      done
    else
      if ! [[ "$part" =~ ^[0-9]+$ ]]; then
        echo "invalid cpu: $part" >&2
        exit 1
      fi
      out+=("$part")
    fi
  done
  printf '%s\n' "${out[@]}"
}

mapfile -t cpu_array < <(expand_cpu_list "$cpus")
if (( ${#cpu_array[@]} == 0 )); then
  echo "no cpu resolved from --cpus" >&2
  exit 1
fi

mapfile -t irq_array < <(grep -E "^[[:space:]]*[0-9]+:.*${iface}([:-]|[[:space:]]|$)" /proc/interrupts \
  | awk -F: '{gsub(/[[:space:]]/, "", $1); print $1}')

if (( ${#irq_array[@]} == 0 )); then
  echo "no IRQ found for iface=$iface in /proc/interrupts" >&2
  exit 1
fi

if (( apply == 1 )) && (( EUID != 0 )); then
  echo "--apply requires root" >&2
  exit 1
fi

idx=0
for irq in "${irq_array[@]}"; do
  cpu="${cpu_array[$((idx % ${#cpu_array[@]}))]}"
  target="/proc/irq/${irq}/smp_affinity_list"
  echo "irq=${irq} cpu=${cpu} file=${target}"
  if (( apply == 1 )); then
    echo "$cpu" > "$target"
  fi
  idx=$((idx + 1))
done
