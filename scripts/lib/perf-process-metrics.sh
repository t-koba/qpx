#!/usr/bin/env bash

clock_ticks() {
  getconf CLK_TCK 2>/dev/null || echo 100
}

children_of_pid() {
  local pid="$1"
  if command -v pgrep >/dev/null 2>&1; then
    pgrep -P "$pid" 2>/dev/null || true
  elif ps -o pid= --ppid "$pid" >/dev/null 2>&1; then
    ps -o pid= --ppid "$pid" 2>/dev/null | awk '{ print $1 }'
  fi
}

process_tree_pids() {
  local root="$1"
  local child
  if [ -z "$root" ]; then
    return
  fi
  echo "$root"
  for child in $(children_of_pid "$root"); do
    process_tree_pids "$child"
  done
}

proc_cpu_ticks() {
  local pid="$1"
  local stat="/proc/${pid}/stat"
  if [ ! -r "$stat" ]; then
    echo 0
    return
  fi
  awk '{
    comm_end = index($0, ") ")
    if (comm_end == 0) {
      print 0
      exit
    }
    rest = substr($0, comm_end + 2)
    split(rest, fields, " ")
    print fields[12] + fields[13]
  }' "$stat"
}

process_cpu_ms_portable() {
  local pid="$1"
  local cpu_time
  cpu_time="$(ps -o time= -p "$pid" 2>/dev/null | awk '{$1=$1; print}' || true)"
  if [ -z "$cpu_time" ]; then
    echo 0
    return
  fi
  awk -v value="$cpu_time" 'BEGIN {
    days = 0
    if (index(value, "-") > 0) {
      split(value, day_parts, "-")
      days = day_parts[1]
      value = day_parts[2]
    }
    count = split(value, time_parts, ":")
    hours = 0
    if (count == 3) {
      hours = time_parts[1]
      minutes = time_parts[2]
      seconds = time_parts[3]
    } else if (count == 2) {
      minutes = time_parts[1]
      seconds = time_parts[2]
    } else {
      print 0
      exit
    }
    printf "%.0f", ((((days * 24) + hours) * 60 + minutes) * 60 + seconds) * 1000
  }'
}

proc_status_value_kb() {
  local pid="$1"
  local key="$2"
  local status="/proc/${pid}/status"
  if [ ! -r "$status" ]; then
    echo 0
    return
  fi
  awk -v key="$key" '$1 == key ":" { print $2; found = 1; exit } END { if (!found) print 0 }' "$status"
}

process_tree_cpu_ms() {
  local root="$1"
  local hz pid ticks total_ticks total_ms
  if [ -z "$root" ]; then
    echo 0
    return
  fi
  if [ ! -d /proc ]; then
    total_ms=0
    for pid in $(process_tree_pids "$root"); do
      total_ms=$((total_ms + $(process_cpu_ms_portable "$pid")))
    done
    echo "$total_ms"
    return
  fi
  hz="$(clock_ticks)"
  total_ticks=0
  for pid in $(process_tree_pids "$root"); do
    ticks="$(proc_cpu_ticks "$pid")"
    total_ticks=$((total_ticks + ticks))
  done
  awk -v ticks="$total_ticks" -v hz="$hz" 'BEGIN { printf "%.0f", (ticks * 1000) / hz }'
}

process_tree_status_kb() {
  local root="$1"
  local key="$2"
  local pid value total
  if [ -z "$root" ] || [ ! -d /proc ]; then
    echo 0
    return
  fi
  total=0
  for pid in $(process_tree_pids "$root"); do
    value="$(proc_status_value_kb "$pid" "$key")"
    total=$((total + value))
  done
  echo "$total"
}

process_tree_fd_count() {
  local root="$1"
  local fd pid total
  if [ -z "$root" ] || [ ! -d /proc ]; then
    echo 0
    return
  fi
  total=0
  for pid in $(process_tree_pids "$root"); do
    if [ ! -d "/proc/${pid}/fd" ]; then
      continue
    fi
    for fd in "/proc/${pid}/fd"/*; do
      if [ -e "$fd" ]; then
        total=$((total + 1))
      fi
    done
  done
  echo "$total"
}

process_tree_scheduler_run_delay_ns() {
  local root="$1"
  local pid schedstat task total value
  if [ -z "$root" ] || [ ! -d /proc ]; then
    echo 0
    return
  fi
  total=0
  for pid in $(process_tree_pids "$root"); do
    for task in "/proc/${pid}/task"/*; do
      schedstat="${task}/schedstat"
      if [ ! -r "$schedstat" ]; then
        continue
      fi
      value="$(awk '{ print $2 }' "$schedstat")"
      total=$((total + value))
    done
  done
  echo "$total"
}

monitor_process_tree_rss_peak() {
  local root="$1"
  local output="$2"
  local initial="${3:-}"
  local current peak stopping
  if [ -z "$initial" ]; then
    initial="$(process_tree_status_kb "$root" "VmRSS")"
  fi
  peak="$initial"
  stopping=0
  trap 'stopping=1' TERM INT
  printf '%s\n' "$peak" >"$output"
  while [ "$stopping" -eq 0 ] && kill -0 "$root" >/dev/null 2>&1; do
    current="$(process_tree_status_kb "$root" "VmRSS")"
    if [ "$current" -gt "$peak" ]; then
      peak="$current"
      printf '%s\n' "$peak" >"$output"
    fi
    sleep 0.01
  done
  trap - TERM INT
}

monitor_process_tree_fd_peak() {
  local root="$1"
  local output="$2"
  local initial="${3:-}"
  local current peak stopping
  if [ -z "$initial" ]; then
    initial="$(process_tree_fd_count "$root")"
  fi
  peak="$initial"
  stopping=0
  trap 'stopping=1' TERM INT
  printf '%s\n' "$peak" >"$output"
  while [ "$stopping" -eq 0 ] && kill -0 "$root" >/dev/null 2>&1; do
    current="$(process_tree_fd_count "$root")"
    if [ "$current" -gt "$peak" ]; then
      peak="$current"
      printf '%s\n' "$peak" >"$output"
    fi
    sleep 0.05
  done
  trap - TERM INT
}

peak_growth() {
  local baseline="$1"
  local peak="$2"
  if [ "$peak" -gt "$baseline" ]; then
    echo $((peak - baseline))
  else
    echo 0
  fi
}
