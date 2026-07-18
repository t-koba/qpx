#!/usr/bin/env bash
set -euo pipefail

repository_url="${1:?repository URL is required}"
revision="${2:?40-character commit revision is required}"
destination="${3:?destination path is required}"

if [[ ! "$revision" =~ ^[0-9a-f]{40}$ ]]; then
  echo "revision must be a lowercase 40-character commit SHA" >&2
  exit 2
fi
if [[ -e "$destination" ]]; then
  echo "destination already exists: $destination" >&2
  exit 2
fi

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/qpx-fetch-pinned.XXXXXX")"
cleanup() {
  rm -rf "$work_dir"
}
trap cleanup EXIT

repository_dir="$work_dir/repository"
git init --quiet "$repository_dir"
git -C "$repository_dir" remote add origin "$repository_url"

fetched=false
for attempt in 1 2 3 4; do
  if git -C "$repository_dir" fetch --quiet --no-tags --depth=1 origin "$revision"; then
    fetched=true
    break
  fi
  if (( attempt < 4 )); then
    delay=$((attempt * 2))
    echo "repository fetch attempt $attempt failed; retrying in $delay seconds" >&2
    sleep "$delay"
  fi
done
if [[ "$fetched" != true ]]; then
  echo "failed to fetch pinned repository revision after 4 attempts" >&2
  exit 1
fi

git -C "$repository_dir" checkout --quiet --detach FETCH_HEAD
actual_revision="$(git -C "$repository_dir" rev-parse HEAD)"
if [[ "$actual_revision" != "$revision" ]]; then
  echo "fetched repository revision mismatch" >&2
  exit 1
fi

mkdir -p "$(dirname "$destination")"
mv "$repository_dir" "$destination"
