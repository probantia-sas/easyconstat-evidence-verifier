#!/usr/bin/env bash
set -euo pipefail

[[ $# -eq 1 ]] || {
    printf 'usage: %s PREPARED_DIRECTORY\n' "$0" >&2
    exit 2
}

directory="$(realpath -e -- "$1")"
[[ -d "$directory" && ! -L "$directory" ]] || {
    printf 'error=prepared_directory_invalid\n' >&2
    exit 1
}

manifest="$directory/evidence-manifest.json"
[[ -f "$manifest" && ! -L "$manifest" ]] || {
    printf 'error=manifest_invalid\n' >&2
    exit 1
}

command -v jq >/dev/null 2>&1 || {
    printf 'error=jq_unavailable\n' >&2
    exit 1
}

inventory="$(mktemp)"
expected_names="$(mktemp)"
actual_names="$(mktemp)"
trap 'rm -f -- "$inventory" "$expected_names" "$actual_names"' EXIT

jq -er '
    if (.artifacts | type) != "array" or (.artifacts | length) == 0 then
        error("invalid artifacts")
    elif ((all(.artifacts[];
        (.path | type) == "string"
        and (.size | type) == "number"
        and (.size | floor) == .size
        and .size >= 0
        and (.sha256 | type) == "string"
        and (.sha256 | test("^[a-f0-9]{64}$")))) | not) then
        error("invalid artifact fields")
    else
        .artifacts[]
        | [.path, (.size | tostring), .sha256]
        | @tsv
    end
' "$manifest" > "$inventory"

artifact_count=0
while IFS=$'\t' read -r path expected_size expected_sha256; do
    [[ -n "$path" && "$path" == "$(basename -- "$path")" ]] || {
        printf 'error=unsafe_artifact_path path=%q\n' "$path" >&2
        exit 1
    }
    target="$directory/$path"
    [[ -f "$target" && ! -L "$target" ]] || {
        printf 'error=artifact_invalid path=%q\n' "$path" >&2
        exit 1
    }
    [[ "$(stat -c '%s' -- "$target")" == "$expected_size" ]] || {
        printf 'error=artifact_size_mismatch path=%q\n' "$path" >&2
        exit 1
    }
    [[ "$(sha256sum -- "$target" | awk '{print $1}')" == "$expected_sha256" ]] || {
        printf 'error=artifact_hash_mismatch path=%q\n' "$path" >&2
        exit 1
    }
    printf '%s\n' "$path" >> "$expected_names"
    artifact_count=$((artifact_count + 1))
done < "$inventory"

unique_artifact_count="$(sort "$expected_names" | uniq | wc -l)"
[[ "$unique_artifact_count" -eq "$artifact_count" ]] || {
    printf 'error=duplicate_artifact_path\n' >&2
    exit 1
}

printf '%s\n' 'evidence-manifest.json' >> "$expected_names"
find "$directory" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' > "$actual_names"
sort -u -o "$expected_names" "$expected_names"
sort -u -o "$actual_names" "$actual_names"
cmp -s "$expected_names" "$actual_names" || {
    printf 'error=unexpected_or_missing_file\n' >&2
    exit 1
}

printf 'status=verified\n'
printf 'directory=%s\n' "$directory"
printf 'artifacts=%d\n' "$artifact_count"
printf 'manifest_sha256=%s\n' "$(sha256sum -- "$manifest" | awk '{print $1}')"
