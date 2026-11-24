#!/usr/bin/env bash
set -Eeuo pipefail

fail() {
  echo "mcprism action: $*" >&2
  exit 2
}

if [[ "$(uname -s)" != "Linux" ]]; then
  fail "this action currently supports Linux runners only"
fi

version="${MC_PRISM_VERSION:-}"
if [[ -z "$version" ]]; then
  version="${MC_PRISM_ACTION_REF:-}"
  version="${version#refs/tags/}"
fi
if [[ ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  fail "set version to a release tag such as v0.7.0, or pin this action to a release tag"
fi

case "$(uname -m)" in
  x86_64|amd64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *) fail "unsupported Linux architecture: $(uname -m)" ;;
esac

archive="mcprism_linux_${arch}.tar.gz"
base="https://github.com/HUA503/mcprism/releases/download/${version}"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

curl --fail --location --silent --show-error --retry 3 \
  "${base}/${archive}" --output "${tmp_dir}/${archive}"
curl --fail --location --silent --show-error --retry 3 \
  "${base}/checksums.txt" --output "${tmp_dir}/checksums.txt"

expected="$(awk -v name="$archive" '$2 == name || $2 == "*" name { print $1; exit }' "${tmp_dir}/checksums.txt")"
[[ "$expected" =~ ^[[:xdigit:]]{64}$ ]] || fail "no valid SHA-256 checksum found for ${archive} in release ${version}"
actual="$(sha256sum "${tmp_dir}/${archive}" | awk '{print $1}')"
[[ "$actual" == "$expected" ]] || fail "SHA-256 verification failed for ${archive}"

tar -xzf "${tmp_dir}/${archive}" -C "$tmp_dir"
binary="${tmp_dir}/mcprism"
[[ -x "$binary" ]] || fail "release archive does not contain an executable mcprism binary"

workspace="${GITHUB_WORKSPACE:-$PWD}"
sarif_file="${MC_PRISM_SARIF_FILE:-mcprism.sarif}"
[[ "$sarif_file" != /* ]] || fail "sarif-file must be a workspace-relative path"
sarif_path="${workspace}/${sarif_file}"
mkdir -p "$(dirname "$sarif_path")"

args=(scan "${MC_PRISM_TARGET:-.}" --format sarif --output "$sarif_path")
[[ -z "${MC_PRISM_PROFILE:-}" ]] || args+=(--profile "$MC_PRISM_PROFILE")
[[ -z "${MC_PRISM_POLICY:-}" ]] || args+=(--policy "$MC_PRISM_POLICY")
[[ -z "${MC_PRISM_SUPPRESSIONS:-}" ]] || args+=(--suppressions "$MC_PRISM_SUPPRESSIONS")
[[ -z "${MC_PRISM_BASELINE:-}" ]] || args+=(--baseline "$MC_PRISM_BASELINE")
[[ -z "${MC_PRISM_FAIL_ON:-}" ]] || args+=(--fail-on "$MC_PRISM_FAIL_ON")

echo "sarif-file=${sarif_file}" >> "$GITHUB_OUTPUT"
echo "version=${version}" >> "$GITHUB_OUTPUT"

set +e
"$binary" "${args[@]}"
status=$?
set -e
exit "$status"
