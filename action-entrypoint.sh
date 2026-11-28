#!/usr/bin/env bash
set -Eeuo pipefail

fail() {
  echo "mcprism action: $*" >&2
  exit 2
}

case "$(uname -s)" in
  Linux) os="linux" ;;
  Darwin) os="darwin" ;;
  *) fail "unsupported runner OS: $(uname -s); use Linux or macOS" ;;
esac

version="${MC_PRISM_VERSION:-}"
if [[ -z "$version" ]]; then
  version="${MC_PRISM_ACTION_REF:-}"
  version="${version#refs/tags/}"
fi
if [[ ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  fail "set version to a release tag such as v0.17.0, or pin this action to a release tag"
fi

inventory_target="${MC_PRISM_INVENTORY_TARGET:-}"
inventory_baseline="${MC_PRISM_INVENTORY_BASELINE:-}"
if [[ -n "$inventory_target" && -z "$inventory_baseline" ]]; then
  fail "inventory-target requires inventory-baseline"
fi
if [[ -z "$inventory_target" && -n "$inventory_baseline" ]]; then
  fail "inventory-baseline requires inventory-target"
fi

case "$(uname -m)" in
  x86_64|amd64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *) fail "unsupported ${os} architecture: $(uname -m)" ;;
esac

archive="mcprism_${os}_${arch}.tar.gz"
base="https://github.com/HUA503/mcprism/releases/download/${version}"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

curl --fail --location --silent --show-error --retry 3 \
  "${base}/${archive}" --output "${tmp_dir}/${archive}"
curl --fail --location --silent --show-error --retry 3 \
  "${base}/checksums.txt" --output "${tmp_dir}/checksums.txt"

expected="$(awk -v name="$archive" '$2 == name || $2 == "*" name { print $1; exit }' "${tmp_dir}/checksums.txt")"
[[ "$expected" =~ ^[[:xdigit:]]{64}$ ]] || fail "no valid SHA-256 checksum found for ${archive} in release ${version}"
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "${tmp_dir}/${archive}" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  actual="$(shasum -a 256 "${tmp_dir}/${archive}" | awk '{print $1}')"
else
  fail "no SHA-256 utility found (need sha256sum or shasum)"
fi
[[ "$actual" == "$expected" ]] || fail "SHA-256 verification failed for ${archive}"

tar -xzf "${tmp_dir}/${archive}" -C "$tmp_dir"
binary="${tmp_dir}/mcprism"
[[ -x "$binary" ]] || fail "release archive does not contain an executable mcprism binary"

workspace="${GITHUB_WORKSPACE:-$PWD}"
scan_config="${MC_PRISM_SCAN_CONFIG:-true}"
case "$scan_config" in
  true|false) ;;
  *) fail "scan-config must be true or false" ;;
esac
target="${MC_PRISM_TARGET-.}"
source_target="${MC_PRISM_SOURCE_TARGET:-}"
[[ "$scan_config" == true || -n "$source_target" ]] || fail "set scan-config to true or provide source-target"

sarif_file=""
sarif_path=""
if [[ "$scan_config" == true ]]; then
  sarif_file="${MC_PRISM_SARIF_FILE:-mcprism.sarif}"
  [[ "$sarif_file" != /* ]] || fail "sarif-file must be a workspace-relative path"
  sarif_path="${workspace}/${sarif_file}"
  mkdir -p "$(dirname "$sarif_path")"
fi

source_sarif_file=""
source_sarif_path=""
if [[ -n "$source_target" ]]; then
  source_sarif_file="${MC_PRISM_SOURCE_SARIF_FILE:-mcprism-source.sarif}"
  [[ "$source_sarif_file" != /* ]] || fail "source-sarif-file must be a workspace-relative path"
  [[ "$scan_config" != true || "$source_sarif_file" != "$sarif_file" ]] || fail "source-sarif-file must differ from sarif-file"
  source_sarif_path="${workspace}/${source_sarif_file}"
  mkdir -p "$(dirname "$source_sarif_path")"
fi

args=()
if [[ "$scan_config" == true ]]; then
  args=(scan "$target" --format sarif --output "$sarif_path")
  [[ -z "${MC_PRISM_PROFILE:-}" ]] || args+=(--profile "$MC_PRISM_PROFILE")
  [[ -z "${MC_PRISM_POLICY:-}" ]] || args+=(--policy "$MC_PRISM_POLICY")
  [[ -z "${MC_PRISM_SUPPRESSIONS:-}" ]] || args+=(--suppressions "$MC_PRISM_SUPPRESSIONS")
  [[ -z "${MC_PRISM_BASELINE:-}" ]] || args+=(--baseline "$MC_PRISM_BASELINE")
  [[ -z "${MC_PRISM_FAIL_ON:-}" ]] || args+=(--fail-on "$MC_PRISM_FAIL_ON")
fi

echo "sarif-file=${sarif_file}" >> "$GITHUB_OUTPUT"
echo "source-sarif-file=${source_sarif_file}" >> "$GITHUB_OUTPUT"
echo "version=${version}" >> "$GITHUB_OUTPUT"

set +e
status=0
if [[ "$scan_config" == true ]]; then
  "$binary" "${args[@]}"
  status=$?
fi
source_status=0
if [[ -n "$source_target" ]]; then
  source_args=(vet "$source_target" --format sarif --output "$source_sarif_path")
  [[ -z "${MC_PRISM_PROFILE:-}" ]] || source_args+=(--profile "$MC_PRISM_PROFILE")
  [[ -z "${MC_PRISM_POLICY:-}" ]] || source_args+=(--policy "$MC_PRISM_POLICY")
  [[ -z "${MC_PRISM_SUPPRESSIONS:-}" ]] || source_args+=(--suppressions "$MC_PRISM_SUPPRESSIONS")
  [[ -z "${MC_PRISM_BASELINE:-}" ]] || source_args+=(--baseline "$MC_PRISM_BASELINE")
  [[ -z "${MC_PRISM_FAIL_ON:-}" ]] || source_args+=(--fail-on "$MC_PRISM_FAIL_ON")
  "$binary" "${source_args[@]}"
  source_status=$?
fi
inventory_status="skipped"
inventory_exit=0
if [[ -n "$inventory_baseline" && "$status" -ne 2 && "$source_status" -ne 2 ]]; then
  "$binary" inventory verify "$inventory_target" --baseline "$inventory_baseline"
  inventory_exit=$?
  case "$inventory_exit" in
    0) inventory_status="passed" ;;
    1) inventory_status="drift" ;;
    *) inventory_status="error" ;;
  esac
fi
set -e

echo "inventory-status=${inventory_status}" >> "$GITHUB_OUTPUT"
if [[ "$status" -eq 2 || "$source_status" -eq 2 || "$inventory_exit" -eq 2 ]]; then
  exit 2
fi
if [[ "$status" -ne 0 || "$source_status" -ne 0 || "$inventory_exit" -ne 0 ]]; then
  exit 1
fi
exit 0
