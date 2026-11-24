#!/usr/bin/env bash
set -Eeuo pipefail

fail() {
  echo "Homebrew formula update: $*" >&2
  exit 1
}

tag="${1:-}"
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
  fail "expected a stable release tag such as v0.8.3"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
formula="${repo_root}/Formula/mcprism.rb"
archive="$(mktemp)"
trap 'rm -f "$archive"' EXIT

archive_url="https://github.com/HUA503/mcprism/archive/refs/tags/${tag}.tar.gz"
curl --fail --location --silent --show-error --retry 3 "$archive_url" --output "$archive"
checksum="$(sha256sum "$archive" | cut -d ' ' -f 1)"
[[ "$checksum" =~ ^[[:xdigit:]]{64}$ ]] || fail "could not calculate source archive SHA-256"

sed -i \
  -e "s|^  url \".*\"$|  url \"${archive_url}\"|" \
  -e "s|^  sha256 \".*\"$|  sha256 \"${checksum}\"|" \
  "$formula"

echo "Updated ${formula} for ${tag} (${checksum})"
