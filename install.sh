#!/usr/bin/env sh
# mcprism one-line installer.
#   curl -fsSL https://raw.githubusercontent.com/HUA503/mcprism/main/install.sh | sh
set -e

REPO="HUA503/mcprism"
BINARY="mcprism"
GITHUB="https://github.com/${REPO}"

download() {
  url="$1"; out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$out"
  else
    wget -qO "$out" "$url"
  fi
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    echo ""
  fi
}

invalid_version() {
  echo "error: invalid MC_PRISM_VERSION '${MC_PRISM_VERSION:-}' (expected latest or a version such as v0.33.0)" >&2
  exit 1
}

install_file() {
  src="$1"; dst="$2"
  if command -v install >/dev/null 2>&1; then
    install -m 0755 "$src" "$dst"
  else
    cp "$src" "$dst"
    chmod 0755 "$dst"
  fi
}

main() {
  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  arch=$(uname -m)
  case "$os" in
    linux) os="linux" ;;
    darwin) os="darwin" ;;
    mingw*|msys*|cygwin*) os="windows" ;;
    *) echo "unsupported OS: $os" >&2; exit 1 ;;
  esac
  case "$arch" in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    armv7l|arm) arch="arm" ;;
    *) echo "unsupported architecture: $arch" >&2; exit 1 ;;
  esac

  binname="${BINARY}"
  if [ "$os" = "windows" ]; then
    binname="${BINARY}.exe"
    archive_name="${BINARY}_${os}_${arch}.zip"
  else
    archive_name="${BINARY}_${os}_${arch}.tar.gz"
  fi
  requested_version="${MC_PRISM_VERSION:-latest}"
  if [ "$requested_version" = "latest" ]; then
    base="${GITHUB}/releases/latest/download"
  else
    case "$requested_version" in
      *[!0-9A-Za-z.+-]*) invalid_version ;;
    esac
    if ! printf '%s\n' "$requested_version" | grep -Eq '^v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'; then
      invalid_version
    fi
    case "$requested_version" in
      v*) release_tag="$requested_version" ;;
      *) release_tag="v${requested_version}" ;;
    esac
    base="${GITHUB}/releases/download/${release_tag}"
  fi

  tmpdir=$(mktemp -d)
  trap 'rm -rf "$tmpdir"' EXIT

  echo "Downloading ${archive_name}"
  download "${base}/${archive_name}" "$tmpdir/archive"
  echo "Downloading checksums.txt"
  if ! download "${base}/checksums.txt" "$tmpdir/checksums.txt"; then
    echo "error: could not fetch checksums.txt; refusing to install" >&2
    exit 1
  fi
  want=$(awk -v n="$archive_name" '$2==n {print $1}' "$tmpdir/checksums.txt")
  if [ -z "$want" ]; then
    echo "error: ${archive_name} not found in checksums.txt; refusing to install" >&2
    exit 1
  fi
  got=$(sha256_of "$tmpdir/archive")
  if [ -z "$got" ]; then
    echo "error: no sha256 tool found; refusing to install" >&2
    exit 1
  fi
  if [ "$got" != "$want" ]; then
    echo "error: checksum mismatch for ${archive_name}" >&2
    echo "  expected ${want}" >&2
    echo "  got      ${got}" >&2
    exit 1
  fi
  echo "Checksum verified"

  if [ "$os" = "windows" ]; then
    if command -v unzip >/dev/null 2>&1; then
      unzip -o "$tmpdir/archive" -d "$tmpdir" >/dev/null
    elif command -v powershell >/dev/null 2>&1; then
      win_archive=$(cygpath -w "$tmpdir/archive" 2>/dev/null || echo "$tmpdir/archive")
      win_dir=$(cygpath -w "$tmpdir" 2>/dev/null || echo "$tmpdir")
      powershell -NoProfile -Command "Expand-Archive -Force '$win_archive' '$win_dir'"
    else
      echo "error: need 'unzip' or PowerShell to extract the Windows archive" >&2
      exit 1
    fi
  else
    tar -xzf "$tmpdir/archive" -C "$tmpdir"
  fi

  if [ ! -f "$tmpdir/$binname" ]; then
    echo "error: ${binname} not found inside the archive" >&2
    exit 1
  fi

  install_dir="/usr/local/bin"
  if [ ! -w "$install_dir" ]; then
    install_dir="$HOME/.local/bin"
    mkdir -p "$install_dir"
  fi
  install_file "$tmpdir/$binname" "$install_dir/$binname"
  echo "Installed ${binname} to ${install_dir}/${binname}"
  case ":${PATH:-}:" in
    *":${install_dir}:"*)
      echo "Run '${BINARY} scan' to get started."
      ;;
    *)
      echo "The install directory is not on PATH: ${install_dir}"
      echo "Run '${install_dir}/${BINARY} scan', or add the directory to PATH."
      ;;
  esac
}

main "$@"
