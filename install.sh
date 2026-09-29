#!/usr/bin/env sh
# mcprism one-line installer.
#   curl -fsSL https://raw.githubusercontent.com/HUA503/mcprism/main/install.sh | sh
set -e

REPO="HUA503/mcprism"
BINARY="mcprism"
GITHUB="https://github.com/${REPO}"

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

  asset="${BINARY}_${os}_${arch}"
  if [ "$os" = "windows" ]; then
    url="${GITHUB}/releases/latest/download/${asset}.zip"
  else
    url="${GITHUB}/releases/latest/download/${asset}.tar.gz"
  fi

  tmpdir=$(mktemp -d)
  trap 'rm -rf "$tmpdir"' EXIT
  echo "Downloading $url"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$tmpdir/archive"
  else
    wget -qO "$tmpdir/archive" "$url"
  fi

  if [ "$os" = "windows" ]; then
    unzip -o "$tmpdir/archive" -d "$tmpdir" >/dev/null
  else
    tar -xzf "$tmpdir/archive" -C "$tmpdir"
  fi

  install_dir="/usr/local/bin"
  if [ ! -w "$install_dir" ]; then
    install_dir="$HOME/.local/bin"
    mkdir -p "$install_dir"
  fi
  install -m 0755 "$tmpdir/${BINARY}" "$install_dir/${BINARY}"
  echo "Installed ${BINARY} to ${install_dir}/${BINARY}"
  echo "Run '${BINARY} scan' to get started."
}

main "$@"
