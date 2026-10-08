#!/usr/bin/env bash
# Build the vX.Y.Z release archives the same way GoReleaser would:
#   mcprism_<os>_<arch>.[tar.gz|zip] + checksums.txt
# Run from the project root:  bash scripts/build_dist.sh
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="$(grep -oP 'const version = "\K[^"]+' cmd/mcprism/main.go)"
echo "Building dist for mcprism ${VERSION}"

rm -rf dist
mkdir -p dist

build_archive() {
  local goos="$1" goarch="$2" ext="$3" bin="$4"
  local dir="dist/mcprism_${goos}_${goarch}"
  mkdir -p "$dir"
  echo "  building ${goos}/${goarch}"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath -ldflags="-s -w" -o "$dir/$bin" ./cmd/mcprism
  cp LICENSE README.md "$dir/"
  (cd dist && tar czf "mcprism_${goos}_${goarch}.${ext}" "$(basename "$dir")")
  rm -rf "$dir"
}

build_archive linux amd64 tar.gz mcprism
build_archive linux arm64 tar.gz mcprism
build_archive darwin amd64 tar.gz mcprism
build_archive darwin arm64 tar.gz mcprism

# windows amd64 only (matches .goreleaser.yml ignore list), zip format
W="dist/mcprism_windows_amd64"
mkdir -p "$W"
echo "  building windows/amd64"
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
  go build -trimpath -ldflags="-s -w" -o "$W/mcprism.exe" ./cmd/mcprism
cp LICENSE README.md "$W/"
(cd dist && python3 -c "
import zipfile, os
z = zipfile.ZipFile('mcprism_windows_amd64.zip','w',zipfile.ZIP_DEFLATED)
for f in ['mcprism_windows_amd64/mcprism.exe','mcprism_windows_amd64/LICENSE','mcprism_windows_amd64/README.md']:
    z.write(f)
z.close()
")
rm -rf "$W"

# checksums
(cd dist && sha256sum *.tar.gz *.zip > checksums.txt)
echo "Dist files:"
ls -la dist/ | grep -vE "^d|total"
echo "Checksums:"
cat dist/checksums.txt
