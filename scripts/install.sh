#!/bin/sh
set -eu

fail() {
  printf 'spar installer: %s\n' "$1" >&2
  exit 1
}

for command in curl tar uname; do
  command -v "$command" >/dev/null 2>&1 || fail "required command not found: $command"
done

os="$(uname -s)"
arch="$(uname -m)"
case "$os-$arch" in
  Linux-x86_64|Linux-amd64) artifact="linux-amd64" ;;
  Linux-aarch64|Linux-arm64) artifact="linux-arm64" ;;
  Darwin-arm64) artifact="darwin-arm64" ;;
  Darwin-x86_64) artifact="darwin-amd64" ;;
  *) fail "unsupported platform: $os $arch" ;;
esac

version="${SPAR_VERSION:-}"
if [ -z "$version" ]; then
  latest_url="$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
    https://github.com/deepso7/spar/releases/latest)"
  version="${latest_url##*/}"
fi
version="${version#v}"
case "$version" in
  ""|*[!0-9A-Za-z.+-]*) fail "invalid release version: $version" ;;
esac

archive="spar-v${version}-${artifact}"
release_url="https://github.com/deepso7/spar/releases/download/v${version}"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/spar-install.XXXXXX")"
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM

curl -fsSL -o "$work_dir/$archive.tar.gz" "$release_url/$archive.tar.gz" ||
  fail "prebuilt spar is not available for v$version on $artifact"

tar -xzf "$work_dir/$archive.tar.gz" -C "$work_dir"
if [ -x "$work_dir/$archive/spar" ]; then
  binary="$work_dir/$archive/spar"
elif [ -x "$work_dir/spar" ]; then
  binary="$work_dir/spar"
else
  fail "archive does not contain an executable spar"
fi

install_dir="${SPAR_INSTALL_DIR:-$HOME/.local/bin}"
mkdir -p "$install_dir"
install -m 0755 "$binary" "$install_dir/spar"
printf 'installed spar %s to %s/spar\n' "$version" "$install_dir"
printf 'next: spar listen --relay\n'
