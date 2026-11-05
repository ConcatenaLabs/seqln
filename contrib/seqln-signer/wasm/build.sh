#!/usr/bin/env bash
# Builds the WASM signer so that anyone gets the same bytes from the same source.
#
#   contrib/seqln-signer/wasm/build.sh web <out-dir>      # the package a wallet page serves
#   contrib/seqln-signer/wasm/build.sh nodejs <out-dir>   # the package the Node tests load
#
# What fixes the output:
#   - rustc, from rust-toolchain.toml beside this script (rustup installs it);
#   - wasm-bindgen, from Cargo.lock (wasm-pack fetches the matching CLI);
#   - no wasm-opt pass (Cargo.toml turns it off);
#   - the build path: rustc names each crate's symbols with a hash of the
#     crate's absolute path, so the tracked files of contrib/seqln-signer are
#     copied to one fixed directory and built there;
#   - every other machine path remapped out (the cargo home, the toolchain).
# The C code of secp256k1 is compiled by the machine's clang; a different
# clang major version changes those functions' bodies.
#
# It prints the package's sha256. Two builds of one commit print the same.
set -euo pipefail
target=${1:?name the target: web or nodejs}
out=${2:?name the output directory}
case $target in web|nodejs) ;; *) echo "target is web or nodejs, not $target" >&2; exit 2;; esac
mkdir -p "$out"
out=$(cd "$out" && pwd)
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
crate=$(dirname "$here")
root=/tmp/seqln-signer-wasm-build
cargo_home=${CARGO_HOME:-$HOME/.cargo}
rustup_home=${RUSTUP_HOME:-$HOME/.rustup}

rm -rf "$root"
mkdir -p "$root/seqln/contrib/seqln-signer"
(cd "$crate" && git ls-files -z --cached --others --exclude-standard . | tar --null -T - -cf -) | tar -xf - -C "$root/seqln/contrib/seqln-signer"

flags=(
  "--remap-path-prefix=$root/seqln=/seqln"
  "--remap-path-prefix=$cargo_home=/cargo"
  "--remap-path-prefix=$rustup_home=/rustup"
)
CARGO_ENCODED_RUSTFLAGS="$(IFS=$'\x1f'; echo "${flags[*]}")"
export CARGO_ENCODED_RUSTFLAGS
export CARGO_TARGET_DIR="$root/target"
cd "$root/seqln/contrib/seqln-signer/wasm"
echo "rustc: $(rustc --version); $(wasm-pack --version); clang: $(clang --version 2>/dev/null | head -1)"
wasm-pack build --target "$target" --release --out-dir "$out"
for p in "$HOME" "$root" "$cargo_home"; do
  if grep -a -q -F "$p" "$out/seqln_signer_wasm_bg.wasm"; then
    echo "error: $out/seqln_signer_wasm_bg.wasm still contains $p" >&2
    exit 1
  fi
done
rm -rf "$root"
echo "built from $(git -C "$crate" rev-parse --short=9 HEAD)$(git -C "$crate" diff --quiet HEAD -- . || echo ' with local changes'): seqln_signer_wasm_bg.wasm $(wc -c < "$out/seqln_signer_wasm_bg.wasm") bytes, sha256 $(sha256sum "$out/seqln_signer_wasm_bg.wasm" | cut -d' ' -f1)"
