#!/usr/bin/env bash
set -euo pipefail
project_dir="$(cd "$(dirname "$0")/.." && pwd)"
: "${ANDROID_NDK_HOME:=${ANDROID_HOME:?Set ANDROID_HOME}/ndk/27.0.12077973}"
export ANDROID_NDK_HOME
cd "$project_dir/vendor/boxkernel"
export CARGO_TARGET_DIR="${BOXOS_TARGET_DIR:-$project_dir/vendor/boxkernel/target}"
# Android 15 devices may use 16 KiB pages.
export RUSTFLAGS="${RUSTFLAGS:-} -C link-arg=-Wl,-z,max-page-size=16384"
cargo ndk -t arm64-v8a -t x86_64 -P 26 build --release --locked
for pair in aarch64-linux-android:arm64-v8a x86_64-linux-android:x86_64; do
    target="${pair%:*}"
    abi="${pair#*:}"
    destination="$project_dir/app/src/main/jniLibs/$abi"
    mkdir -p "$destination"
    cp "$CARGO_TARGET_DIR/$target/release/proot" "$destination/libboxkernel.so"
    loader=""
    for candidate in "$CARGO_TARGET_DIR/$target/release/build"/boxkernel-*/out/loader.exe; do
        if [[ -s "$candidate" && ( -z "$loader" || "$candidate" -nt "$loader" ) ]]; then loader="$candidate"; fi
    done
    test -n "$loader" || { echo "Missing embedded loader for $abi" >&2; exit 1; }
    cp "$loader" "$destination/libboxloader.so"
    chmod 755 "$destination/"*.so
done
