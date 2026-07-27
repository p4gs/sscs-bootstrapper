#!/bin/bash -eu
# ClusterFuzzLite build script — compile the cargo-fuzz targets and copy the
# resulting libFuzzer binaries into $OUT. Installed by sscsb's `fuzzing` control.
cd "$SRC/{{project}}"
# CUSTOMIZE: cargo-fuzz targets are inherently project-specific — sscsb cannot
# generate meaningful ones for you. Add a `fuzz/` cargo-fuzz project
# (`cargo fuzz init`) that fuzzes your untrusted-input parsers, then this loop
# builds and ships every target you define.
cargo fuzz build -O
TARGET_DIR="$SRC/{{project}}/fuzz/target/x86_64-unknown-linux-gnu/release"
for target in $(cargo fuzz list); do
  cp "$TARGET_DIR/$target" "$OUT/"
done
