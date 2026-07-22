#!/bin/bash -eu
# ClusterFuzzLite build script: compile the cargo-fuzz targets and copy the
# resulting libFuzzer binaries into $OUT for the fuzzing engine.
cd "$SRC/sscsb"
cargo fuzz build -O
TARGET_DIR="$SRC/sscsb/fuzz/target/x86_64-unknown-linux-gnu/release"
for target in parse_trailers parse_signers parse_deps; do
  cp "$TARGET_DIR/$target" "$OUT/"
done
