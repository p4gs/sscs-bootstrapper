# ClusterFuzzLite build environment for sscsb's cargo-fuzz targets.
# ClusterFuzzLite is the fuzzing integration OpenSSF Scorecard detects for Rust.
FROM gcr.io/oss-fuzz-base/base-builder-rust
COPY . $SRC/sscsb
WORKDIR $SRC/sscsb
COPY .clusterfuzzlite/build.sh $SRC/build.sh
