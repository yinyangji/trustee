#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

if (( $# != 5 )); then
    printf 'Usage: %s SOURCE_DIR BUILDER_IMAGE@sha256:DIGEST OUTPUT_DIR COMMIT SOURCE_DATE_EPOCH\n' "$0" >&2
    exit 2
fi

source_dir=$(realpath "$1")
builder=$2
output_dir=$(realpath -m "$3")
commit=$4
epoch=$5

if [[ ! $builder =~ @sha256:[0-9a-f]{64}$ || ! $commit =~ ^([a-f0-9]{40}|[a-f0-9]{64})$ || ! $epoch =~ ^(0|[1-9][0-9]*)$ ]]; then
    printf 'Specify an immutable builder digest, full Git object ID and Unix epoch.\n' >&2
    exit 2
fi
if [[ ! -f $source_dir/Cargo.lock ]]; then
    printf 'Source directory must contain the published Trustee source and Cargo.lock.\n' >&2
    exit 2
fi
if [[ $output_dir == "$source_dir" || $output_dir == "$source_dir/"* ]]; then
    printf 'The output directory must be outside the source directory.\n' >&2
    exit 2
fi
mkdir -p "$output_dir"

# The release inputs contain a vendored Cargo configuration and dependencies.
# The published builder contains the pinned toolchain, protoc, and native headers.
docker run --rm --pull never --network none --platform linux/amd64 \
    --user "$(id -u):$(id -g)" \
    --workdir /build/src \
    --mount "type=bind,source=$source_dir,target=/build/src,readonly" \
    --mount "type=bind,source=$output_dir,target=/output" \
    --tmpfs /build/target:exec,mode=1777 \
    --tmpfs /build/cargo:mode=1777 \
    --tmpfs /build/tmp:exec,mode=1777 \
    --env CARGO_HOME=/build/cargo \
    --env CARGO_TARGET_DIR=/build/target \
    --env TMPDIR=/build/tmp \
    --env RUSTFLAGS='--remap-path-prefix=/build/src=/src --remap-path-prefix=/build/target=/target' \
    --env "TRUSTEE_AS_BUILD_COMMIT=$commit" \
    --env "SOURCE_DATE_EPOCH=$epoch" \
    --env TZ=UTC --env LC_ALL=C.UTF-8 \
    "$builder" /bin/sh -ec '
        umask 022
        cargo build --frozen --release -p attestation-service \
            --features all-verifier,restful-bin,tdx-self-attestation \
            --bin grpc-as --bin restful-as
        cargo build --frozen --release -p tdx-workload --features as-launch --bin tdx-as-launch
        install -m 0755 /build/target/release/grpc-as /build/target/release/restful-as \
            /build/target/release/tdx-as-launch /output/
        cd /output
        sha384sum grpc-as restful-as tdx-as-launch > expected-elf.sha384
    '
