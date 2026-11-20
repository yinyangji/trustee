# Copyright (c) 2023 by Alibaba.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

# rust:1.95.0
FROM --platform=${BUILDPLATFORM:-linux/amd64} \
    docker.io/library/rust@sha256:f49565f188ee00bc2a18dd418183f2c5f23ef7d6e691890517ed341a598f67c3 \
    AS builder
ARG ARCH=x86_64
ARG VERIFIER=all-verifier
ARG ENABLE_INFERENCE=false
ARG TRUSTEE_AS_BUILD_COMMIT
ARG SOURCE_DATE_EPOCH
ARG RELEASE_ELF_DIR=

WORKDIR /usr/src/attestation-service
COPY . .

# Install TPM Build Dependencies
RUN apt-get update && apt-get install --no-install-recommends -y protobuf-compiler clang libtss2-dev cmake

# Install TDX Build Dependencies
ARG DCAP_VERSION=1_27_100
RUN if [ "${ARCH}" = "x86_64" ]; then curl -L https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | gpg --dearmor --output /usr/share/keyrings/intel-sgx.gpg && \
    curl -sSLf https://download.01.org/intel-sgx/sgx_repo/ubuntu/apt_preference_files/99dcap_${DCAP_VERSION}_noble_custom_version.cfg | \
    tee -a /etc/apt/preferences.d/99dcap && \
    echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main' | tee /etc/apt/sources.list.d/intel-sgx.list && \
    apt-get update && apt-get install --no-install-recommends -y libsgx-dcap-quote-verify-dev; fi

# Build and Install gRPC attestation-service
RUN if [ "$(uname -m)" != "${ARCH}" ]; then \
    export GCC_PACKAGE="gcc-${ARCH}-linux-gnu"; \
    export GCC_COMPILER="${ARCH}-linux-gnu-gcc"; \
    export RUSTC_TARGET="${ARCH}-unknown-linux-gnu"; \
    export TARGET_FLAG="--target ${RUSTC_TARGET}"; \
    export RUSTFLAGS_ARGS=" -C linker=${GCC_COMPILER}"; \
    export RUSTFLAGS="${RUSTFLAGS_ARGS}"; \
    apt-get install -y ${GCC_PACKAGE}; \
    rustup target add ${RUSTC_TARGET}; fi; \
    if [ -n "${RELEASE_ELF_DIR}" ]; then \
        if [ "${ENABLE_INFERENCE}" != "true" ] || [ "${ARCH}" != "x86_64" ] || [ "${VERIFIER}" != "all-verifier" ]; then \
            echo "Release ELF packaging requires the shared x86_64 inference profile" >&2; exit 1; \
        fi; \
        cd "${RELEASE_ELF_DIR}" && \
        sha384sum grpc-as restful-as tdx-as-launch > /tmp/actual-as.sha384 && \
        cmp expected-elf.sha384 /tmp/actual-as.sha384 && \
        install -D -m 0755 -t /opt/as/bin grpc-as restful-as tdx-as-launch; \
    elif [ "${ENABLE_INFERENCE}" = "true" ]; then \
        if [ "${ARCH}" != "x86_64" ] || { [ "${VERIFIER}" != "all-verifier" ] && [ "${VERIFIER}" != "tdx-verifier" ]; }; then \
            echo "ENABLE_INFERENCE requires x86_64 and a native TDX verifier" >&2; exit 1; \
        fi; \
        cargo install --root /opt/as --path attestation-service --bin grpc-as --bin restful-as \
            --features "grpc-bin,restful-bin,tdx-self-attestation,${VERIFIER}" --locked ${TARGET_FLAG} && \
        cargo install --root /opt/as --path tools/tdx-workload --bin tdx-as-launch \
            --features as-launch --locked ${TARGET_FLAG}; \
    else \
        cargo install --root /opt/as --path attestation-service --bin grpc-as \
            --features "grpc-bin,${VERIFIER}" --locked ${TARGET_FLAG}; \
    fi

# ubuntu:24.04
FROM ubuntu@sha256:7c06e91f61fa88c08cc74f7e1b7c69ae24910d745357e0dfe1d2c0322aaf20f9
ARG ARCH=x86_64
ARG VERIFIER=all-verifier

LABEL org.opencontainers.image.source="https://github.com/confidential-containers/trustee/tree/main/attestation-service"

# Install Openssl Suites and libcurl (required by grpc-as on all architectures)
RUN apt-get update && apt-get install -y openssl libcurl4 && \
    apt install --reinstall ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/{apt,dpkg,cache,log} /tmp/* /var/tmp/*

# Install TDX Runtime Dependencies
ARG DCAP_VERSION=1_27_100
RUN if [ "${ARCH}" = "x86_64" ] && ( [ "${VERIFIER}" = "all-verifier" ] || [ "${VERIFIER}" = "tdx-verifier" ] ); \
    then apt-get update && apt-get install curl gnupg -y && \
    curl -L https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | gpg --dearmor --output /usr/share/keyrings/intel-sgx.gpg && \
    curl -sSLf https://download.01.org/intel-sgx/sgx_repo/ubuntu/apt_preference_files/99dcap_${DCAP_VERSION}_noble_custom_version.cfg | \
    tee -a /etc/apt/preferences.d/99dcap && \
    echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main' | tee /etc/apt/sources.list.d/intel-sgx.list && \
    apt-get update && \
    apt-get install --no-install-recommends -y libsgx-dcap-quote-verify && \
    apt-get remove curl gnupg -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/{apt,dpkg,cache,log} /tmp/* /var/tmp/*; fi

# Install TPM Runtime Dependencies
RUN if [ "${VERIFIER}" = "all-verifier" ] || [ "${VERIFIER}" = "az-snp-vtpm-verifier" ] || [ "${VERIFIER}" = "az-tdx-vtpm-verifier" ]; \
    then apt-get update && apt-get install libtss2-dev -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/{apt,dpkg,cache,log} /tmp/* /var/tmp/*; fi

COPY --from=builder /opt/as/bin/ /usr/local/bin/

VOLUME /opt/confidential-containers/attestation-service

CMD ["grpc-as", "--socket", "0.0.0.0:50004"]

EXPOSE 50004
