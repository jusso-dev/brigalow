FROM golang:1.25-bookworm AS cosign
RUN go install -tags=pkcs11key github.com/sigstore/cosign/v2/cmd/cosign@v2.6.0

FROM rust:1-bookworm AS tools-base
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 openssl opensc softhsm2 osslsigncode libengine-pkcs11-openssl \
    gnupg gnupg-pkcs11-scd default-jre-headless gcc-mingw-w64-x86-64 curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=cosign /go/bin/cosign /usr/local/bin/cosign
RUN curl --fail --silent --show-error --location https://github.com/ebourg/jsign/releases/download/7.6/jsign-7.6.jar -o /usr/local/lib/jsign.jar \
    && echo '6cf58aa080e7ff82656f320cff8d4a3bff30408df8766806dcba3740dd839fa5  /usr/local/lib/jsign.jar' | sha256sum --check

FROM tools-base AS tools-build
WORKDIR /work
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY deploy/dev ./deploy/dev
COPY examples ./examples
RUN cargo build --locked -p brig -p brigalow-pkcs11 -p brigalow-server --bin brigalow-ca --bin brig --lib \
    && cargo test --locked -p brigalow-server --test identity --features tool-tests --no-run \
    && find target/debug/deps -maxdepth 1 -type f -name 'identity-*' -executable -exec cp {} /tool-tests \;
FROM tools-base
WORKDIR /work
RUN mkdir -p /work/crates/brigalow-server
COPY --from=tools-build /tool-tests /tool-tests
COPY --from=tools-build /work/target/debug/libbrigalow_pkcs11.so /work/target/debug/libbrigalow_pkcs11.so
COPY --from=tools-build /work/target/debug/brig /work/target/debug/brig
COPY --from=tools-build /work/target/debug/brigalow-ca /work/target/debug/brigalow-ca
COPY deploy/dev ./deploy/dev
COPY actions ./actions
ENTRYPOINT ["/tool-tests", "tool", "--nocapture", "--test-threads=1"]
