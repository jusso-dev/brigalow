FROM rust:1-bookworm AS build
WORKDIR /work
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo test --locked -p brigalow-crypto --test custody --features pkcs11-tests --no-run \
    && find target/debug/deps -maxdepth 1 -type f -name 'custody-*' -executable -exec cp {} /crypto-tests \;
RUN cargo test --locked -p brigalow-crypto --test private_ca --features pkcs11-tests --no-run \
    && find target/debug/deps -maxdepth 1 -type f -name 'private_ca-*' -executable -exec cp {} /ca-tests \;
RUN cargo test --locked -p brigalow-crypto --test recovery --features pkcs11-tests --no-run \
    && find target/debug/deps -maxdepth 1 -type f -name 'recovery-*' -executable -exec cp {} /recovery-tests \;
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends softhsm2 opensc openssl python3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /crypto-tests /crypto-tests
COPY --from=build /ca-tests /ca-tests
COPY --from=build /recovery-tests /recovery-tests
COPY deploy/dev/hsm_recover.py /hsm_recover.py
COPY deploy/dev/hsm_test.py /hsm_test.py
CMD ["python3", "/hsm_test.py"]
