FROM rust:1-bookworm AS build
WORKDIR /work
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo test --locked -p brigalow-crypto --test custody --features pkcs11-tests --no-run \
    && find target/debug/deps -maxdepth 1 -type f -name 'custody-*' -executable -exec cp {} /crypto-tests \;
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends softhsm2 opensc openssl python3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /crypto-tests /crypto-tests
COPY deploy/dev/hsm_test.py /hsm_test.py
CMD ["python3", "/hsm_test.py"]
