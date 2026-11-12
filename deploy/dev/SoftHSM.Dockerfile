FROM rust:1-bookworm AS build
WORKDIR /work
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY deploy/dev/copy_test_binary.py /usr/local/bin/copy_test_binary.py
RUN cargo test --locked -p brigalow-crypto --test custody --features pkcs11-tests --no-run --message-format=json-render-diagnostics > /tmp/custody.json \
    && python3 /usr/local/bin/copy_test_binary.py custody /crypto-tests < /tmp/custody.json
RUN cargo test --locked -p brigalow-crypto --test private_ca --features pkcs11-tests --no-run --message-format=json-render-diagnostics > /tmp/private_ca.json \
    && python3 /usr/local/bin/copy_test_binary.py private_ca /ca-tests < /tmp/private_ca.json
RUN cargo test --locked -p brigalow-crypto --test recovery --features pkcs11-tests --no-run --message-format=json-render-diagnostics > /tmp/recovery.json \
    && python3 /usr/local/bin/copy_test_binary.py recovery /recovery-tests < /tmp/recovery.json
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends softhsm2 opensc openssl python3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /crypto-tests /crypto-tests
COPY --from=build /ca-tests /ca-tests
COPY --from=build /recovery-tests /recovery-tests
COPY deploy/dev/hsm_recover.py /hsm_recover.py
COPY deploy/dev/hsm_test.py /hsm_test.py
CMD ["python3", "/hsm_test.py"]
