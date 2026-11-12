# Vendor HSM provider/configuration must be added by the operator; no software fallback.
FROM rust:1-bookworm@sha256:e6f2cff35d0f309acf8433b4f05878ed77092602c5065cc81801177da0bb3a9c AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked -p brigalow-server -p brig

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/brigalow-server /src/target/release/brigalow-admin /src/target/release/brigalow-audit /src/target/release/brigalow-ca /src/target/release/brig /usr/local/bin/
COPY LICENSE /usr/share/doc/brigalow/LICENSE
USER 10001:10001
ENV BRIGALOW_MODE=production BRIGALOW_BIND=0.0.0.0:8080
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=8s --start-period=10s --retries=3 CMD curl --fail --silent --max-time 4 http://127.0.0.1:8080/healthz >/dev/null || exit 1
CMD ["/usr/local/bin/brigalow-server"]

# Disposable CI/local qualification only. Never publish this target as production.
FROM runtime AS test-runtime
USER 0
RUN apt-get update && apt-get install -y --no-install-recommends softhsm2 && rm -rf /var/lib/apt/lists/*
USER 10001:10001

# Default build excludes the software HSM test dependency.
FROM runtime AS production
