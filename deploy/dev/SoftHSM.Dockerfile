FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends softhsm2 opensc openssl \
    && rm -rf /var/lib/apt/lists/*
# PKCS#11 is an in-process library, not a network service. Phase 2 will run
# its integration client inside this image with the token store mounted.
CMD ["softhsm2-util", "--show-slots"]
