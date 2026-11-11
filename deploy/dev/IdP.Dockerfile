FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-cryptography \
    && rm -rf /var/lib/apt/lists/*
COPY test_idp.py /test_idp.py
CMD ["python3", "/test_idp.py"]
