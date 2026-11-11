FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 openssl \
    && rm -rf /var/lib/apt/lists/*
COPY test_tsa.py /test_tsa.py
CMD ["python3", "/test_tsa.py"]
