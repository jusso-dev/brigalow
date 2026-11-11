#!/usr/bin/env python3
"""Disposable Compose acceptance harness; generated secrets never leave temporary files."""
import argparse
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import json
import time
import urllib.request
import urllib.error

parser = argparse.ArgumentParser()
parser.add_argument("--context", required=True, help="Explicit Docker context, e.g. orbstack or default (CI)")
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
project = "brigalow-test-" + secrets.token_hex(6)
with tempfile.TemporaryDirectory(prefix="brigalow-test-") as directory:
    env = os.environ.copy()
    env["BRIGALOW_TEST_SECRETS"] = directory
    for name in ("postgres_password", "app_password", "hsm_pin"):
        path = Path(directory) / name
        path.touch(mode=0o600)
        path.write_text(secrets.token_hex(24))
    compose = ["docker", "--context", args.context, "compose", "-p", project,
               "-f", str(root / "deploy/dev/compose.yml")]
    def run(command, **kwargs):
        return subprocess.run(command, cwd=root, env=env, check=True, **kwargs)
    def openssl(*arguments):
        run(["openssl", *arguments], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ca_key, ca_cert = str(Path(directory)/"ca.key"), str(Path(directory)/"ca.crt")
    server_key, server_cert = str(Path(directory)/"server.key"), str(Path(directory)/"server.crt")
    csr, extensions = str(Path(directory)/"server.csr"), Path(directory)/"server.ext"
    openssl("req", "-x509", "-newkey", "rsa:3072", "-nodes", "-keyout", ca_key, "-out", ca_cert,
            "-days", "1", "-subj", "/CN=Brigalow ephemeral test CA",
            "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    openssl("req", "-new", "-newkey", "rsa:3072", "-nodes", "-keyout", server_key,
            "-out", csr, "-subj", "/CN=localhost")
    extensions.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1,DNS:localhost\n")
    openssl("x509", "-req", "-in", csr, "-CA", ca_cert, "-CAkey", ca_key, "-CAcreateserial",
            "-out", server_cert, "-days", "1", "-extfile", str(extensions))
    env["BRIGALOW_TEST_DB_CA_FILE"] = ca_cert
    try:
        run(compose + ["up", "-d", "--build", "--wait", "--wait-timeout", "120"])
        address = run(compose + ["port", "postgres", "5432"], capture_output=True, text=True).stdout.strip()
        env["BRIGALOW_TEST_DB_PORT"] = address.rsplit(":", 1)[1]
        env["BRIGALOW_TEST_ADMIN_PASSWORD_FILE"] = str(Path(directory) / "postgres_password")
        env["BRIGALOW_TEST_APP_PASSWORD_FILE"] = str(Path(directory) / "app_password")
        run(["cargo", "test", "--locked", "--workspace", "--features", "integration"])
        # Independently invoke the public CLI on the database-backed export.
        export = Path(directory)/"audit.jsonl"
        verify = ["cargo", "run", "--locked", "--quiet", "-p", "brig", "--", "audit", "verify"]
        run(verify + [str(export)])
        lines = export.read_text().splitlines()
        tampered = lines.copy()
        tampered[499] = tampered[499].replace("original", "Original", 1)
        for name, data, expected in [("changed",tampered,"seq 500"), ("deleted",lines[:9]+lines[10:],"seq 10")]:
            path = Path(directory)/(name+".jsonl")
            path.write_text("\n".join(data)+"\n")
            result = subprocess.run(verify + [str(path)], cwd=root, env=env, capture_output=True, text=True)
            assert result.returncode != 0 and expected in result.stderr, "AT-AUD-01 tampering escaped detection"
        print("AT-AUD-01: database export, 1000 entries, mutation and deletion verified by brig")
        run(["cargo", "build", "--locked", "-p", "brigalow-server"])
        metadata = json.loads(run(["cargo", "metadata", "--no-deps", "--format-version", "1"], capture_output=True, text=True).stdout)
        server = str(Path(metadata["target_directory"]) / "debug/brigalow-server")
        server_env = {k: v for k, v in env.items() if not k.startswith("BRIGALOW_")}
        server_env.update({"BRIGALOW_MODE": "lab", "BRIGALOW_BIND": "127.0.0.1:0",
                           "BRIGALOW_DB_HOST": "127.0.0.1", "BRIGALOW_DB_PORT": env["BRIGALOW_TEST_DB_PORT"],
                           "BRIGALOW_DB_NAME": "brigalow", "BRIGALOW_DB_USER": "brigalow_runtime",
                           "BRIGALOW_DB_CA_FILE": env["BRIGALOW_TEST_DB_CA_FILE"],
                           "BRIGALOW_DB_PASSWORD": (Path(directory)/"app_password").read_text(),
                           "BRIGALOW_HSM_PIN": (Path(directory)/"hsm_pin").read_text()})
        log_path = Path(directory)/"server.log"
        with log_path.open("w+") as log:
            process = subprocess.Popen([server], cwd=root, env=server_env, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 15
                address = None
                while time.monotonic() < deadline:
                    text = log_path.read_text()
                    if "address=" in text:
                        address = text.split("address=", 1)[1].split()[0]
                        break
                    if process.poll() is not None:
                        raise AssertionError("server failed to start; diagnostics withheld to protect secrets")
                    time.sleep(0.05)
                assert address, "server readiness timeout"
                # Explicit no-proxy client: every HTTP request stays on loopback.
                client = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                with client.open("http://" + address + "/healthz", timeout=5) as response:
                    body = response.read().decode()
                    assert response.status == 200
                    assert json.loads(body) == {"status":"ok", "mode":"lab", "signing_available":False}
                try:
                    client.open("http://" + address + "/debug", timeout=5)
                    raise AssertionError("debug endpoint must not exist")
                except urllib.error.HTTPError as error:
                    assert error.code == 404
                    body += error.read().decode()
                # Exercise runtime health failure after startup, with real credentials loaded.
                run(compose + ["stop", "postgres"])
                try:
                    client.open("http://" + address + "/healthz", timeout=8)
                    raise AssertionError("health must fail when the database is unavailable")
                except urllib.error.HTTPError as error:
                    assert error.code == 503
                    body += error.read().decode()
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            assert process.returncode == 0, "server did not shut down gracefully"
            output = log_path.read_text() + body
            for name in ("app_password", "hsm_pin"):
                assert (Path(directory)/name).read_text() not in output, "AT-OPS-01 secret disclosure"
            assert "LAB MODE" in output
        print("AT-OPS-01: live health/debug responses and server logs contain no generated secrets")
        run(compose + ["exec", "-T", "softhsm", "softhsm2-util", "--show-slots"])
    finally:
        # Only this harness's uniquely named resources. Data lives in tmpfs.
        subprocess.run(compose + ["down", "--remove-orphans", "--rmi", "local"], cwd=root, env=env, check=True)
