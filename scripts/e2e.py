#!/usr/bin/env python3
"""Disposable Compose acceptance harness; generated secrets never leave temporary files."""
import argparse
import os
from pathlib import Path
import secrets
import subprocess
import tempfile

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
    try:
        run(compose + ["up", "-d", "--build", "--wait", "--wait-timeout", "120"])
        address = run(compose + ["port", "postgres", "5432"], capture_output=True, text=True).stdout.strip()
        env["BRIGALOW_TEST_DB_PORT"] = address.rsplit(":", 1)[1]
        env["BRIGALOW_TEST_ADMIN_PASSWORD_FILE"] = str(Path(directory) / "postgres_password")
        env["BRIGALOW_TEST_APP_PASSWORD_FILE"] = str(Path(directory) / "app_password")
        run(["cargo", "test", "--locked", "--workspace", "--features", "integration"])
        run(compose + ["exec", "-T", "softhsm", "softhsm2-util", "--show-slots"])
    finally:
        # Only this harness's uniquely named resources. Data lives in tmpfs.
        subprocess.run(compose + ["down", "--remove-orphans", "--rmi", "local"], cwd=root, env=env, check=True)
