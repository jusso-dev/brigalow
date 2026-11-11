#!/usr/bin/env python3
"""Generate public parser seeds and run bounded libFuzzer targets. No fixtures contain keys."""
import json
import os
import pathlib
import subprocess
import tempfile
import uuid

root = pathlib.Path(__file__).resolve().parents[1]
for target in ["requests", "certificates", "audit"]:
    (root / "fuzz/corpus" / target).mkdir(parents=True, exist_ok=True)
def seed(target, name, data):
    (root / "fuzz/corpus" / target / name).write_bytes(data)
seed("requests", "submission", json.dumps(dict(request_id=str(uuid.uuid4()), policy=str(uuid.uuid4()), digest_alg="sha256", digest=[0]*32, artifact_name="fuzz", format="raw", metadata={})).encode())
seed("audit", "entry", json.dumps([dict(seq=1, org_id=str(uuid.uuid4()), at=1, actor="fuzz", action="fuzz", subject="fuzz", details={}, prev_hash="0"*64, entry_hash="0"*64)]).encode())
with tempfile.TemporaryDirectory(prefix="brigalow-fuzz-") as temporary:
    d = pathlib.Path(temporary)
    result = subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", str(d/"key"), "-out", str(d/"certificate"), "-outform", "DER", "-days", "1", "-subj", "/CN=Ephemeral fuzz seed"], capture_output=True)
    assert result.returncode == 0, "cannot generate public certificate seed"
    seed("certificates", "certificate", (d/"certificate").read_bytes())
seconds = int(os.environ.get("BRIGALOW_FUZZ_SECONDS", "15"))
assert 1 <= seconds <= 300
fuzz_env = os.environ.copy()
nightly_cargo = subprocess.check_output(["rustup", "which", "--toolchain", "nightly", "cargo"], text=True).strip()
nightly_rustc = subprocess.check_output(["rustup", "which", "--toolchain", "nightly", "rustc"], text=True).strip()
fuzz_env.update(CARGO=nightly_cargo, RUSTC=nightly_rustc, RUSTUP_TOOLCHAIN="nightly",
                PATH=str(pathlib.Path(nightly_cargo).parent) + os.pathsep + fuzz_env["PATH"])
for target in ["requests", "certificates", "audit"]:
    subprocess.run(["rustup", "run", "nightly", "cargo", "fuzz", "run", target, "--", f"-max_total_time={seconds}", "-max_len=65536", "-timeout=5", "-rss_limit_mb=2048"], cwd=root, env=fuzz_env, check=True)
