"""Exercise the real operator CLI across process restarts; runtime network has no egress."""
import json
import os
import pathlib
import secrets
import subprocess
import sys
import tempfile
import uuid

binary = "/work/target/debug/brigalow-ca"
org, db_user = sys.argv[1:]
def run(*args, ok=True):
    result = subprocess.run(args, capture_output=True, timeout=60)
    if (result.returncode == 0) != ok:
        raise AssertionError("CA command failed expectation; diagnostics withheld")
    return result.stdout
with tempfile.TemporaryDirectory(prefix="brigalow-ca-") as temporary:
    root = pathlib.Path(temporary)
    os.chdir(root)
    (root / "tokens").mkdir()
    (root / "softhsm.conf").write_text(f"directories.tokendir = {root}/tokens\nobjectstore.backend = file\n")
    os.environ["SOFTHSM2_CONF"] = str(root / "softhsm.conf")
    pin, so_pin = secrets.token_hex(24), secrets.token_hex(24)
    run("softhsm2-util", "--init-token", "--free", "--label", "brigalow-ca-test", "--pin", pin, "--so-pin", so_pin)
    (root / "pin").write_text(pin)
    (root / "pin").chmod(0o600)
    (root / "runtime.toml").write_text(f'''mode = "production"
backend = "pkcs11"
backend_id = "ca-isolated-test"
hsm_module = "/usr/lib/softhsm/libsofthsm2.so"
hsm_token = "brigalow-ca-test"
hsm_pin_file = "{root}/pin"
db_host = "postgres"
db_user = "{db_user}"
db_password_file = "/test-secrets/app_password"
db_ca_file = "/test-secrets/ca.crt"
''')
    os.environ["BRIGALOW_CONFIG"] = str(root / "runtime.toml")
    run(binary, "init", "--subject", "CN=Ephemeral operator issuer", "--output", "issuer")
    run("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
        "-keyout", "root.key", "-out", "root.pem", "-days", "30", "-subj", "/CN=Ephemeral offline root",
        "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    pathlib.Path("issuer.ext").write_text("basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nextendedKeyUsage=codeSigning\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")
    run("openssl", "x509", "-req", "-in", "issuer/issuer.csr", "-CA", "root.pem", "-CAkey", "root.key",
        "-set_serial", "1", "-days", "20", "-extfile", "issuer.ext", "-out", "issuer.pem")
    for name in ["root", "issuer"]:
        run("openssl", "x509", "-in", name + ".pem", "-outform", "DER", "-out", name + ".der")
    profile = str(uuid.uuid4())
    pathlib.Path("ca.json").write_text(json.dumps({"org": org, "issuer_key_file": "issuer/issuer-key.json",
        "chain": ["issuer.der"], "anchors": ["root.der"], "profiles": [{"id": profile,
        "oid": "1.3.6.1.4.1.32473.1", "subject": "CN=Ephemeral daily profile"}]}))
    # The leaf key is generated for this test only. Production leaves originate from
    # the signing backend via its CSR API; this CLI never imports or exports keys.
    run("openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
        "-keyout", "leaf.key", "-out", "leaf.csr", "-subj", "/CN=Untrusted CSR name")
    args = [binary, "--ca", "ca.json"]
    run(*args, "issue", "--profile", profile, "--csr", "leaf.csr", "--output", "issued")
    # New process: same day cannot issue again, even for the same key.
    run(*args, "issue", "--profile", profile, "--csr", "leaf.csr", "--output", "duplicate", ok=False)
    day = str(int(__import__("time").time()) // 86400)
    run(*args, "export", "--profile", profile, "--day", day, "--output", "recovered")
    assert pathlib.Path("issued/leaf.der").read_bytes() == pathlib.Path("recovered/leaf.der").read_bytes()
    run("openssl", "x509", "-inform", "DER", "-in", "issued/leaf.der", "-out", "leaf.pem")
    run("openssl", "verify", "-purpose", "any", "-CAfile", "root.pem", "-untrusted", "issuer.pem", "leaf.pem")
    run(*args, "crl", "--output", "before.crl")
    run(*args, "revoke", "--profile", profile, "--day", day)
    run(*args, "crl", "--output", "after.crl")
    for name in ["before", "after"]:
        run("openssl", "crl", "-inform", "DER", "-in", name + ".crl", "-out", name + ".pem")
        run("openssl", "crl", "-in", name + ".pem", "-verify", "-CAfile", "issuer.pem", "-noout")
        run("openssl", "verify", "-purpose", "any", "-CAfile", "root.pem", "-untrusted", "issuer.pem",
            "-CRLfile", name + ".pem", "-crl_check", "leaf.pem", ok=(name == "before"))
    # A separate HSM audit key and ordinary append-only application DB role.
    (root / "ca.toml").write_text((root / "runtime.toml").read_text())
    ca_config = str(root / "ca.toml")
    runtime = (root / "runtime.toml").read_text().replace(db_user, "brigalow_runtime")
    (root / "runtime.toml").write_text(runtime)
    audit = "/work/target/debug/brigalow-audit"
    run(audit, "init", "--output", "audit-key")
    run(audit, "checkpoint", "--org", org, "--key", "audit-key/audit-key.json", "--output", "checkpoint")
    verify = ["/work/target/debug/brig", "audit", "verify", "checkpoint/audit.jsonl", "--checkpoint",
              "checkpoint/checkpoint.json", "--public-key", "audit-key/audit-public.der"]
    run(*verify)
    pathlib.Path("checkpoint.digest").write_bytes(__import__("hashlib").sha256(pathlib.Path("checkpoint/checkpoint.bytes").read_bytes()).digest())
    independent = ["openssl", "pkeyutl", "-verify", "-pubin", "-keyform", "DER", "-inkey", "audit-key/audit-public.der",
                   "-sigfile", "checkpoint/checkpoint.sig", "-in", "checkpoint.digest", "-pkeyopt", "digest:sha256"]
    run(*independent)
    pathlib.Path("checkpoint.digest").write_bytes(__import__("hashlib").sha256(b"tampered checkpoint").digest())
    run(*independent, ok=False)
    lines = pathlib.Path("checkpoint/audit.jsonl").read_bytes().splitlines(keepends=True)
    pathlib.Path("truncated.jsonl").write_bytes(b"".join(lines[:-1]))
    run(*[("truncated.jsonl" if arg == "checkpoint/audit.jsonl" else arg) for arg in verify], ok=False)

    # AT-AUD-03: atomic private bundle, read-only recovery and expected-head freshness.
    names = sorted(p.name for p in pathlib.Path("checkpoint").iterdir())
    assert names == ["COMPLETE.json", "audit.jsonl", "checkpoint.bytes", "checkpoint.json", "checkpoint.sig"]
    assert pathlib.Path("checkpoint").stat().st_mode & 0o7777 == 0o700
    assert not [p for p in root.iterdir() if p.name.startswith(".brigalow-stage-")]
    record = json.loads(pathlib.Path("checkpoint/checkpoint.json").read_bytes())["checkpoint"]
    seq = str(record["seq"])
    head = f"{record['org_id']}:{seq}:{record['entry_hash']}"
    # Duplicate scheduling of the same head is refused without signing again.
    run(audit, "checkpoint", "--org", org, "--key", "audit-key/audit-key.json", "--output", "repeat", ok=False)
    assert not pathlib.Path("repeat").exists()
    # Recovery needs no key backend: this config has no HSM module, token or PIN at all.
    no_hsm = [line for line in runtime.splitlines() if not line.startswith(("backend", "hsm_"))]
    (root / "recover.toml").write_text("\n".join(no_hsm + ['backend = "disabled"']) + "\n")
    os.environ["BRIGALOW_CONFIG"] = str(root / "recover.toml")
    run(audit, "checkpoint", "--org", org, "--key", "audit-key/audit-key.json", "--output", "nohsm", ok=False)
    assert not pathlib.Path("nohsm").exists()
    recover = [audit, "recover", "--org", org, "--seq", seq, "--public-key", "audit-key/audit-public.der"]
    run(*recover, "--output", "audit-recovered")
    for name in names:
        assert pathlib.Path("checkpoint", name).read_bytes() == pathlib.Path("audit-recovered", name).read_bytes(), name
    # Onto an existing complete directory: verified byte-for-byte, never replaced.
    run(*recover, "--output", "checkpoint")
    pathlib.Path("different").mkdir()
    run(*recover, "--output", "different", ok=False)
    assert list(pathlib.Path("different").iterdir()) == []
    absent = subprocess.run([audit, "recover", "--org", org, "--seq", str(int(seq) + 100000), "--public-key",
                             "audit-key/audit-public.der", "--output", "absent"], capture_output=True, timeout=60)
    assert absent.returncode != 0 and b"does not show that the HSM did not sign" in absent.stderr
    run("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "other.key")
    run("openssl", "ec", "-in", "other.key", "-pubout", "-outform", "DER", "-out", "other.der")
    run(audit, "recover", "--org", org, "--seq", seq, "--public-key", "other.der", "--output", "wrong-key", ok=False)
    run(audit, "recover", "--org", str(uuid.uuid4()), "--seq", seq, "--public-key", "audit-key/audit-public.der",
        "--output", "wrong-org", ok=False)
    for name in ["absent", "wrong-key", "wrong-org"]:
        assert not pathlib.Path(name).exists()
    os.environ["BRIGALOW_CONFIG"] = str(root / "runtime.toml")
    pathlib.Path("recovered.digest").write_bytes(__import__("hashlib").sha256(pathlib.Path("audit-recovered/checkpoint.bytes").read_bytes()).digest())
    run("openssl", "pkeyutl", "-verify", "-pubin", "-keyform", "DER", "-inkey", "audit-key/audit-public.der",
        "-sigfile", "audit-recovered/checkpoint.sig", "-in", "recovered.digest", "-pkeyopt", "digest:sha256")
    recovered = ["/work/target/debug/brig", "audit", "verify", "audit-recovered/audit.jsonl", "--checkpoint",
                 "audit-recovered/checkpoint.json", "--public-key", "audit-key/audit-public.der"]
    assert b"freshness unknown" in run(*recovered)
    assert b"expected head" in run(*recovered, "--expected-head", head)
    # A newer checkpoint makes the recovered (older, valid) one stale against the retained head.
    os.environ["BRIGALOW_CONFIG"] = ca_config
    run(*args, "crl", "--output", "advance.crl")  # appends audit events, advancing the head
    os.environ["BRIGALOW_CONFIG"] = str(root / "runtime.toml")
    run(audit, "checkpoint", "--org", org, "--key", "audit-key/audit-key.json", "--output", "newer")
    newer = json.loads(pathlib.Path("newer/checkpoint.json").read_bytes())["checkpoint"]
    newer_head = f"{newer['org_id']}:{newer['seq']}:{newer['entry_hash']}"
    run(*recovered, "--expected-head", newer_head, ok=False)

print("CA operator CLI: HSM issuer survives restart, duplicate day refused, persisted outputs recovered, CRL revocation verified; audit checkpoint recovered read-only and freshness-checked")
