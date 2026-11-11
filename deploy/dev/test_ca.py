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
print("CA operator CLI: HSM issuer survives restart, duplicate day refused, persisted outputs recovered, CRL revocation verified")
