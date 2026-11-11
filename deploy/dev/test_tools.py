"""Independent native tool acceptance. Runs only in the disposable Linux container."""
import base64
import hashlib
import os
import pathlib
import re
import subprocess
import sys

root = pathlib.Path(sys.argv[1])
ca = sys.argv[2]
module = "/work/target/debug/libbrigalow_pkcs11.so"
uri = "pkcs11:token=Brigalow;object=brigalow;type=private"
os.chdir(root)
os.environ["PKCS11_MODULE_PATH"] = module
os.environ["COSIGN_PKCS11_MODULE_PATH"] = module

def run(*args, ok=True, data=None):
    result = subprocess.run(args, input=data, capture_output=True)
    if not ok and result.returncode == 0:
        raise AssertionError("negative tool check unexpectedly succeeded")
    if ok and result.returncode:
        raise AssertionError(f"{args[0]} failed: {result.stdout.decode(errors='replace')} {result.stderr.decode(errors='replace')}")
    return result.stdout

blob = b"Brigalow generated tool acceptance artifact\n" * 1024
pathlib.Path("artifact.bin").write_bytes(blob)
pathlib.Path("digest").write_bytes(hashlib.sha256(blob).digest())
run("openssl", "pkey", "-pubin", "-inform", "DER", "-in", "public.der", "-out", "public.pem")
run("openssl", "pkeyutl", "-engine", "pkcs11", "-keyform", "engine", "-inkey", uri,
    "-sign", "-pkeyopt", "digest:sha256", "-in", "digest", "-out", "openssl.sig")
run("openssl", "pkeyutl", "-verify", "-pubin", "-inkey", "public.pem", "-sigfile", "openssl.sig",
    "-in", "digest", "-pkeyopt", "digest:sha256")
pathlib.Path("sha1").write_bytes(hashlib.sha1(blob).digest())
run("openssl", "pkeyutl", "-engine", "pkcs11", "-keyform", "engine", "-inkey", uri,
    "-sign", "-pkeyopt", "digest:sha1", "-in", "sha1", "-out", "forbidden.sig", ok=False)
run("pkcs11-tool", "--module", module, "--read-object", "--type", "privkey", ok=False)

pathlib.Path("hello.c").write_text("int main(void) { return 0; }\n")
run("x86_64-w64-mingw32-gcc", "hello.c", "-o", "hello.exe")
run("osslsigncode", "sign", "-pkcs11module", module,
    "-certs", "leaf.pem", "-key", uri, "-h", "sha256", "-in", "hello.exe", "-out", "osslsigncode.exe")
run("osslsigncode", "verify", "-CAfile", ca, "-in", "osslsigncode.exe")

pathlib.Path("sunpkcs11.conf").write_text(f"name = Brigalow\nlibrary = {module}\nslot = 1\n")
pathlib.Path("jsign.exe").write_bytes(pathlib.Path("hello.exe").read_bytes())
run("java", "-jar", "/usr/local/lib/jsign.jar", "--storetype", "PKCS11", "--keystore", "sunpkcs11.conf",
    "--alias", "brigalow", "--alg", "SHA-256", "jsign.exe")
run("osslsigncode", "verify", "-CAfile", ca, "-in", "jsign.exe")

cosign_uri = f"pkcs11:token=Brigalow;object=brigalow?module-path={module}"
run("cosign", "sign-blob", "--key", cosign_uri, "--tlog-upload=false", "--output-signature", "cosign.sig", "artifact.bin")
run("cosign", "verify-blob", "--key", "public.pem", "--signature", "cosign.sig", "--insecure-ignore-tlog", "artifact.bin")

# GPG uses its standard PKCS#11 smartcard bridge; private keys stay remote.
home = root / "gnupg"
home.mkdir(mode=0o700)
os.environ["GNUPGHOME"] = str(home)
(home / "gpg-agent.conf").write_text("scdaemon-program /usr/bin/gnupg-pkcs11-scd\nallow-loopback-pinentry\n")
(home / "gnupg-pkcs11-scd.conf").write_text(f"providers brigalow\nprovider-brigalow-library {module}\n")
try:
    run("gpg", "--batch", "--card-status")
    learned = run("gpg-connect-agent", "SCD LEARN", "/bye").decode()
    grips = re.findall(r"^S KEYPAIRINFO ([0-9A-F]{40}) ", learned, re.MULTILINE)
    assert len(set(grips)) == 1, "expected one existing remote card key"
    registration = (f"Key-Type: RSA\nKey-Grip: {grips[0]}\nKey-Usage: sign\n"
                    "Name-Real: Brigalow ephemeral tool test\nExpire-Date: 1d\n%commit\n")
    run("gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
        "--cert-digest-algo", "SHA256", "--generate-key", data=registration.encode())
    run("gpg", "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", "", "--digest-algo", "SHA256",
        "--output", "gpg.sig", "--detach-sign", "artifact.bin")
    run("gpg", "--verify", "gpg.sig", "artifact.bin")
finally:
    subprocess.run(["gpgconf", "--kill", "all"], capture_output=True)
print("AT-INT-01: OpenSSL, osslsigncode, jsign, cosign and GPG verified remote signatures")

# Exercise the release workflow's actual local lab control-plane signature.
import tomllib
config = tomllib.loads(pathlib.Path(os.environ["BRIGALOW_PKCS11_CONFIG"]).read_text())
release = pathlib.Path(os.environ["BRIGALOW_TEST_RELEASE_DIR"])
run("/work/target/debug/brig", "sign", "--server", config["server"], "--org", config["org"],
    "--project", config["project"], "--policy", config["policy"], "--ca-file", config["ca_file"],
    "--format", "raw", "--output", str(release/"manifest.sig"), str(release/"manifest.json"))
(release/"lab-public.pem").write_bytes(pathlib.Path("public.pem").read_bytes())
run("python3", "/work/scripts/verify_release.py", str(release), "--public-key", str(release/"lab-public.pem"))
manifest = (release/"manifest.json").read_bytes()
(release/"manifest.json").write_bytes(manifest+b" ")
run("python3", "/work/scripts/verify_release.py", str(release), "--public-key", str(release/"lab-public.pem"), ok=False)
(release/"manifest.json").write_bytes(manifest)
