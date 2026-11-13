#!/usr/bin/env python3
"""Verify a release manifest signature and every payload digest against an independently pinned key.

`--mode lab` keeps the version 1 lab contract. `--mode operator` accepts only the strict
version 2 operator manifest. Neither mode makes a public-trust, CA or platform-trust decision.
"""
import argparse
import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

MAX_MANIFEST = 65536
MAX_SIGNATURE = 16384
MAX_KEY = 16384
MAX_ARTIFACTS = 2
MANIFEST, SIGNATURE = "manifest.json", "manifest.sig"
ARCHIVE, SBOM = "brigalow-linux.tar.gz", "sbom.cdx.json"
OPERATOR_FIELDS = {"version", "trust", "provenance", "source_commit", "digest_algorithm", "artifacts"}
ARTIFACT_FIELDS = {"role", "name", "sha256"}
ROLES = {"archive": ARCHIVE, "sbom": SBOM}
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
COMMIT = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
SHA256 = re.compile(r"[0-9a-f]{64}")
NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
NONBLOCK = getattr(os, "O_NONBLOCK", 0)
# Version 2 signature profile: the two exact DER SPKI encodings the PKCS#11 backend produces.
# P-256 ECDSA (id-ecPublicKey, prime256v1, uncompressed point) and RSA-3072 rsaEncryption with
# NULL parameters, a 384-byte modulus (top bit set) and exponent 65537. A structure check only.
P256_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004")
P256_LENGTH = 91
RSA3072_PREFIX = bytes.fromhex("308201a2300d06092a864886f70d0101010500" "0382018f00" "3082018a" "0282018100")
RSA3072_SUFFIX = bytes.fromhex("0203010001")
RSA3072_LENGTH = 422
UNCHECKED_WARNING = ("WARNING: --revision-unchecked: the source commit was declared by the signer and was not "
                     "compared with an expected revision, so an older validly signed release (a rollback) "
                     "would also pass.")


class Rejected(Exception):
    pass


def canonical(manifest):
    """The exact operator manifest encoding. Packaging writes these bytes; verification requires them."""
    return (json.dumps(manifest, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Rejected("duplicate JSON key in manifest")
        result[key] = value
    return result


def non_finite(_value):
    raise Rejected("non-finite number in manifest")


def parse_strict(data):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise Rejected("manifest is not UTF-8") from None
    try:
        return json.loads(text, object_pairs_hook=no_duplicates, parse_constant=non_finite)
    except json.JSONDecodeError:
        raise Rejected("manifest is not valid JSON") from None


def open_member(directory_fd, name):
    """Open a bundle entry relative to the bundle only; symlinks and non-regular files are refused."""
    try:
        fd = os.open(name, os.O_RDONLY | NOFOLLOW | NONBLOCK, dir_fd=directory_fd)
    except OSError:
        raise Rejected(f"{name} is not a readable regular file in the bundle (symlinks are rejected)") from None
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise Rejected(f"{name} is not a regular file")
    return fd


def read_member(directory_fd, name, limit):
    fd = open_member(directory_fd, name)
    with os.fdopen(fd, "rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise Rejected(f"{name} is too large")
    return data


def hash_member(directory_fd, name):
    fd = open_member(directory_fd, name)
    digest = hashlib.sha256()
    with os.fdopen(fd, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def supported_key(spki_der):
    """True only for the fixed version 2 profile: exact P-256 or RSA-3072/65537 SPKI encodings."""
    if len(spki_der) == P256_LENGTH and spki_der.startswith(P256_PREFIX):
        return True
    return (len(spki_der) == RSA3072_LENGTH and spki_der.startswith(RSA3072_PREFIX)
            and spki_der[len(RSA3072_PREFIX)] & 0x80 != 0 and spki_der.endswith(RSA3072_SUFFIX))


def pinned_key(path, bundle):
    """Normalise the separately pinned public key. A key inside the bundle cannot establish identity.

    Only P-256 ECDSA and RSA-3072 (exponent 65537) keys are accepted, before any signature check.
    """
    try:
        info = os.stat(path)
    except OSError:
        raise Rejected("pinned public key is missing") from None
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_KEY:
        raise Rejected("pinned public key must be a small regular file")
    resolved, root = Path(path).resolve(), Path(bundle).resolve()
    if resolved == root or root in resolved.parents:
        raise Rejected("pinned public key must not come from inside the bundle")
    result = subprocess.run(["openssl", "pkey", "-pubin", "-in", str(path), "-outform", "DER"], capture_output=True)
    if result.returncode or not result.stdout:
        raise Rejected("pinned key is not a PEM public key")
    if not supported_key(result.stdout):
        raise Rejected("unsupported key algorithm: operator version 2 accepts only a P-256 ECDSA or "
                       "RSA-3072 (exponent 65537) public key")
    return info, result.stdout


def verify_signature(manifest, signature, spki_der):
    """Independent OpenSSL check over the exact manifest bytes that are parsed afterwards."""
    pem = "-----BEGIN PUBLIC KEY-----\n" + "\n".join(
        re.findall(".{1,64}", base64.b64encode(spki_der).decode())) + "\n-----END PUBLIC KEY-----\n"
    with tempfile.TemporaryDirectory(prefix="brigalow-verify-") as scratch:
        key, sig = Path(scratch) / "key.pem", Path(scratch) / "manifest.sig"
        key.write_text(pem)
        sig.write_bytes(signature)
        result = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(key), "-signature", str(sig)],
                                input=manifest, capture_output=True)
    if result.returncode:
        raise Rejected("release manifest signature invalid for the pinned public key")


def operator_schema(manifest):
    if not isinstance(manifest, dict) or set(manifest) != OPERATOR_FIELDS:
        raise Rejected("unknown or missing manifest fields")
    if type(manifest["version"]) is not int or manifest["version"] != 2:
        raise Rejected("unsupported manifest version")
    if manifest["trust"] != "operator":
        raise Rejected("unsupported trust label")
    if manifest["provenance"] != "self-hosted":
        raise Rejected("unsupported provenance")
    if manifest["digest_algorithm"] != "sha256":
        raise Rejected("unsupported digest algorithm")
    if not isinstance(manifest["source_commit"], str) or not COMMIT.fullmatch(manifest["source_commit"]):
        raise Rejected("source commit must be a full lowercase hexadecimal commit ID")
    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != MAX_ARTIFACTS:
        raise Rejected("artifact count must be exactly one archive and one SBOM")
    roles, names = set(), set()
    for item in artifacts:
        if not isinstance(item, dict) or set(item) != ARTIFACT_FIELDS:
            raise Rejected("unknown or missing artifact fields")
        name = item["name"]
        if (not isinstance(name, str) or not NAME.fullmatch(name) or ".." in name
                or name in (MANIFEST, SIGNATURE)):
            raise Rejected("artifact name must be a plain basename")
        if item["role"] not in ROLES or item["role"] in roles or name in names:
            raise Rejected("artifact roles and names must be unique archive/SBOM entries")
        if ROLES[item["role"]] != name:
            raise Rejected("artifact name does not match the operator bundle layout")
        if not isinstance(item["sha256"], str) or not SHA256.fullmatch(item["sha256"]):
            raise Rejected("artifact digest must be lowercase SHA-256 hex")
        roles.add(item["role"])
        names.add(name)


def verify_operator_bundle(bundle, public_key, expected_revision, expected_key_sha256=None,
                           revision_unchecked=False):
    """Verify a version 2 operator bundle. Returns (pinned SPKI SHA-256, source commit).

    The caller must give the full expected source commit, or explicitly waive the comparison.
    """
    if (expected_revision is None) == (not revision_unchecked):
        raise Rejected("operator verification requires exactly one of an expected revision or an explicit "
                       "revision-unchecked waiver")
    bundle = Path(bundle)
    try:
        info = os.lstat(bundle)
    except OSError:
        raise Rejected("bundle directory is missing") from None
    if not stat.S_ISDIR(info.st_mode):
        raise Rejected("bundle must be a real directory, not a symlink")
    key_info, spki = pinned_key(public_key, bundle)
    fingerprint = hashlib.sha256(spki).hexdigest()
    if expected_key_sha256 is not None and expected_key_sha256.lower() != fingerprint:
        raise Rejected("pinned public key fingerprint mismatch")
    if expected_revision is not None and not COMMIT.fullmatch(expected_revision):
        raise Rejected("expected revision must be a full lowercase hexadecimal commit ID")
    directory_fd = os.open(bundle, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | NOFOLLOW)
    try:
        manifest_bytes = read_member(directory_fd, MANIFEST, MAX_MANIFEST)
        signature = read_member(directory_fd, SIGNATURE, MAX_SIGNATURE)
        verify_signature(manifest_bytes, signature, spki)
        manifest = parse_strict(manifest_bytes)
        operator_schema(manifest)
        if canonical(manifest) != manifest_bytes:
            raise Rejected("manifest is not in canonical operator encoding")
        artifacts = {item["name"]: item["sha256"] for item in manifest["artifacts"]}
        entries = os.listdir(directory_fd)
        if set(entries) != {MANIFEST, SIGNATURE, *artifacts} or len(entries) != len(artifacts) + 2:
            raise Rejected("unexpected or missing bundle files")
        for name in entries:
            entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if (entry.st_dev, entry.st_ino) == (key_info.st_dev, key_info.st_ino):
                raise Rejected("pinned public key must not come from inside the bundle")
        for name, digest in artifacts.items():
            if hash_member(directory_fd, name) != digest:
                raise Rejected(f"artifact digest mismatch: {name}")
    finally:
        os.close(directory_fd)
    if expected_revision is not None and manifest["source_commit"] != expected_revision:
        raise Rejected("source commit does not match the expected revision")
    return fingerprint, manifest["source_commit"]


def operator_report(fingerprint, commit, revision_checked=True):
    revision = (f"source commit {commit} matches the expected revision" if revision_checked else
                f"source commit {commit} was declared by the signer and NOT compared with an expected "
                "revision, so an older validly signed release (a rollback) would also pass")
    return ("Operator release verified: manifest signature is valid for the separately pinned public key "
            f"(SPKI SHA-256 {fingerprint}) and every payload digest matches. Declared origin: operator "
            f"(self-hosted); {revision}. This is cryptographic validity and a declared label "
            "only; it is not a public-trust, CA or platform-trust decision.")


def verify_operator(args):
    fingerprint, commit = verify_operator_bundle(args.directory, args.public_key, args.expected_revision,
                                                 args.expected_key_sha256, args.revision_unchecked)
    if args.revision_unchecked:
        print(UNCHECKED_WARNING, file=sys.stderr)
    print(operator_report(fingerprint, commit, revision_checked=not args.revision_unchecked))


def verify_lab(args):
    """Version 1 lab contract, unchanged: signature, lab label and listed payload digests."""
    directory = args.directory
    result = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(args.public_key), "-signature",
                             str(directory / SIGNATURE), str(directory / MANIFEST)], capture_output=True)
    if result.returncode:
        raise Rejected("release manifest signature invalid")
    manifest = json.loads((directory / MANIFEST).read_text())
    if not isinstance(manifest, dict) or manifest.get("version") != 1 or manifest.get("trust") != "lab":
        raise Rejected("not a version 1 lab manifest")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files or len(files) > 20:
        raise Rejected("invalid lab file list")
    for name, digest in files.items():
        if Path(name).name != name or name in [".", ".."]:
            raise Rejected("invalid artifact path")
        if hashlib.sha256((directory / name).read_bytes()).hexdigest() != digest:
            raise Rejected("artifact digest mismatch")
    print("Lab release signature and payload digests verified; identity depends on independently trusting the public key")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--mode", required=True, choices=["lab", "operator"],
                        help="lab: version 1 lab bundle; operator: strict version 2 operator bundle")
    parser.add_argument("--public-key", required=True, type=Path,
                        help="independently trusted PEM public key; operator mode refuses a key inside the bundle")
    revision = parser.add_mutually_exclusive_group()
    revision.add_argument("--expected-revision",
                          help="operator mode: the full source commit you expect, from an independently trusted "
                               "channel; operator mode requires this or --revision-unchecked")
    revision.add_argument("--revision-unchecked", action="store_true",
                          help="operator mode: knowingly skip the source commit comparison; the commit is then "
                               "only the signer's claim and a rollback to an older signed release also passes")
    parser.add_argument("--expected-key-sha256", help="operator mode: SHA-256 of the pinned key's DER SPKI")
    args = parser.parse_args()
    if args.mode == "lab" and (args.expected_revision or args.expected_key_sha256 or args.revision_unchecked):
        parser.error("--expected-revision, --revision-unchecked and --expected-key-sha256 apply to operator mode only")
    if args.mode == "operator" and args.expected_revision is None and not args.revision_unchecked:
        parser.error("operator mode requires --expected-revision <full commit> (or an explicit --revision-unchecked)")
    try:
        (verify_operator if args.mode == "operator" else verify_lab)(args)
    except Rejected as error:
        print(f"release verification failed: {error}", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
