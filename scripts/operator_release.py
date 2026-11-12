#!/usr/bin/env python3
"""Local operator release workflow: build, freeze, sign through Brigalow policy, verify, publish.

Builds the archive/SBOM into a private staging directory beside --output, freezes the version 2
operator manifest, submits exactly one `brig sign --format raw` request through the normal
policy/approval/gate path, verifies the result against a separately pinned public key, then
publishes the complete directory with an atomic no-replace rename. It never retries, never
overwrites, never contacts anything other than the configured Brigalow server, and creates no
GitHub release. Signing credentials come only from BRIGALOW_TOKEN in the environment.
"""
import argparse
import ctypes
import ctypes.util
import errno
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

from package_release import package
from verify_release import COMMIT, MANIFEST, SIGNATURE, Rejected, operator_report, pinned_key, verify_operator_bundle

REQUEST = re.compile(r"\brequest ([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b")
AT_FDCWD, RENAME_NOREPLACE, RENAME_EXCL = -100, 1, 4


class Failed(Exception):
    def __init__(self, message, request=None):
        super().__init__(message)
        self.request = request


def publish_no_replace(source, target):
    """Atomically rename source to target only if target does not exist. No check-then-rename emulation."""
    libc = ctypes.CDLL(ctypes.util.find_library("c") or None, use_errno=True)
    src, dst = os.fsencode(source), os.fsencode(target)
    if sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        libc.renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        result = libc.renameat2(AT_FDCWD, src, AT_FDCWD, dst, RENAME_NOREPLACE)
    elif sys.platform == "darwin" and hasattr(libc, "renamex_np"):
        libc.renamex_np.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        result = libc.renamex_np(src, dst, RENAME_EXCL)
    else:
        raise Failed("no atomic no-replace rename primitive on this platform; refusing to publish")
    if result != 0:
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            raise Failed("output already exists; existing output was not modified")
        raise Failed(f"atomic no-replace publication unavailable or failed ({errno.errorcode.get(code, code)}); refusing to publish")


def fsync_path(path, directory=False):
    fd = os.open(path, os.O_RDONLY | (getattr(os, "O_DIRECTORY", 0) if directory else 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def sign(args, manifest, signature):
    """Run brig exactly once. Relay its request ID; never resubmit on any failure."""
    command = [str(args.brig), "sign", "--server", args.server, "--org", args.org, "--project", args.project,
               "--policy", args.policy, "--format", "raw", "--output", str(signature)]
    if args.ca_file:
        command += ["--ca-file", str(args.ca_file)]
    command.append(str(manifest))
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    seen, lines = [], []

    def relay(stream, sink):
        for line in stream:
            lines.append(line.rstrip("\n"))
            match = REQUEST.search(line)
            if match and not seen:
                seen.append(match.group(1))
                print(f"Brigalow request ID: {match.group(1)}", file=sys.stderr, flush=True)
            print(f"brig: {line.rstrip()}", file=sink, flush=True)

    readers = [threading.Thread(target=relay, args=(process.stdout, sys.stderr), daemon=True),
               threading.Thread(target=relay, args=(process.stderr, sys.stderr), daemon=True)]
    for reader in readers:
        reader.start()
    try:
        code = process.wait(timeout=args.timeout)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        for reader in readers:
            reader.join(timeout=5)
        raise Failed("signing did not finish before the timeout; outcome uncertain", seen[0] if seen else None) from None
    for reader in readers:
        reader.join(timeout=5)
    request = seen[0] if seen else None
    if code != 0:
        raise Failed("brig signing failed (denied, rejected, gate failure, expired or interrupted)", request)
    if request is None:
        raise Failed("brig reported success without a request ID; outcome uncertain")
    return request


def run(args, state):
    output = args.output
    if os.path.lexists(output):
        raise Failed("output already exists; refusing before any signing request")
    parent = output.parent.resolve()
    if not parent.is_dir():
        raise Failed("output parent directory does not exist")
    if args.expected_revision is not None and not COMMIT.fullmatch(args.expected_revision):
        raise Failed("expected revision must be a full lowercase hexadecimal commit ID")
    if not os.environ.get("BRIGALOW_TOKEN"):
        raise Failed("BRIGALOW_TOKEN is required")
    pinned_key(args.public_key, output)
    staging = Path(tempfile.mkdtemp(prefix=".brigalow-operator-", dir=parent))
    try:
        bundle, signing = staging/"bundle", staging/"signing"
        signing.mkdir(mode=0o700)
        revision = package(args.binaries, bundle, trust="operator", source=args.source)
        if args.expected_revision is not None and revision != args.expected_revision:
            raise Failed("checkout commit does not match --expected-revision; nothing was submitted")
        for name in os.listdir(bundle):
            os.chmod(bundle/name, 0o444)
        frozen = hashlib.sha256((bundle/MANIFEST).read_bytes()).hexdigest()
        print(f"Frozen operator manifest SHA-256 {frozen} for source commit {revision}", file=sys.stderr)
        try:
            request = sign(args, bundle/MANIFEST, signing/SIGNATURE)
        except Failed as error:
            state["request"] = error.request
            raise
        state["request"] = request
        if os.listdir(signing) != [SIGNATURE]:
            raise Failed("signing produced outputs outside the version 2 operator bundle "
                         "(timestamp/attestation outputs are not supported yet)", request)
        if hashlib.sha256((bundle/MANIFEST).read_bytes()).hexdigest() != frozen:
            raise Failed("manifest changed after it was frozen", request)
        os.rename(signing/SIGNATURE, bundle/SIGNATURE)
        os.chmod(bundle/SIGNATURE, 0o444)
        try:
            fingerprint, commit = verify_operator_bundle(bundle, args.public_key, revision, args.expected_key_sha256)
        except Rejected as error:
            raise Failed(f"signed bundle failed verification against the pinned key: {error}", request) from None
        for name in os.listdir(bundle):
            fsync_path(bundle/name)
        os.chmod(bundle, 0o755)
        fsync_path(bundle, directory=True)
        publish_no_replace(bundle, output)
        state["published"] = True
        fsync_path(parent, directory=True)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    print(operator_report(fingerprint, commit))
    print(f"Published {output} (request {request})")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binaries", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path, help="final bundle directory; must not exist")
    parser.add_argument("--public-key", required=True, type=Path,
                        help="separately pinned PEM public key for the release signing key (never from the bundle)")
    parser.add_argument("--expected-key-sha256", help="independently reviewed SHA-256 of the pinned key's DER SPKI")
    parser.add_argument("--expected-revision", help="require this full source commit ID")
    parser.add_argument("--source", type=Path, help="clean git checkout to package (default: this repository)")
    parser.add_argument("--brig", type=Path, default=Path("brig"))
    parser.add_argument("--server", required=True)
    parser.add_argument("--org", required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--policy", required=True, help="release-purpose policy name or ID")
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--timeout", type=float, default=360.0,
                        help="seconds to wait for brig (approval, gates, window) before failing as uncertain")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    state = {}
    try:
        run(args, state)
    except Exception as error:  # noqa: BLE001 - every failure must report the request ID and exit non-zero
        reason = str(error) if isinstance(error, (Failed, Rejected)) else f"unexpected {type(error).__name__}"
        outcome = ("The bundle was renamed into place but its durability is uncertain; verify it before use"
                   if state.get("published") else "No completed bundle was published")
        print(f"operator release failed: {reason}. {outcome}.", file=sys.stderr)
        request = state.get("request")
        if request:
            print(f"Query request {request} on the Brigalow server before any new attempt; "
                  "do not resubmit blindly. This command never retries.", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
