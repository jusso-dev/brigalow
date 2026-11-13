#!/usr/bin/env python3
"""Local operator release workflow: build, freeze, sign through Brigalow policy, verify, publish.

Builds the archive/SBOM into a private staging directory beside --output, freezes the version 2
operator manifest, submits exactly one `brig sign --format raw` request through the normal
policy/approval/gate path, verifies the result against a separately pinned public key, then
publishes the complete directory with an atomic no-replace rename. It never retries, never
overwrites, never contacts anything other than the configured Brigalow server, and creates no
GitHub release. Signing credentials come only from BRIGALOW_TOKEN in the environment.

--expected-revision is required: the operator states the commit they intend to release. SIGINT,
SIGTERM and SIGHUP stop and reap brig, remove staging and report the request ID as an uncertain
outcome. Leftover staging from earlier runs is reported and left in place.
"""
import argparse
import ctypes
import ctypes.util
import errno
import fcntl
import hashlib
import math
import os
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import threading
from pathlib import Path

from package_release import package
from verify_release import COMMIT, MANIFEST, SIGNATURE, Rejected, operator_report, pinned_key, verify_operator_bundle

REQUEST = re.compile(r"\brequest ([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b")
RENAME_NOREPLACE, RENAME_EXCL = 1, 4
STAGE_PREFIX = ".brigalow-operator-"
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | getattr(os, "O_NONBLOCK", 0)
SIGNALS = tuple(getattr(signal, name) for name in ("SIGINT", "SIGTERM", "SIGHUP") if hasattr(signal, name))
MAX_TIMEOUT = 86400  # brig accepts up to 604800 s, so the margin below always fits.
# brig is told to keep polling this long after --timeout, so this command's own deadline always
# fires first and a long approval is reported as an uncertain outcome, never as a plain failure.
BRIG_WAIT_MARGIN = 60
# brig messages meaning the request was submitted but its final state is unknown. Matched so a
# brig-side poll deadline or lost status connection is never reported as a plain failure.
UNCERTAIN = ("approval still pending", "signing request interrupted", "cannot retrieve request status")


class Failed(Exception):
    def __init__(self, message, request=None):
        super().__init__(message)
        self.request = request


class Interrupted(BaseException):
    """Raised in the main thread by SIGINT, SIGTERM or SIGHUP."""


class Deferred:
    """Hold SIGINT/SIGTERM/SIGHUP while a resource is created and recorded in `state`, so an
    interruption can never leave an unrecorded brig child or staging directory behind."""

    def __enter__(self):
        signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)

    def __exit__(self, *_):
        signal.pthread_sigmask(signal.SIG_UNBLOCK, SIGNALS)


def interrupt(signum, _frame):
    # Later signals are ignored so stopping brig and removing staging run once, to completion.
    for number in SIGNALS:
        signal.signal(number, signal.SIG_IGN)
    raise Interrupted(signal.Signals(signum).name)


def publish_no_replace(source_fd, source, target_fd, target):
    """Atomically rename source to target, each relative to a directory fd, only if target does not
    exist. No check-then-rename emulation."""
    libc = ctypes.CDLL(ctypes.util.find_library("c") or None, use_errno=True)
    src, dst = os.fsencode(source), os.fsencode(target)
    if sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        libc.renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        result = libc.renameat2(source_fd, src, target_fd, dst, RENAME_NOREPLACE)
    elif sys.platform == "darwin" and hasattr(libc, "renameatx_np"):
        libc.renameatx_np.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        result = libc.renameatx_np(source_fd, src, target_fd, dst, RENAME_EXCL)
    else:
        raise Failed("no atomic no-replace rename primitive on this platform; refusing to publish")
    if result != 0:
        code = ctypes.get_errno()
        if code in (errno.EEXIST, errno.ENOTEMPTY):
            raise Failed("output already exists; existing output was not modified")
        raise Failed(f"atomic no-replace publication unavailable or failed ({errno.errorcode.get(code, code)}); refusing to publish")


def sync_fd(fd):
    """Flush to stable storage. On macOS fsync(2) leaves data in the drive cache, so use F_FULLFSYNC
    and fail closed if the filesystem refuses it."""
    try:
        if hasattr(fcntl, "F_FULLFSYNC"):
            fcntl.fcntl(fd, fcntl.F_FULLFSYNC)
        else:
            os.fsync(fd)
    except OSError as error:
        raise Failed(f"cannot flush to stable storage ({errno.errorcode.get(error.errno, error.errno)})") from None


def same_entry(directory_fd, name, fd):
    """True if `name` in `directory_fd` is still the object open as `fd` (not swapped or replaced)."""
    try:
        entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError:
        return False
    opened = os.fstat(fd)
    return (entry.st_dev, entry.st_ino) == (opened.st_dev, opened.st_ino)


def same_path(path, fd):
    """True if `path` (not following a final symlink) is the object open as `fd`."""
    try:
        entry = os.lstat(path)
    except OSError:
        return False
    opened = os.fstat(fd)
    return (entry.st_dev, entry.st_ino) == (opened.st_dev, opened.st_ino)


def open_parent(parent):
    """Open the output parent once. It must be a real directory: a symlink in its place is refused."""
    if os.path.islink(parent):
        raise Failed(f"output parent directory {parent} is a symlink; give its real path")
    try:
        return os.open(parent, DIR_FLAGS)
    except OSError:
        raise Failed("output parent directory does not exist, is not a directory or is a symlink") from None


def warn_leftovers(parent_fd):
    """Earlier interrupted runs may have left staging behind. It may be evidence for an uncertain
    request, so it is reported, never deleted and never treated as output."""
    for name in sorted(os.listdir(parent_fd)):
        if name.startswith(STAGE_PREFIX):
            print(f"warning: leftover staging directory {name} from an earlier interrupted run was found beside "
                  "--output. It is not published output and was not removed. Check the request ID from that run "
                  "on the Brigalow server before deleting it.", file=sys.stderr, flush=True)


def make_stage(parent_fd):
    """Create a private staging directory beside the output and check its owner and 0700 mode."""
    name = STAGE_PREFIX + secrets.token_hex(8)
    os.mkdir(name, 0o700, dir_fd=parent_fd)
    try:
        fd = os.open(name, DIR_FLAGS, dir_fd=parent_fd)
    except OSError:
        os.rmdir(name, dir_fd=parent_fd)
        raise Failed("cannot open the staging directory") from None
    os.fchmod(fd, 0o700)
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        os.close(fd)
        raise Failed("staging directory is not a private 0700 directory owned by this user; refusing")
    return name, fd


def remove_stage(parent_fd, name, fd):
    if not same_entry(parent_fd, name, fd):
        print(f"warning: staging directory {name} was replaced during the run and was not removed", file=sys.stderr)
        return
    try:
        shutil.rmtree(name, dir_fd=parent_fd)
    except OSError:
        print(f"warning: staging directory {name} could not be removed completely", file=sys.stderr)


def stop(process, state):
    """Terminate and reap brig. Its request may still complete on the server."""
    if process.poll() is None:
        state["brig_stopped"] = True
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def sign(args, manifest, signature, state):
    """Run brig exactly once. Relay its request ID; never resubmit on any failure."""
    command = [str(args.brig), "sign", "--server", args.server, "--org", args.org, "--project", args.project,
               "--policy", args.policy, "--format", "raw", "--output", str(signature),
               "--wait", str(math.ceil(args.timeout) + BRIG_WAIT_MARGIN)]
    if args.ca_file:
        command += ["--ca-file", str(args.ca_file)]
    command.append(str(manifest))
    # The child inherits the blocked mask, so unblock before exec or brig would ignore terminate().
    with Deferred():
        process = state["brig"] = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_UNBLOCK, SIGNALS))

    uncertain = []

    def relay(stream, sink):
        for line in stream:
            if any(marker in line for marker in UNCERTAIN):
                uncertain.append(line)
            match = REQUEST.search(line)
            if match and "request" not in state:
                state["request"] = match.group(1)
                print(f"Brigalow request ID: {match.group(1)}", file=sys.stderr, flush=True)
            print(f"brig: {line.rstrip()}", file=sink, flush=True)

    readers = [threading.Thread(target=relay, args=(process.stdout, sys.stderr), daemon=True),
               threading.Thread(target=relay, args=(process.stderr, sys.stderr), daemon=True)]
    for reader in readers:
        reader.start()
    try:
        code = process.wait(timeout=args.timeout)
    except subprocess.TimeoutExpired:
        stop(process, state)
        for reader in readers:
            reader.join(timeout=5)
        raise Failed("signing did not finish before the timeout; outcome uncertain", state.get("request")) from None
    except BaseException:
        stop(process, state)
        for reader in readers:
            reader.join(timeout=5)
        raise
    for reader in readers:
        reader.join(timeout=5)
    request = state.get("request")
    if code != 0 and uncertain:
        raise Failed("brig stopped before the request reached a final state; outcome uncertain", request)
    if code != 0:
        raise Failed("brig signing failed (denied, rejected, gate failure, expired or interrupted)", request)
    if request is None:
        raise Failed("brig reported success without a request ID; outcome uncertain")
    return request


def read_at(directory_fd, name):
    fd = os.open(name, FILE_FLAGS, dir_fd=directory_fd)
    with os.fdopen(fd, "rb") as handle:
        return handle.read()


def each_file(directory_fd, action):
    """Apply `action(fd)` to every regular file directly inside the directory, never following symlinks."""
    for name in os.listdir(directory_fd):
        fd = os.open(name, FILE_FLAGS, dir_fd=directory_fd)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise Failed(f"staged entry {name} is not a regular file")
            action(fd)
        finally:
            os.close(fd)


def untracked_output(parent, source):
    """Staging under a non-ignored path in the source checkout would dirty it mid-packaging."""
    source = Path(source or Path(__file__).resolve().parents[1]).resolve()
    if parent != source and source not in parent.parents:
        return
    probe = parent/".brigalow-operator-probe"
    ignored = subprocess.run(["git", "check-ignore", "-q", "--no-index", str(probe)], cwd=source)
    if ignored.returncode != 0:
        raise Failed(f"output directory {parent} is inside the source checkout and not ignored by git; "
                     "choose an output outside the checkout or under an ignored path such as dist/")


def run(args, state):
    """One release attempt. Staging is removed and brig is stopped on every exit path."""
    try:
        release(args, state)
    finally:
        cleanup(state)


def release(args, state):
    output = Path(os.path.abspath(args.output))
    if not output.name or output.name in (".", ".."):
        raise Failed("--output must name a new directory")
    if not COMMIT.fullmatch(args.expected_revision):
        raise Failed("expected revision must be a full lowercase hexadecimal commit ID")
    if not os.environ.get("BRIGALOW_TOKEN"):
        raise Failed("BRIGALOW_TOKEN is required")
    with Deferred():
        parent_fd = state["parent_fd"] = open_parent(output.parent)
    try:
        os.stat(output.name, dir_fd=parent_fd, follow_symlinks=False)
        raise Failed("output already exists; refusing before any signing request")
    except FileNotFoundError:
        pass
    pinned_key(args.public_key, output)
    untracked_output(output.parent.resolve(), args.source)
    warn_leftovers(parent_fd)
    with Deferred():
        stage_name, stage_fd = state["stage"] = make_stage(parent_fd)
    # Path-based work below (packaging, brig, the verifier) goes through this private 0700 stage.
    staging = output.parent/stage_name
    # Prove no-replace publication works here before spending a signature or window slot.
    os.mkdir("probe", 0o700, dir_fd=stage_fd)
    publish_no_replace(stage_fd, "probe", stage_fd, "probe-published")
    os.mkdir("signing", 0o700, dir_fd=stage_fd)
    revision = package(args.binaries, staging/"bundle", trust="operator", source=args.source)
    if revision != args.expected_revision:
        raise Failed("checkout commit does not match --expected-revision; nothing was submitted")
    with Deferred():
        bundle_fd = state["bundle_fd"] = os.open("bundle", DIR_FLAGS, dir_fd=stage_fd)
    if not (same_path(staging, stage_fd) and same_path(staging/"bundle", bundle_fd)):
        raise Failed("staging directory was moved or replaced during packaging; nothing was submitted")
    each_file(bundle_fd, lambda fd: os.fchmod(fd, 0o444))
    frozen = hashlib.sha256(read_at(bundle_fd, MANIFEST)).hexdigest()
    print(f"Frozen operator manifest SHA-256 {frozen} for source commit {revision}", file=sys.stderr)
    request = sign(args, staging/"bundle"/MANIFEST, staging/"signing"/SIGNATURE, state)
    signing_fd = os.open("signing", DIR_FLAGS, dir_fd=stage_fd)
    try:
        if os.listdir(signing_fd) != [SIGNATURE]:
            raise Failed("signing produced outputs outside the version 2 operator bundle "
                         "(timestamp/attestation outputs are not supported yet)", request)
        if hashlib.sha256(read_at(bundle_fd, MANIFEST)).hexdigest() != frozen:
            raise Failed("manifest changed after it was frozen", request)
        os.rename(SIGNATURE, SIGNATURE, src_dir_fd=signing_fd, dst_dir_fd=bundle_fd)
    finally:
        os.close(signing_fd)
    each_file(bundle_fd, lambda fd: os.fchmod(fd, 0o444))
    try:
        fingerprint, commit = verify_operator_bundle(staging/"bundle", args.public_key, revision,
                                                     args.expected_key_sha256)
    except Rejected as error:
        raise Failed(f"signed bundle failed verification against the pinned key: {error}", request) from None
    # The verifier, brig and packaging use paths; publication uses the fds. They must be the same objects.
    if not (same_path(staging, stage_fd) and same_path(staging/"bundle", bundle_fd)
            and same_entry(stage_fd, "bundle", bundle_fd)):
        raise Failed("staging directory was moved or replaced during the run", request)
    each_file(bundle_fd, sync_fd)
    os.fchmod(bundle_fd, 0o755)
    sync_fd(bundle_fd)
    publish_no_replace(stage_fd, "bundle", parent_fd, output.name)
    state["published"] = True
    sync_fd(parent_fd)
    print(operator_report(fingerprint, commit))
    print(f"Published {output} (request {request})")


def cleanup(state):
    """Stop brig, then remove staging. Under main()'s handlers, further signals are ignored from
    here so cleanup always completes."""
    with Deferred():
        for number in SIGNALS:
            if signal.getsignal(number) is interrupt:
                signal.signal(number, signal.SIG_IGN)
    if state.get("brig") is not None:
        stop(state["brig"], state)
    if "bundle_fd" in state:
        os.close(state["bundle_fd"])
    if "stage" in state:
        name, fd = state["stage"]
        remove_stage(state["parent_fd"], name, fd)
        os.close(fd)
    if "parent_fd" in state:
        os.close(state["parent_fd"])


def report(error, state):
    if isinstance(error, Interrupted):
        reason = f"interrupted by {error}"
    elif isinstance(error, (Failed, Rejected)):
        reason = str(error)
    else:
        reason = f"unexpected {type(error).__name__}"
    request = state.get("request")
    if state.get("published"):
        outcome = "The bundle was renamed into place but its durability is uncertain; verify it before use"
    elif state.get("brig") is not None and state["brig"].returncode == 0:
        outcome = ("No completed bundle was published. The request was signed and staging was removed, so "
                   "that signature and any release-window slot are spent")
    elif state.get("brig_stopped"):
        outcome = ("No completed bundle was published. brig was stopped and staging removed; the signing "
                   "outcome is uncertain: the request may still be approved and signed on the server")
    else:
        outcome = "No completed bundle was published"
    print(f"operator release failed: {reason}. {outcome}.", file=sys.stderr)
    if request:
        print(f"Query request {request} on the Brigalow server before any new attempt; "
              "do not resubmit blindly. This command never retries.", file=sys.stderr)
    elif state.get("brig") is not None:
        print("brig was started but no request ID was seen; check the Brigalow server for a request from this "
              "run before any new attempt. This command never retries.", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binaries", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path,
                        help="final bundle directory; must not exist, and its parent must not be a symlink")
    parser.add_argument("--public-key", required=True, type=Path,
                        help="separately pinned PEM public key for the release signing key (never from the bundle)")
    parser.add_argument("--expected-key-sha256", help="independently reviewed SHA-256 of the pinned key's DER SPKI")
    parser.add_argument("--expected-revision", required=True,
                        help="the full source commit ID you intend to release; the checkout must match it")
    parser.add_argument("--source", type=Path, help="clean git checkout to package (default: this repository)")
    parser.add_argument("--brig", type=Path, default=Path("brig"))
    parser.add_argument("--server", required=True)
    parser.add_argument("--org", required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--policy", required=True, help="release-purpose policy name or ID")
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--timeout", type=float, default=360.0,
                        help="seconds to wait for brig (approval, gates, window) before failing as uncertain; "
                             f"at most {MAX_TIMEOUT}. brig itself is told to wait {BRIG_WAIT_MARGIN} s longer")
    args = parser.parse_args()
    if not 0 < args.timeout <= MAX_TIMEOUT:
        parser.error(f"--timeout must be positive and at most {MAX_TIMEOUT}")
    state = {}
    for number in SIGNALS:
        signal.signal(number, interrupt)
    try:
        run(args, state)
    except (Exception, Interrupted) as error:  # noqa: BLE001 - every failure must report the request ID
        report(error, state)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
