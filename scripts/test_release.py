"""Release packaging and verification tests (AT-REL-03 unit level plus the lab regression).

Every key is generated at test time with OpenSSL. A fake `brig` stands in for the control plane
so failure semantics (denial, timeout, collisions) can be exercised without a server; the real
policy path is covered by the Compose tools test.
"""
import hashlib
import json
import os
import pathlib
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import time
import unittest

SCRIPTS = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
from operator_release import Failed, publish_no_replace  # noqa: E402
from verify_release import Rejected, verify_operator_bundle  # noqa: E402
from package_release import operator_manifest  # noqa: E402
from verify_release import ARCHIVE, SBOM, canonical  # noqa: E402

NAMES = ["brig", "brigalow-server", "brigalow-ca", "brigalow-audit", "brigalow-admin", "libbrigalow_pkcs11.so"]
VERIFY = [sys.executable, str(SCRIPTS/"verify_release.py")]
WORKFLOW = [sys.executable, str(SCRIPTS/"operator_release.py")]
FAKE_BRIG = textwrap.dedent('''\
    #!/usr/bin/env python3
    """Test double for `brig sign --format raw`. Never contacts a server."""
    import os, pathlib, signal, subprocess, sys, time, uuid
    args = sys.argv[1:]
    assert args[0] == "sign" and args[args.index("--format") + 1] == "raw"
    output, artifact = pathlib.Path(args[args.index("--output") + 1]), pathlib.Path(args[-1])
    with open(os.environ["FAKE_BRIG_CALLS"], "a") as calls:
        calls.write(f"call --wait {args[args.index('--wait') + 1]}\\n")
    mode = os.environ["FAKE_BRIG_MODE"]
    request = uuid.uuid4()

    def terminated(signum, _frame):
        pathlib.Path(os.environ["FAKE_BRIG_PID"] + ".terminated").write_text(str(signum))
        sys.exit(1)

    signal.signal(signal.SIGTERM, terminated)
    print(f"Submitting request {request}", file=sys.stderr, flush=True)
    if mode == "deny":
        sys.exit("server rejected request; no signature written")
    if mode == "pending":
        sys.exit("approval still pending; query the submitted request ID (do not resubmit)")
    if mode == "hang":
        pathlib.Path(os.environ["FAKE_BRIG_PID"]).write_text(str(os.getpid()))
        time.sleep(600)
    if mode == "collide":
        target = pathlib.Path(os.environ["FAKE_BRIG_COLLIDE"])
        target.mkdir()
        (target / "operator-owned").write_text("pre-existing")
    if mode == "tamper":
        artifact.chmod(0o644)
        artifact.write_bytes(artifact.read_bytes() + b" ")
    key = os.environ["FAKE_BRIG_WRONG_KEY"] if mode == "wrong-key" else os.environ["FAKE_BRIG_KEY"]
    signature = subprocess.run(["openssl", "dgst", "-sha256", "-sign", key, str(artifact)],
                               capture_output=True, check=True).stdout
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, signature)
    os.close(fd)
    if mode == "timestamp":
        pathlib.Path(f"{output}.tsr").write_bytes(b"unauthenticated token")
    if mode == "kill-parent":
        # Kill point: the signature has landed in staging and the workflow dies without cleanup.
        os.kill(os.getppid(), signal.SIGKILL)
        time.sleep(5)
    print(f"Signed request {request}")
''')


def openssl(*args, data=None):
    result = subprocess.run(["openssl", *args], input=data, capture_output=True)
    assert result.returncode == 0, "generated release fixture OpenSSL call failed"
    return result.stdout


P256 = ("EC", "ec_paramgen_curve:P-256")
RSA3072 = ("RSA", "rsa_keygen_bits:3072")
# Keys outside the fixed version 2 profile. Each is generated at test time.
UNSUPPORTED = {
    "RSA-2048": ("RSA", "rsa_keygen_bits:2048"),
    "RSA-4096": ("RSA", "rsa_keygen_bits:4096"),
    "RSA-3072 exponent 3": ("RSA", "rsa_keygen_bits:3072", "rsa_keygen_pubexp:3"),
    "P-384": ("EC", "ec_paramgen_curve:P-384"),
    "RSA-PSS 3072": ("RSA-PSS", "rsa_keygen_bits:3072"),
    "Ed25519": ("ED25519",),
}


def keypair(directory, name, spec=P256):
    private, public = directory/f"{name}.key", directory/f"{name}.pem"
    algorithm, *options = spec
    openssl("genpkey", "-algorithm", algorithm, *[arg for option in options for arg in ("-pkeyopt", option)],
            "-out", str(private))
    openssl("pkey", "-in", str(private), "-pubout", "-out", str(public))
    return private, public


def spki_sha256(public):
    return hashlib.sha256(openssl("pkey", "-pubin", "-in", str(public), "-outform", "DER")).hexdigest()


def binaries(directory):
    path = directory/"bin"
    path.mkdir()
    for name in NAMES:
        (path/name).write_bytes(b"generated packaging fixture")
    return path


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="brigalow-release-test-")
        self.root = pathlib.Path(self.temporary.name)
        self.key, self.public = keypair(self.root, "operator")
        self.attacker_key, self.attacker_public = keypair(self.root, "attacker")
        self.binaries = binaries(self.root)

    def tearDown(self):
        for path in self.root.rglob("*"):
            if not path.is_symlink():
                path.chmod(0o700 if path.is_dir() else 0o600)
        self.temporary.cleanup()

    def sign(self, bundle, key=None):
        signature = openssl("dgst", "-sha256", "-sign", str(key or self.key), str(bundle/"manifest.json"))
        sig = bundle/"manifest.sig"
        if sig.exists():
            sig.chmod(0o600)
        sig.write_bytes(signature)

    def verify(self, bundle, *extra, mode="operator", key=None, revision="fixture"):
        """Operator mode passes the fixture commit as --expected-revision unless told otherwise."""
        if mode == "operator" and revision == "fixture":
            revision = getattr(self, "commit", None)
        if mode == "operator" and revision is not None and "--expected-revision" not in extra:
            extra = ("--expected-revision", revision, *extra)
        return subprocess.run(VERIFY + [str(bundle), "--mode", mode, "--public-key", str(key or self.public), *extra],
                              capture_output=True, text=True)

    def assert_rejected(self, bundle, *extra, reason=None, **kwargs):
        result = self.verify(bundle, *extra, **kwargs)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        if reason:
            self.assertIn(reason, result.stderr)
        return result


class Lab(Fixture):
    def test_lab_packaging_sbom_and_payload_tamper(self):
        subprocess.run([sys.executable, str(SCRIPTS/"package_release.py"), "--binaries", str(self.binaries),
                        "--output", str(self.root/"dist")], check=True)
        dist = self.root/"dist"
        with tarfile.open(dist/ARCHIVE) as archive:
            self.assertEqual(set(archive.getnames()), set(NAMES + ["LICENSE"]))
        sbom = json.loads((dist/SBOM).read_text())
        self.assertEqual(sbom["bomFormat"], "CycloneDX")
        self.assertTrue(any(c["name"] == "brigalow-core" for c in sbom["components"]))
        manifest = json.loads((dist/"manifest.json").read_text())
        self.assertEqual((manifest["version"], manifest["trust"]), (1, "lab"))
        self.sign(dist)
        self.assertEqual(self.verify(dist, mode="lab").returncode, 0)
        # Lab output can never pass operator verification, even with the correct key.
        self.assert_rejected(dist, mode="operator")
        (dist/ARCHIVE).write_bytes(b"tampered payload")
        self.assert_rejected(dist, mode="lab")

    def test_mode_is_explicit(self):
        result = subprocess.run(VERIFY + [str(self.root), "--public-key", str(self.public)], capture_output=True)
        self.assertNotEqual(result.returncode, 0)


class OperatorVerifier(Fixture):
    def setUp(self):
        super().setUp()
        self.bundle = self.root/"bundle"
        self.bundle.mkdir()
        (self.bundle/ARCHIVE).write_bytes(b"generated archive fixture")
        (self.bundle/SBOM).write_bytes(b'{"bomFormat":"CycloneDX"}\n')
        self.commit = "a" * 40
        self.write(self.manifest())

    def manifest(self):
        return json.loads(operator_manifest(self.commit, self.digest(ARCHIVE), self.digest(SBOM)))

    def digest(self, name):
        return hashlib.sha256((self.bundle/name).read_bytes()).hexdigest()

    def write(self, manifest, raw=None, key=None):
        (self.bundle/"manifest.json").write_bytes(raw if raw is not None else canonical(manifest))
        self.sign(self.bundle, key)

    def test_valid_bundle_reports_origin_not_public_trust(self):
        result = self.verify(self.bundle, "--expected-revision", self.commit,
                             "--expected-key-sha256", spki_sha256(self.public))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Declared origin: operator", result.stdout)
        self.assertIn("not a public-trust", result.stdout)

    def test_exact_bytes_and_payload_tampering(self):
        manifest = (self.bundle/"manifest.json").read_bytes()
        (self.bundle/"manifest.json").write_bytes(manifest + b" ")
        self.assert_rejected(self.bundle, reason="signature invalid")
        (self.bundle/"manifest.json").write_bytes(manifest.replace(self.commit.encode(), b"b" * 40))
        self.assert_rejected(self.bundle, reason="signature invalid")
        (self.bundle/"manifest.json").write_bytes(manifest)
        # A re-signed but non-canonical encoding is not the frozen operator byte format.
        self.write(None, raw=json.dumps(self.manifest()).encode())
        self.assert_rejected(self.bundle, reason="canonical")
        self.write(self.manifest())
        for name in [ARCHIVE, SBOM]:
            original = (self.bundle/name).read_bytes()
            (self.bundle/name).write_bytes(original + b"x")
            self.assert_rejected(self.bundle, reason=f"digest mismatch: {name}")
            (self.bundle/name).write_bytes(original)
        self.assertEqual(self.verify(self.bundle).returncode, 0)

    def test_expected_revision(self):
        self.assert_rejected(self.bundle, "--expected-revision", "b" * 40, reason="expected revision")
        self.assert_rejected(self.bundle, "--expected-revision", "HEAD", reason="full lowercase")
        self.assertEqual(self.verify(self.bundle, "--expected-revision", self.commit).returncode, 0)

    def test_missing_expected_revision_is_refused(self):
        result = self.assert_rejected(self.bundle, revision=None, reason="requires --expected-revision")
        self.assertNotIn("verified", result.stdout)
        self.assert_rejected(self.bundle, "--revision-unchecked", reason="not allowed with")
        with self.assertRaises(Rejected):
            verify_operator_bundle(self.bundle, self.public, None)
        with self.assertRaises(Rejected):
            verify_operator_bundle(self.bundle, self.public, self.commit, revision_unchecked=True)
        self.assertNotEqual(self.verify(self.bundle, "--revision-unchecked", mode="lab").returncode, 0)

    def test_revision_unchecked_passes_with_rollback_warning(self):
        result = self.verify(self.bundle, "--revision-unchecked", revision=None)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("WARNING: --revision-unchecked", result.stderr)
        self.assertIn("declared by the signer", result.stderr)
        self.assertIn("rollback", result.stderr)
        self.assertIn(f"source commit {self.commit} was declared by the signer and NOT compared", result.stdout)
        checked = self.verify(self.bundle)
        self.assertIn("matches the expected revision", checked.stdout)
        self.assertNotIn("WARNING", checked.stderr)
        # The waiver skips only the comparison: signature, schema and payload checks still apply.
        (self.bundle/SBOM).write_bytes(b"tampered")
        self.assert_rejected(self.bundle, "--revision-unchecked", revision=None, reason="digest mismatch")

    def test_rsa3072_bundle_verifies(self):
        key, public = keypair(self.root, "rsa3072", RSA3072)
        self.write(self.manifest(), key=key)
        result = self.verify(self.bundle, "--expected-key-sha256", spki_sha256(public), key=public)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_rejected(self.bundle, reason="signature invalid")

    def test_unsupported_key_algorithms_rejected_before_openssl(self):
        explicit = self.root/"p256-explicit.pem"
        openssl("ec", "-in", str(self.key), "-pubout", "-param_enc", "explicit", "-out", str(explicit))
        compressed = self.root/"p256-compressed.pem"
        openssl("ec", "-in", str(self.key), "-pubout", "-conv_form", "compressed", "-out", str(compressed))
        # Same P-256 key, other valid encodings: the exact-encoding check fails closed.
        for public in [explicit, compressed]:
            with self.subTest(encoding=public.name):
                self.assert_rejected(self.bundle, key=public, reason="unsupported key algorithm")
        for name, spec in UNSUPPORTED.items():
            with self.subTest(key=name):
                key, public = keypair(self.root, name.replace(" ", "-"), spec)
                if spec[0] != "ED25519":  # dgst -sha256 cannot drive Ed25519; the key check comes first anyway.
                    self.write(self.manifest(), key=key)
                    check = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(public), "-signature",
                                            str(self.bundle/"manifest.sig"), str(self.bundle/"manifest.json")],
                                           capture_output=True)
                    self.assertEqual(check.returncode, 0, f"{name}: OpenSSL alone would accept this signature")
                self.assert_rejected(self.bundle, key=public, reason="unsupported key algorithm")
                self.assert_rejected(self.bundle, "--revision-unchecked", key=public, revision=None,
                                     reason="unsupported key algorithm")

    def test_wrong_and_co_delivered_keys(self):
        self.assert_rejected(self.bundle, key=self.attacker_public, reason="signature invalid")
        self.assert_rejected(self.bundle, "--expected-key-sha256", spki_sha256(self.attacker_public),
                             reason="fingerprint mismatch")
        # Replacement attack: altered payload, re-signed by an attacker who ships their own key.
        (self.bundle/SBOM).write_bytes(b'{"bomFormat":"attacker"}\n')
        self.write(self.manifest(), key=self.attacker_key)
        self.assert_rejected(self.bundle, reason="signature invalid")
        shutil.copy(self.attacker_public, self.bundle/"operator-public.pem")
        self.assert_rejected(self.bundle, key=self.bundle/"operator-public.pem", reason="inside the bundle")
        os.remove(self.bundle/"operator-public.pem")
        os.link(self.attacker_public, self.bundle/"public.pem")
        self.assert_rejected(self.bundle, key=self.attacker_public)

    def test_missing_extra_and_non_regular_files(self):
        sbom = (self.bundle/SBOM).read_bytes()
        os.remove(self.bundle/SBOM)
        self.assert_rejected(self.bundle)
        outside = self.root/"outside.json"
        outside.write_bytes(sbom)
        os.symlink(outside, self.bundle/SBOM)
        self.assert_rejected(self.bundle, reason="symlinks are rejected")
        os.remove(self.bundle/SBOM)
        (self.bundle/SBOM).mkdir()
        self.assert_rejected(self.bundle)
        (self.bundle/SBOM).rmdir()
        os.mkfifo(self.bundle/SBOM)
        self.assert_rejected(self.bundle, reason="not a regular file")
        os.remove(self.bundle/SBOM)
        (self.bundle/SBOM).write_bytes(sbom)
        (self.bundle/"extra.bin").write_bytes(b"unlisted")
        self.assert_rejected(self.bundle, reason="unexpected or missing")
        os.remove(self.bundle/"extra.bin")
        link = self.root/"linked-bundle"
        os.symlink(self.bundle, link)
        self.assert_rejected(link, reason="real directory")
        self.assertEqual(self.verify(self.bundle).returncode, 0)

    def test_strict_schema(self):
        good = self.manifest()
        cases = [
            (dict(good, version=3), "unsupported manifest version"),
            (dict(good, version=1), "unsupported manifest version"),
            (dict(good, version=True), "unsupported manifest version"),
            (dict(good, trust="lab"), "unsupported trust label"),
            (dict(good, trust="public"), "unsupported trust label"),
            (dict(good, digest_algorithm="sha512"), "unsupported digest algorithm"),
            (dict(good, provenance="public-ca"), "unsupported provenance"),
            (dict(good, note="extra"), "unknown or missing manifest fields"),
            ({k: v for k, v in good.items() if k != "source_commit"}, "unknown or missing manifest fields"),
            (dict(good, source_commit="abc123"), "full lowercase"),
            (dict(good, source_commit="A" * 40), "full lowercase"),
            (dict(good, artifacts=good["artifacts"] + [dict(role="sbom", name="b.json", sha256="0" * 64)]),
             "artifact count"),
            (dict(good, artifacts=good["artifacts"][:1]), "artifact count"),
            (dict(good, artifacts=[good["artifacts"][0], good["artifacts"][0]]), "unique"),
            (dict(good, artifacts=[dict(good["artifacts"][0], extra=1), good["artifacts"][1]]), "artifact fields"),
            (dict(good, artifacts=[dict(good["artifacts"][0], name="other.tar.gz"), good["artifacts"][1]]), "layout"),
            (dict(good, artifacts=[good["artifacts"][0], dict(good["artifacts"][1], sha256="F" * 64)]), "SHA-256"),
        ]
        for name in ["../sbom.cdx.json", "/etc/passwd", "sub/sbom.cdx.json", "..", ".hidden", "manifest.sig", ""]:
            cases.append((dict(good, artifacts=[good["artifacts"][0], dict(good["artifacts"][1], name=name)]),
                          "basename"))
        for manifest, reason in cases:
            with self.subTest(reason=reason, manifest=manifest):
                self.write(manifest)
                self.assert_rejected(self.bundle, reason=reason)
        text = canonical(good).decode()
        duplicate = text.replace('"trust": "operator"', '"trust": "lab",\n  "trust": "operator"', 1)
        self.write(None, raw=duplicate.encode())
        self.assert_rejected(self.bundle, reason="duplicate JSON key")
        nested = text.replace('"role": "sbom"', '"role": "archive",\n      "role": "sbom"', 1)
        self.write(None, raw=nested.encode())
        self.assert_rejected(self.bundle, reason="duplicate JSON key")
        self.write(None, raw=text.replace('"version": 2', '"version": NaN').encode())
        self.assert_rejected(self.bundle, reason="non-finite")
        self.write(None, raw=b"\xff" + text.encode())
        self.assert_rejected(self.bundle, reason="UTF-8")
        self.write(None, raw=text.encode() + b" " * 70000)
        self.assert_rejected(self.bundle, reason="too large")
        self.write(good)
        self.assertEqual(self.verify(self.bundle).returncode, 0)

    def test_operator_bundle_fails_lab_mode(self):
        self.assert_rejected(self.bundle, mode="lab", reason="not a version 1 lab manifest")


class Workflow(Fixture):
    def setUp(self):
        super().setUp()
        self.source = self.root/"source"
        (self.source/"src").mkdir(parents=True)
        (self.source/"Cargo.toml").write_text('[package]\nname = "brigalow-core"\nversion = "0.0.1"\nedition = "2021"\nlicense = "Apache-2.0"\n')
        (self.source/"src/lib.rs").write_text("")
        (self.source/"LICENSE").write_text("generated licence fixture\n")
        (self.source/".gitignore").write_text("target/\n")
        subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=self.source, check=True, capture_output=True)
        git = ["git", "-c", "user.name=Release Test", "-c", "user.email=release-test@example.invalid",
               "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main"]
        subprocess.run(git + ["init", "-q"], cwd=self.source, check=True)
        subprocess.run(git + ["add", "-A"], cwd=self.source, check=True)
        subprocess.run(git + ["commit", "-q", "-m", "fixture"], cwd=self.source, check=True)
        self.commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.source, text=True).strip()
        self.brig = self.root/"fake-brig"
        self.brig.write_text(FAKE_BRIG)
        self.brig.chmod(0o755)
        self.calls = self.root/"calls"
        self.calls.touch()
        self.published = self.root/"published"
        self.published.mkdir()
        self.output = self.published/"brigalow-operator"

    def command(self, mode="sign", *extra, timeout="30", token="generated-test-token", revision="fixture"):
        env = dict(os.environ, FAKE_BRIG_MODE=mode, FAKE_BRIG_CALLS=str(self.calls), FAKE_BRIG_KEY=str(self.key),
                   FAKE_BRIG_WRONG_KEY=str(self.attacker_key), FAKE_BRIG_COLLIDE=str(self.output),
                   FAKE_BRIG_PID=str(self.root/"brig.pid"))
        env.pop("BRIGALOW_TOKEN", None)
        if token:
            env["BRIGALOW_TOKEN"] = token
        if revision == "fixture" and "--expected-revision" not in extra:
            extra = ("--expected-revision", self.commit, *extra)
        command = WORKFLOW + ["--binaries", str(self.binaries), "--output", str(self.output),
                              "--public-key", str(self.public), "--source", str(self.source),
                              "--brig", str(self.brig), "--server", "https://brigalow.invalid",
                              "--org", "00000000-0000-4000-8000-000000000001",
                              "--project", "00000000-0000-4000-8000-000000000002",
                              "--policy", "release", "--timeout", timeout, *extra]
        return command, env

    def release(self, mode="sign", *extra, **kwargs):
        command, env = self.command(mode, *extra, **kwargs)
        return subprocess.run(command, env=env, capture_output=True, text=True, timeout=120)

    def staging(self):
        return [p for p in self.published.iterdir() if p.name.startswith(".brigalow-operator-")]

    def wait_for(self, path, timeout=60):
        deadline = time.monotonic() + timeout
        while not path.exists():
            self.assertLess(time.monotonic(), deadline, f"{path.name} never appeared")
            time.sleep(0.05)

    def alive(self, pid):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        return True

    def call_count(self):
        return len(self.calls.read_text().splitlines())

    def assert_failed(self, result, calls, request=True, published=False):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.call_count(), calls, "signing must never be retried")
        if not published:
            self.assertIn("No completed bundle was published", result.stderr)
        if request:
            self.assertRegex(result.stderr, r"Query request [0-9a-f-]{36} on the Brigalow server")
        leftovers = [p.name for p in self.published.iterdir() if p.name.startswith(".brigalow-operator-")]
        self.assertEqual(leftovers, [], "staging must be removed")

    def test_success_publishes_complete_verified_bundle(self):
        result = self.release("sign", "--expected-revision", self.commit,
                              "--expected-key-sha256", spki_sha256(self.public))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.call_count(), 1)
        # brig is told to poll longer than --timeout (30 s), so the workflow's deadline fires first.
        self.assertEqual(self.calls.read_text(), "call --wait 90\n")
        self.assertRegex(result.stderr, r"Brigalow request ID: [0-9a-f-]{36}")
        self.assertNotIn("leftover staging", result.stderr)
        self.assertEqual(sorted(os.listdir(self.output)), sorted(["manifest.json", "manifest.sig", ARCHIVE, SBOM]))
        manifest = json.loads((self.output/"manifest.json").read_text())
        self.assertEqual((manifest["version"], manifest["trust"], manifest["source_commit"]), (2, "operator", self.commit))
        verified = self.verify(self.output, "--expected-revision", self.commit)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assert_rejected(self.output, mode="lab")
        self.assertEqual([p.name for p in self.published.iterdir()], [self.output.name])
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o755)
        for name in os.listdir(self.output):
            self.assertEqual((self.output/name).stat().st_mode & 0o777, 0o444, name)

    def test_rsa3072_operator_release(self):
        self.key, self.public = keypair(self.root, "operator-rsa", RSA3072)
        result = self.release("sign", "--expected-key-sha256", spki_sha256(self.public))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.call_count(), 1)
        self.assertEqual(self.verify(self.output).returncode, 0)

    def test_unsupported_pinned_key_refused_before_submission(self):
        for name in ["RSA-2048", "P-384", "Ed25519"]:
            with self.subTest(key=name):
                _, self.public = keypair(self.root, f"workflow-{name}", UNSUPPORTED[name])
                result = self.release()
                self.assert_failed(result, calls=0, request=False)
                self.assertIn("unsupported key algorithm", result.stderr)

    def test_expected_revision_required_before_any_submission(self):
        result = self.release(revision=None)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--expected-revision", result.stderr)
        self.assertEqual(self.call_count(), 0)
        self.assertEqual(os.listdir(self.published), [])
        # The verifier's waiver is not a workflow option.
        result = self.release("sign", "--revision-unchecked", revision=None)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.call_count(), 0)

    def test_brig_poll_deadline_is_uncertain_not_a_plain_failure(self):
        result = self.release("pending")
        self.assert_failed(result, calls=1)
        self.assertIn("outcome uncertain", result.stderr)
        self.assertNotIn("brig signing failed", result.stderr)
        self.assertIn("do not resubmit blindly", result.stderr)

    def test_sigkill_after_signature_lands_publishes_nothing(self):
        result = self.release("kill-parent")
        self.assertEqual(result.returncode, -signal.SIGKILL, result.stderr)
        self.assertEqual(self.call_count(), 1)
        self.assertFalse(os.path.lexists(self.output))
        # SIGKILL cannot be handled: staging, holding the signature, is left for the operator.
        leftovers = self.staging()
        self.assertEqual(len(leftovers), 1)
        self.assertTrue((leftovers[0]/"signing"/"manifest.sig").is_file())
        # The next run warns about it, never deletes it and never treats it as output.
        result = self.release("deny")
        self.assertIn(f"leftover staging directory {leftovers[0].name}", result.stderr)
        self.assertEqual(self.staging(), leftovers)
        self.assertTrue((leftovers[0]/"signing"/"manifest.sig").is_file())
        self.assertFalse(os.path.lexists(self.output))

    def test_leftover_staging_warns_and_is_kept(self):
        leftover = self.published/".brigalow-operator-0123456789abcdef"
        (leftover/"bundle").mkdir(parents=True)
        (leftover/"bundle"/"evidence").write_text("from an interrupted run")
        result = self.release()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("warning: leftover staging directory .brigalow-operator-0123456789abcdef", result.stderr)
        self.assertEqual((leftover/"bundle"/"evidence").read_text(), "from an interrupted run")
        self.assertEqual(sorted(p.name for p in self.published.iterdir()), sorted([leftover.name, self.output.name]))

    def test_signals_reap_brig_remove_staging_and_report_request(self):
        for number in [signal.SIGTERM, signal.SIGINT, signal.SIGHUP]:
            with self.subTest(signal=number.name):
                pid_file = self.root/"brig.pid"
                for path in [pid_file, pathlib.Path(f"{pid_file}.terminated")]:
                    path.unlink(missing_ok=True)
                command, env = self.command("hang", timeout="120")
                process = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    self.wait_for(pid_file)
                    brig = int(pid_file.read_text())
                    self.assertEqual(len(self.staging()), 1)
                    process.send_signal(number)
                    stdout, stderr = process.communicate(timeout=60)
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait()
                self.assertEqual(process.returncode, 1, stderr)
                self.assertIn(f"interrupted by {number.name}", stderr)
                self.assertIn("outcome is uncertain", stderr)
                self.assertRegex(stderr, r"Query request [0-9a-f-]{36} on the Brigalow server")
                self.assertEqual(pathlib.Path(f"{pid_file}.terminated").read_text(), str(int(signal.SIGTERM)),
                                 "brig must be terminated, not left polling")
                self.assertFalse(self.alive(brig), "brig must be reaped")
                self.assertEqual(self.staging(), [], "staging must be removed")
                self.assertFalse(os.path.lexists(self.output))
                self.assertNotIn("Published", stdout)

    def test_symlinked_output_parent_refused(self):
        real = self.root/"real-parent"
        real.mkdir()
        link = self.root/"linked-parent"
        os.symlink(real, link)
        self.output = link/"brigalow-operator"
        result = self.release()
        self.assert_failed(result, calls=0, request=False)
        self.assertIn("symlink", result.stderr)
        self.assertEqual(os.listdir(real), [])

    def test_existing_output_is_never_touched(self):
        self.output.mkdir()
        (self.output/"operator-owned").write_text("keep")
        self.assert_failed(self.release(), calls=0, request=False)
        self.assertEqual(os.listdir(self.output), ["operator-owned"])

    def test_publication_race_fails_closed(self):
        result = self.release("collide")
        self.assert_failed(result, calls=1)
        self.assertIn("output already exists", result.stderr)
        self.assertEqual(os.listdir(self.output), ["operator-owned"])

    def test_denial_and_gate_failure_are_not_retried(self):
        self.assert_failed(self.release("deny"), calls=1)
        self.assertFalse(os.path.lexists(self.output))

    def test_timeout_reports_request_and_publishes_nothing(self):
        result = self.release("hang", timeout="2")
        self.assert_failed(result, calls=1)
        self.assertIn("outcome uncertain", result.stderr)
        self.assertFalse(os.path.lexists(self.output))

    def test_unverifiable_signature_is_not_published(self):
        result = self.release("wrong-key")
        self.assert_failed(result, calls=1)
        self.assertIn("failed verification against the pinned key", result.stderr)
        self.assertFalse(os.path.lexists(self.output))

    def test_unexpected_signing_outputs_and_manifest_change(self):
        self.assert_failed(self.release("timestamp"), calls=1)
        self.assert_failed(self.release("tamper"), calls=2)
        self.assertFalse(os.path.lexists(self.output))

    def test_revision_and_checkout_guards_run_before_submission(self):
        self.assert_failed(self.release("sign", "--expected-revision", "b" * 40), calls=0, request=False)
        self.assert_failed(self.release("sign", "--expected-revision", "HEAD"), calls=0, request=False)
        self.assertEqual(self.staging(), [])
        (self.source/"LICENSE").write_text("uncommitted change\n")
        self.assert_failed(self.release(), calls=0, request=False)
        self.assertFalse(os.path.lexists(self.output))

    def test_token_and_pinned_key_required(self):
        self.assert_failed(self.release(token=None), calls=0, request=False)
        self.public = self.root/"missing.pem"
        self.assert_failed(self.release(), calls=0, request=False)

    def test_output_in_unignored_checkout_path_refused_before_submission(self):
        (self.source/"releases").mkdir()
        self.output = self.source/"releases"/"brigalow-operator"
        result = self.release()
        self.assert_failed(result, calls=0, request=False)
        self.assertIn("not ignored by git", result.stderr)
        self.assertFalse(os.path.lexists(self.output))

    def test_unusable_publication_refused_before_submission(self):
        import operator_release
        original = operator_release.publish_no_replace
        def unsupported(source_fd, source, target_fd, target):
            raise Failed("no atomic no-replace rename primitive on this platform; refusing to publish")
        operator_release.publish_no_replace = unsupported
        try:
            args = type("Args", (), dict(output=self.output, expected_revision=self.commit, public_key=self.public,
                                         source=self.source, binaries=self.binaries))()
            os.environ["BRIGALOW_TOKEN"] = "generated-test-token"
            with self.assertRaises(Failed):
                operator_release.run(args, {})
        finally:
            operator_release.publish_no_replace = original
            os.environ.pop("BRIGALOW_TOKEN", None)
        self.assertEqual(self.call_count(), 0, "probe must fail before any signing request")
        self.assertFalse(os.path.lexists(self.output))
        self.assertEqual([p.name for p in self.published.iterdir() if p.name.startswith(".brigalow-operator-")], [])

    def test_no_replace_primitive(self):
        source, target = self.root/"staged", self.root/"target"
        source.mkdir()
        target.mkdir()  # A plain rename(2) would silently replace this empty directory.
        root = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with self.assertRaises(Failed):
                publish_no_replace(root, "staged", root, "target")
            self.assertTrue(source.is_dir() and target.is_dir())
            target.rmdir()
            publish_no_replace(root, "staged", root, "target")
        finally:
            os.close(root)
        self.assertFalse(source.exists())
        self.assertTrue(target.is_dir())


if __name__ == "__main__":
    result = unittest.main(verbosity=2, exit=False).result
    if not result.wasSuccessful():
        raise SystemExit(1)
    print("Release packaging/SBOM, lab regression and AT-REL-03 operator verification/workflow tests passed")
