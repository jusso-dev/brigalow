#!/usr/bin/env python3
"""Offline checks for the Azure reference. Never contacts Azure, IMDS or Docker.

Covers the boot-time materialiser (private modes, owners, digest pin, login key length, no owner
credentials), that the Compose guard accepts its output, and that the Bicep template embeds the
repository's production files unchanged. Run: python3 deploy/azure/test_azure.py
"""
import base64
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from production import validate  # noqa: E402

spec = importlib.util.spec_from_file_location("brigalow_boot", HERE / "cloud-init/brigalow-boot.py")
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)


def values(**overrides):
    base = {
        "image": "example.invalid/brigalow@sha256:" + "a" * 64,
        "config": "mode = \"production\"\n",
        "identity": "{}",
        "anchor": "-",
        "db_password": secrets.token_hex(16),
        "login_key": base64.b64encode(secrets.token_bytes(32)).decode(),
        "tls_crt": "certificate",
        "tls_key": "key",
    }
    base.update(overrides)
    return base


class Boot(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.ca = self.dir / "ca.pem"
        self.ca.write_text("ca")
        self.owners = {}
        patcher = patch.object(os, "chown", lambda path, uid, gid: self.owners.__setitem__(str(path), uid))
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_boot(self, **overrides):
        return boot.materialise(values(**overrides), run=self.dir / "run", ca_bundle=self.ca)

    def test_private_directories_and_files(self):
        image, config, tls = self.run_boot(anchor=base64.b64encode(b"\x30\x00").decode())
        self.assertTrue(image.endswith("a" * 64))
        for directory, uid in [(config, 10001), (tls, 101)]:
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
            self.assertEqual(self.owners[str(directory)], uid)
            for file in directory.iterdir():
                self.assertTrue(stat.S_ISREG(file.lstat().st_mode))
                self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600)
                self.assertEqual(self.owners[str(file)], uid)
        self.assertEqual(sorted(p.name for p in config.iterdir()),
                         ["artifact-signing-root.der", "config.toml", "db-ca.pem", "db-password",
                          "identity.json", "login-key"])
        self.assertEqual(sorted(p.name for p in tls.iterdir()), ["tls.crt", "tls.key"])
        self.assertEqual((config / "artifact-signing-root.der").read_bytes(), b"\x30\x00")
        # The Compose guard accepts this layout when owners match the container UIDs.
        original = Path.lstat

        def owned(path):
            result = list(original(path))
            result[4] = self.owners.get(str(path), 0)
            return os.stat_result(result)

        with patch.object(Path, "lstat", owned):
            validate({"BRIGALOW_IMAGE": image, "BRIGALOW_CONFIG_DIR": str(config),
                      "BRIGALOW_TLS_DIR": str(tls)})
        # A rerun replaces the previous files rather than failing on O_EXCL.
        self.run_boot()
        self.assertFalse((config / "artifact-signing-root.der").exists())

    def test_rejections(self):
        for overrides in [{"image": "example.invalid/brigalow:latest"},
                          {"image": "example.invalid/brigalow@sha256:bad"},
                          {"login_key": base64.b64encode(b"x" * 31).decode()},
                          {"login_key": "not base64!"},
                          {"anchor": "not base64!"}]:
            with self.assertRaises(Exception, msg=str(overrides)):
                self.run_boot(**overrides)
        run = self.dir / "run"
        run.mkdir(exist_ok=True)
        (self.dir / "elsewhere").mkdir()
        if (run / "config").exists():
            shutil.rmtree(run / "config")
        (run / "config").symlink_to(self.dir / "elsewhere")
        with self.assertRaises(ValueError):
            self.run_boot()

    def test_reads_only_runtime_secrets(self):
        names = set(boot.SECRETS.values())
        for forbidden in ["owner", "admin", "migrat", "postgres-administrator"]:
            self.assertFalse(any(forbidden in name for name in names), forbidden)

    def test_failures_withhold_details(self):
        with patch.object(boot, "read_secrets_until", side_effect=ValueError("secret-value-123")), \
                patch.object(boot, "ROOT", self.dir), patch.object(boot, "RUN", self.dir / "run"):
            (self.dir / "boot.json").write_text(json.dumps({"vault": "v", "client_id": "c"}))
            with patch("sys.stderr") as stderr, patch.object(sys, "argv", ["boot", "up", "-d"]):
                with self.assertRaises(SystemExit):
                    boot.main()
            written = "".join(call.args[0] for call in stderr.write.call_args_list)
            self.assertNotIn("secret-value-123", written)
            self.assertIn("details withheld", written)

    def test_secret_reads_retry_until_a_bounded_deadline(self):
        clock = [0.0]
        pauses = []
        def sleep(seconds):
            pauses.append(seconds)
            clock[0] += seconds
        # Succeeds once access propagates.
        calls = iter([ValueError("403"), ValueError("403"), {"ok": True}])
        def flaky(*_):
            value = next(calls)
            if isinstance(value, Exception):
                raise value
            return value
        with patch.object(boot, "read_secrets", side_effect=flaky):
            self.assertEqual(boot.read_secrets_until("v", "c", 900, lambda: clock[0], sleep), {"ok": True})
        self.assertEqual(pauses, [5, 10])
        # Never succeeds: stops at the deadline instead of retrying forever.
        clock[0], pauses[:] = 0.0, []
        with patch.object(boot, "read_secrets", side_effect=ValueError("403")):
            with self.assertRaises(ValueError):
                boot.read_secrets_until("v", "c", 900, lambda: clock[0], sleep)
        self.assertLessEqual(clock[0], 900)
        self.assertGreaterEqual(clock[0], 600, "must allow at least 10 minutes for propagation")
        self.assertLessEqual(max(pauses), boot.SECRET_RETRY_MAX_PAUSE)
        # Slow failures: each read takes the full 90 seconds of network timeouts. No read may
        # start at or after the deadline, so the phase ends within deadline + one read.
        clock[0], starts = 0.0, []
        def slow(*_):
            starts.append(clock[0])
            clock[0] += 90
            raise ValueError("timeout")
        with patch.object(boot, "read_secrets", side_effect=slow):
            with self.assertRaises(ValueError):
                boot.read_secrets_until("v", "c", 900, lambda: clock[0], sleep)
        self.assertTrue(all(t < 900 for t in starts), starts)
        self.assertLessEqual(clock[0], 900 + 90)
        self.assertGreaterEqual(len(starts), 2)

    def test_boot_unit_runs_once_with_room_for_the_retry_phase(self):
        unit = (HERE / "cloud-init/cloud-init.yml").read_text()
        self.assertIn("Restart=no", unit)
        self.assertNotIn("Restart=on-failure", unit)
        timeout = int(unit.split("TimeoutStartSec=")[1].split()[0])
        self.assertGreater(timeout, boot.SECRET_DEADLINE_SECONDS + 90)

    def test_imds_and_vault_calls_refuse_redirects_and_proxies(self):
        handlers = [type(h).__name__ for h in boot.OPENER.handlers]
        self.assertIn("NoRedirect", handlers)
        # ProxyHandler({}) replaces the environment-proxy default and registers no proxy routes.
        with patch.dict(os.environ, {"http_proxy": "http://proxy.invalid:1", "https_proxy": "http://proxy.invalid:1"}):
            self.assertFalse(any(getattr(h, "proxies", None) for h in boot.OPENER.handlers))
        self.assertTrue(boot.IMDS.startswith("http://169.254.169.254/"))
        with self.assertRaises(ValueError):
            boot.read_secrets("bad.name/../x", "client")


class Template(unittest.TestCase):
    def test_bicep_embeds_reviewed_production_files(self):
        if shutil.which("az") is None:
            self.skipTest("az CLI not installed")
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "main.json"
            subprocess.run(["az", "bicep", "build", "--file", str(HERE / "main.bicep"), "--outfile", str(out)],
                           check=True, capture_output=True)
            text = out.read_text()
        for path in ["deploy/production/compose.yml", "deploy/production/nginx.conf",
                     "scripts/production.py", "deploy/azure/cloud-init/brigalow-boot.py"]:
            self.assertIn(base64.b64encode((ROOT / path).read_bytes()).decode(), text, path)
        template = json.loads(text)
        # Secrets are secure parameters only; no default values.
        for name, parameter in template["parameters"].items():
            if parameter["type"] == "securestring":
                self.assertNotIn("defaultValue", parameter, name)
        for name in ["postgresAdministratorPassword", "dbRuntimePassword", "loginStateKey",
                     "tlsCertificatePem", "tlsPrivateKeyPem"]:
            self.assertEqual(template["parameters"][name]["type"], "securestring", name)

    def test_example_parameters_hold_no_secrets(self):
        text = (HERE / "main.bicepparam.example").read_text()
        self.assertIn("getSecret(", text)
        self.assertNotIn("BEGIN", text)
        for line in text.splitlines():
            if "Password" in line or "loginStateKey" in line or "tlsPrivateKey" in line:
                self.assertTrue("getSecret(" in line or line.lstrip().startswith("//"), line)


if __name__ == "__main__":
    unittest.main()
