"""Input guards only; never deploy or contact Docker."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from production import validate


class ProductionInputs(unittest.TestCase):
    def test_digest_and_private_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env = {"BRIGALOW_IMAGE": "example.invalid/brigalow@sha256:" + "1" * 64}
            for name, files in [("BRIGALOW_CONFIG_DIR", ["config.toml", "identity.json"]),
                                ("BRIGALOW_TLS_DIR", ["tls.crt", "tls.key"])]:
                path = root / name
                path.mkdir(mode=0o700)
                env[name] = str(path)
                for file in files:
                    (path / file).touch(mode=0o600)
            original = Path.lstat
            wrong_owner = set()
            def owned(path):
                values = list(original(path))
                uid = 10001 if "BRIGALOW_CONFIG_DIR" in path.parts else 101
                values[4] = 0 if str(path) in wrong_owner else uid
                return os.stat_result(values)
            with patch.object(Path, "lstat", owned):
                self.assert_valid_and_rejections(env, wrong_owner)

    def assert_valid_and_rejections(self, env, wrong_owner):
        validate(env)
        for name in ["BRIGALOW_CONFIG_DIR", "BRIGALOW_TLS_DIR"]:
            directory = Path(env[name])
            for target in [directory, *directory.iterdir()]:
                wrong_owner.add(str(target))
                with self.assertRaises(ValueError): validate(env)
                wrong_owner.clear()
        for image in ["example.invalid/brigalow:latest", "", "image@sha256:bad"]:
            with self.assertRaises(ValueError): validate(dict(env, BRIGALOW_IMAGE=image))
        config = Path(env["BRIGALOW_CONFIG_DIR"])
        config.chmod(0o755)
        with self.assertRaises(ValueError): validate(env)
        config.chmod(0o700)
        file = config / "config.toml"
        file.chmod(0o644)
        with self.assertRaises(ValueError): validate(env)
        file.chmod(0o600)
        link = config / "linked"
        link.symlink_to(file)
        with self.assertRaises(ValueError): validate(env)
        link.unlink()
        file.unlink()
        with self.assertRaises(ValueError): validate(env)

if __name__ == "__main__":
    unittest.main()
