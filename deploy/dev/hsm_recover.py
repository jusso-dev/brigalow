"""Validate only the disposable harness token against its restored public DB reference."""
import os
import pathlib
import subprocess
env = os.environ.copy()
env["BRIGALOW_TEST_HSM_PIN"] = pathlib.Path("/tmp/recovery-pin").read_text()
env["BRIGALOW_TEST_HSM_MODULE"] = "/usr/lib/softhsm/libsofthsm2.so"
env["BRIGALOW_RECOVERY_CHECK"] = "1"
subprocess.run(["/recovery-tests"], env=env, check=True)
