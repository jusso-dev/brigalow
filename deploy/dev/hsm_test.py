"""Initialise only the disposable Compose token; PINs generated at runtime."""
import os
import secrets
import subprocess
pin = secrets.token_hex(24)
so_pin = secrets.token_hex(24)
subprocess.run(["softhsm2-util", "--init-token", "--free", "--label", "brigalow-test", "--pin", pin, "--so-pin", so_pin], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
env = os.environ.copy()
env["BRIGALOW_TEST_HSM_PIN"] = pin
env["BRIGALOW_TEST_HSM_MODULE"] = "/usr/lib/softhsm/libsofthsm2.so"
subprocess.run(["/crypto-tests", "--nocapture"], env=env, check=True)
subprocess.run(["/ca-tests", "--nocapture"], env=env, check=True)
