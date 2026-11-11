"""Local-only draft chart checks. Never contacts a Kubernetes cluster."""
import subprocess
args=["--set","image=example.invalid/brigalow@sha256:"+"0"*64,"--set","existingSecret=brigalow-test-only"]
subprocess.run(["helm","lint","deploy/helm/brigalow"]+args,check=True)
rendered=subprocess.check_output(["helm","template","brigalow","deploy/helm/brigalow"]+args,text=True)
assert "type: ClusterIP" in rendered and "automountServiceAccountToken: false" in rendered and "chmod 0600" in rendered
assert subprocess.run(["helm","template","brigalow","deploy/helm/brigalow"],capture_output=True).returncode!=0
assert subprocess.run(["helm","template","brigalow","deploy/helm/brigalow","--set","existingSecret=test","--set","image=example.invalid/brigalow:latest"],capture_output=True).returncode!=0
