"""Local-only single-instance chart checks. Never contacts a Kubernetes cluster."""
import subprocess
import json
egress=json.dumps([{"to":[{"ipBlock":{"cidr":"192.0.2.0/24"}}],"ports":[{"protocol":"TCP","port":443},{"protocol":"TCP","port":5432}]}])
args=["--set-json","networkPolicy.egress="+egress,"--set","image=example.invalid/brigalow@sha256:"+"0"*64,"--set","existingSecret=brigalow-test-only"]
subprocess.run(["helm","lint","deploy/helm/brigalow"]+args,check=True)
rendered=subprocess.check_output(["helm","template","brigalow","deploy/helm/brigalow"]+args,text=True)
assert "type: ClusterIP" in rendered and "automountServiceAccountToken: false" in rendered and "chmod 0600" in rendered
assert subprocess.run(["helm","template","brigalow","deploy/helm/brigalow"],capture_output=True).returncode!=0
assert subprocess.run(["helm","template","brigalow","deploy/helm/brigalow","--set","existingSecret=test","--set","image=example.invalid/brigalow:latest"],capture_output=True).returncode!=0

assert "kind: NetworkPolicy" in rendered and "policyTypes: [Ingress, Egress]" in rendered
assert "type: Recreate" in rendered
assert "value: production" in rendered and "path: /livez" in rendered
assert subprocess.run(["helm","template","brigalow","deploy/helm/brigalow"]+args+["--set","replicas=2"],capture_output=True).returncode!=0
assert subprocess.run(["helm","template","brigalow","deploy/helm/brigalow"]+args+["--set-json","networkPolicy.egress=[]"],capture_output=True).returncode!=0
print("AT-OPS-05: immutable image, single replica, restricted pod and explicit network policy enforced")
