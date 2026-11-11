import importlib.util
import io
import json
import pathlib
import secrets
import unittest
import urllib.parse
import uuid
from unittest.mock import patch, Mock

spec = importlib.util.spec_from_file_location("action_sign", pathlib.Path(__file__).with_name("sign.py"))
action = importlib.util.module_from_spec(spec)
spec.loader.exec_module(action)

class Wrapper(unittest.TestCase):
    def test_scoped_audience_environment_only_and_no_mint_credential_in_child(self):
        org = str(uuid.uuid4())
        credential, token = secrets.token_urlsafe(32), secrets.token_urlsafe(64)
        env = {"BRIGALOW_INPUT_ORG": org, "ACTIONS_ID_TOKEN_REQUEST_URL": "https://oidc.example/token?audience=wrong",
               "ACTIONS_ID_TOKEN_REQUEST_TOKEN": credential, "BRIGALOW_BINARY": "/generated/brig",
               "BRIGALOW_INPUT_SERVER": "https://signer.example", "BRIGALOW_INPUT_PROJECT": str(uuid.uuid4()),
               "BRIGALOW_INPUT_POLICY": "release", "BRIGALOW_INPUT_OUTPUT": "artifact.sig",
               "BRIGALOW_INPUT_FORMAT": "raw", "BRIGALOW_INPUT_FILE": "artifact.bin"}
        client = Mock()
        client.open.return_value = io.BytesIO(json.dumps({"value": token}).encode())
        with patch.object(action.urllib.request, "build_opener", return_value=client), patch.object(action.subprocess, "run") as run:
            action.sign(env)
        request = client.open.call_args.args[0]
        self.assertEqual(urllib.parse.parse_qs(urllib.parse.urlsplit(request.full_url).query), {"audience": ["brigalow:" + org]})
        self.assertEqual(request.headers["Authorization"], "Bearer " + credential)
        self.assertEqual(run.call_args.kwargs["env"]["BRIGALOW_TOKEN"], token)
        self.assertNotIn("ACTIONS_ID_TOKEN_REQUEST_TOKEN", run.call_args.kwargs["env"])
        self.assertNotIn(token, str(run.call_args.args))
        self.assertNotIn(credential, str(run.call_args.args))
        self.assertNotIn("BRIGALOW_TOKEN", env)

    def test_redirects_and_plaintext_refused(self):
        with self.assertRaises(ValueError):
            action.NoRedirect().redirect_request(None)
        with self.assertRaises(ValueError):
            action.sign({"BRIGALOW_INPUT_ORG":str(uuid.uuid4()), "ACTIONS_ID_TOKEN_REQUEST_URL":"http://localhost/token"})

if __name__ == "__main__":
    unittest.main()
