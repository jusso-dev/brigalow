// Optional [tsa] section for the runtime config.toml. Imported by main.bicep, and evaluated offline
// by test_azure.py through `az bicep build-params`. An empty URL means no [tsa] section: timestamps
// stay unavailable and policies must use timestamp = "disabled" (or "optional").
// The TSA signer and anchor are public certificates. They reach the VM as Key Vault secrets, like
// the Artifact Signing root, and brigalow-boot.py writes them as 0600 files owned by UID 10001.

@export()
@description('Renders the [tsa] section, or an empty string when url is empty. Fails on a non-HTTPS URL or a half-configured TSA.')
func tsaSection(url string, signerDerBase64 string, anchorDerBase64 string) string => empty(url)
  ? (signerDerBase64 == '-' && anchorDerBase64 == '-'
      ? ''
      : fail('tsaSignerDerBase64 and tsaAnchorDerBase64 must be "-" when tsaUrl is empty.'))
  : (!startsWith(url, 'https://')
      ? fail('tsaUrl must be an https:// URL. Brigalow does not support HTTP TSAs, including Microsoft\'s http://timestamp.acs.microsoft.com.')
      : (contains(url, '"') || contains(url, '\\') || contains(url, ' ') || contains(url, '\n')
          ? fail('tsaUrl must not contain quotes, backslashes or whitespace.')
          : (signerDerBase64 == '-' || anchorDerBase64 == '-'
              ? fail('tsaUrl needs both tsaSignerDerBase64 and tsaAnchorDerBase64.')
              : '[tsa]\nurl = "${url}"\nsigner_file = "/run/brigalow/tsa-signer.der"\nanchors = ["/run/brigalow/tsa-anchor.der"]\n\n')))
