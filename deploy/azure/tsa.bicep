// Optional [tsa] section for the runtime config.toml. Imported by main.bicep. An empty URL means no
// [tsa] section: timestamps stay unavailable and policies must use timestamp = "disabled" (or
// "optional").
// The TSA signer and anchor are public certificates. They reach the VM as Key Vault secrets, like
// the Artifact Signing root, and brigalow-boot.py writes them as 0600 files owned by UID 10001.
//
// tsaProblem and tsaRender are pure, so test_azure.py can evaluate them offline with
// `bicep build-params`. Bicep 0.49+ refuses `fail()` in a .bicepparam file (BCP452), so only
// tsaSection, which main.bicep uses at deployment time, calls fail().

@export()
@description('Empty when the TSA parameters are valid, otherwise the reason they are refused.')
func tsaProblem(url string, signerDerBase64 string, anchorDerBase64 string) string => empty(url)
  ? (signerDerBase64 == '-' && anchorDerBase64 == '-'
      ? ''
      : 'tsaSignerDerBase64 and tsaAnchorDerBase64 must be "-" when tsaUrl is empty.')
  : (!startsWith(url, 'https://')
      ? 'tsaUrl must be an https:// URL. Brigalow does not support HTTP TSAs, including Microsoft\'s http://timestamp.acs.microsoft.com.'
      : (contains(url, '"') || contains(url, '\\') || contains(url, ' ') || contains(url, '\n')
          ? 'tsaUrl must not contain quotes, backslashes or whitespace.'
          : (signerDerBase64 == '-' || anchorDerBase64 == '-'
              ? 'tsaUrl needs both tsaSignerDerBase64 and tsaAnchorDerBase64.'
              : '')))

@export()
@description('The [tsa] section for a valid, non-empty URL, or an empty string when url is empty.')
func tsaRender(url string) string => empty(url)
  ? ''
  : '[tsa]\nurl = "${url}"\nsigner_file = "/run/brigalow/tsa-signer.der"\nanchors = ["/run/brigalow/tsa-anchor.der"]\n\n'

@export()
@description('Renders the [tsa] section, or an empty string when url is empty. Fails the deployment on any tsaProblem.')
func tsaSection(url string, signerDerBase64 string, anchorDerBase64 string) string => empty(tsaProblem(url, signerDerBase64, anchorDerBase64))
  ? tsaRender(url)
  : fail(tsaProblem(url, signerDerBase64, anchorDerBase64))
