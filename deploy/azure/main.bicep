// Brigalow on Azure: single-instance reference with the Artifact Signing backend.
// Validate offline with `az bicep build --file deploy/azure/main.bicep`. Deploying creates billable
// resources; see deploy/azure/README.md. No HA: one VM, one server process.
targetScope = 'resourceGroup'

@description('Azure region for all resources.')
param location string = resourceGroup().location

@minLength(3)
@maxLength(12)
@description('Short lowercase prefix for resource names.')
param prefix string = 'brigalow'

// ----- Image and network -----
@description('Reviewed Brigalow production image pinned by digest, e.g. registry/brigalow@sha256:<64 hex>.')
param image string

@description('CIDR allowed to reach the TLS proxy on 443. Use your CI egress and admin ranges.')
param httpsSourceCidr string

@description('Open SSH (22) in the NSG. Off by default; prefer Azure Bastion or serial console.')
param enableSsh bool = false

@description('CIDR for SSH when enableSsh is true. Ignored otherwise.')
param sshSourceCidr string = '127.0.0.1/32'

@description('SSH public key for the VM admin user. Not a secret.')
param sshPublicKey string

param adminUsername string = 'brigalowadmin'
param vmSize string = 'Standard_D2s_v5'

// ----- PostgreSQL -----
@description('Owner/migration login for PostgreSQL. Never stored in Key Vault or on the VM.')
param postgresAdministratorLogin string = 'brigalow_owner'

@secure()
@description('Owner/migration password. Used only to create the server and by the separate bootstrap step.')
param postgresAdministratorPassword string

@secure()
@description('Password for the restricted runtime login (brigalow_runtime) you create during bootstrap.')
param dbRuntimePassword string

param postgresVersion string = '16'
param postgresSkuName string = 'Standard_B1ms'
param postgresSkuTier string = 'Burstable'
param postgresStorageSizeGB int = 32

// ----- Runtime secrets -----
@secure()
@description('Base64 of exactly 32 random bytes for [login_keys].')
param loginStateKey string

@secure()
@description('PEM TLS certificate chain for the public URL.')
param tlsCertificatePem string

@secure()
@description('PEM TLS private key for the public URL.')
param tlsPrivateKeyPem string

// ----- Brigalow configuration -----
@description('Public HTTPS URL users and CI reach, matching the TLS certificate.')
param publicUrl string

@description('Organisation UUID you will create with brigalow-admin org-create.')
param orgId string

@description('OIDC authorities (identity.json "authorities" array). Non-secret.')
param oidcAuthorities array

@description('Artifact Signing [[artifact_signing.bindings]] entries (TOML objects). Empty until bootstrap creates the project.')
param artifactSigningBindings array = []

@description('Base64 DER of the pinned Artifact Signing issuing root, or "-" until you have reviewed it.')
param artifactSigningRootDerBase64 string = '-'

// ----- Artifact Signing -----
@minLength(3)
@maxLength(24)
param signingAccountName string

@minLength(5)
@maxLength(100)
param certificateProfileName string

@allowed(['Basic', 'Premium'])
param signingSku string = 'Basic'

// PrivateTrustCIPolicy is omitted on purpose: Microsoft issues those certificates without the
// code-signing EKU, so Brigalow's leaf checks would refuse every result.
@allowed(['PrivateTrust', 'PublicTrust', 'PublicTrustTest', 'VBSEnclave'])
param certificateProfileType string

@description('Identity validation ID from the Azure portal. ARM cannot create it.')
param identityValidationId string

@description('Artifact Signing data-plane endpoint for this region, e.g. https://eus.codesigning.azure.net.')
param signingEndpoint string

resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${prefix}-id'
  location: location
}

module network 'modules/network.bicep' = {
  name: 'network'
  params: {
    location: location
    prefix: prefix
    httpsSourceCidr: httpsSourceCidr
    enableSsh: enableSsh
    sshSourceCidr: sshSourceCidr
  }
}

module postgres 'modules/postgres.bicep' = {
  name: 'postgres'
  params: {
    location: location
    prefix: prefix
    vnetId: network.outputs.vnetId
    delegatedSubnetId: network.outputs.dbSubnetId
    administratorLogin: postgresAdministratorLogin
    administratorPassword: postgresAdministratorPassword
    version: postgresVersion
    skuName: postgresSkuName
    skuTier: postgresSkuTier
    storageSizeGB: postgresStorageSizeGB
  }
}

module signing 'modules/signing.bicep' = {
  name: 'signing'
  params: {
    location: location
    accountName: signingAccountName
    profileName: certificateProfileName
    sku: signingSku
    profileType: certificateProfileType
    identityValidationId: identityValidationId
    signerPrincipalId: identity.properties.principalId
  }
}

var anchorLines = artifactSigningRootDerBase64 == '-' ? '' : '[[trust_anchors]]\nname = "artifact-signing-root"\ntier = "external-ca"\nfile = "/run/brigalow/artifact-signing-root.der"\n\n'
var bindingLines = join(map(artifactSigningBindings, b => '[[artifact_signing.bindings]]\nid = "${b.id}"\norg = "${b.org}"\nproject = "${b.project}"\npurpose = "${b.purpose}"\naccount = "${b.account}"\nprofile = "${b.profile}"\nanchor = "artifact-signing-root"\nprofile_eku = "${b.profileEku}"\n'), '\n')

// Runtime configuration only: restricted login, secret file paths, no owner credentials.
// Multi-line Bicep strings do not interpolate, so placeholders are filled with format().
var configTemplate = '''mode = "production"
bind = "0.0.0.0:8080"
backend = "artifact_signing"
backend_id = "azure-artifact-signing"
db_host = "{0}"
db_port = 5432
db_name = "brigalow"
db_user = "brigalow_runtime"
db_ca_file = "/run/brigalow/db-ca.pem"
db_password_file = "/run/brigalow/db-password"

[login_keys]
active = {{ id = "k1", file = "/run/brigalow/login-key" }}

{1}[artifact_signing]
endpoint = "{2}"
managed_identity_client_id = "{3}"
operation_timeout_seconds = 20

{4}'''
var configToml = format(configTemplate, postgres.outputs.fqdn, anchorLines, signingEndpoint, identity.properties.clientId, bindingLines)

var identityJson = string({
  public_url: publicUrl
  authorities: map(oidcAuthorities, a => union(a, { org_id: orgId }))
})

module keyvault 'modules/keyvault.bicep' = {
  name: 'keyvault'
  params: {
    location: location
    prefix: prefix
    vnetId: network.outputs.vnetId
    endpointSubnetId: network.outputs.endpointSubnetId
    readerPrincipalId: identity.properties.principalId
    dbRuntimePassword: dbRuntimePassword
    loginStateKey: loginStateKey
    tlsCertificatePem: tlsCertificatePem
    tlsPrivateKeyPem: tlsPrivateKeyPem
    image: image
    configToml: configToml
    identityJson: identityJson
    artifactSigningRootDerBase64: artifactSigningRootDerBase64
  }
}

module vm 'modules/vm.bicep' = {
  name: 'vm'
  params: {
    location: location
    prefix: prefix
    subnetId: network.outputs.vmSubnetId
    identityId: identity.id
    identityClientId: identity.properties.clientId
    vaultName: keyvault.outputs.vaultName
    vmSize: vmSize
    adminUsername: adminUsername
    sshPublicKey: sshPublicKey
  }
}

output publicIpAddress string = vm.outputs.publicIpAddress
output postgresFqdn string = postgres.outputs.fqdn
output keyVaultName string = keyvault.outputs.vaultName
output managedIdentityClientId string = identity.properties.clientId
output signingAccountUri string = signing.outputs.accountUri
output certificateProfileId string = signing.outputs.profileId
