// Key Vault: RBAC authorisation, purge protection, private endpoint only. Holds runtime secrets
// and the boot-time configuration. Secrets are created through ARM (control plane), which the
// vault firewall does not block. The VM reads them over the private endpoint at boot.
param location string
param prefix string
param vnetId string
param endpointSubnetId string
@description('Principal that may read secrets at boot (the VM boot identity).')
param readerPrincipalId string
param tenantId string = subscription().tenantId

@secure()
param dbRuntimePassword string
@secure()
param loginStateKey string
@secure()
param tlsCertificatePem string
@secure()
param tlsPrivateKeyPem string
@description('Reviewed image reference pinned by digest.')
param image string
@description('Brigalow config.toml contents (non-secret).')
param configToml string
@description('identity.json contents (non-secret).')
param identityJson string
@description('Base64 DER of the pinned Artifact Signing root, or "-" when not yet pinned.')
param artifactSigningRootDerBase64 string
@description('Base64 DER of the pinned TSA signer, or "-" when no TSA is configured.')
param tsaSignerDerBase64 string
@description('Base64 DER of the TSA signer\'s CA, or "-" when no TSA is configured.')
param tsaAnchorDerBase64 string

var vaultName = take('${prefix}kv${uniqueString(resourceGroup().id)}', 24)
// Built-in role "Key Vault Secrets User": read secret values only.
var secretsUserRoleId = '4633458b-17de-408a-b874-0445c86b69e6'

resource vault 'Microsoft.KeyVault/vaults@2024-11-01' = {
  name: vaultName
  location: location
  properties: {
    tenantId: tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableRbacAuthorization: true
    enablePurgeProtection: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    publicNetworkAccess: 'Disabled'
    networkAcls: {
      bypass: 'None'
      defaultAction: 'Deny'
    }
  }
}

var secrets = [
  { name: 'brigalow-db-runtime-password', value: dbRuntimePassword }
  { name: 'brigalow-login-state-key', value: loginStateKey }
  { name: 'brigalow-tls-crt', value: tlsCertificatePem }
  { name: 'brigalow-tls-key', value: tlsPrivateKeyPem }
  { name: 'brigalow-image', value: image }
  { name: 'brigalow-config-toml', value: configToml }
  { name: 'brigalow-identity-json', value: identityJson }
  { name: 'brigalow-artifact-signing-root', value: artifactSigningRootDerBase64 }
  { name: 'brigalow-tsa-signer', value: tsaSignerDerBase64 }
  { name: 'brigalow-tsa-anchor', value: tsaAnchorDerBase64 }
]

resource secret 'Microsoft.KeyVault/vaults/secrets@2024-11-01' = [for item in secrets: {
  parent: vault
  name: item.name
  properties: {
    value: item.value
    contentType: 'text/plain'
  }
}]

resource reader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: vault
  name: guid(vault.id, readerPrincipalId, secretsUserRoleId)
  properties: {
    principalId: readerPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', secretsUserRoleId)
  }
}

resource dnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  name: 'privatelink.vaultcore.azure.net'
  location: 'global'
}

resource dnsLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: dnsZone
  name: '${prefix}-kv-link'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: { id: vnetId }
  }
}

resource endpoint 'Microsoft.Network/privateEndpoints@2024-05-01' = {
  name: '${prefix}-kv-pe'
  location: location
  properties: {
    subnet: { id: endpointSubnetId }
    privateLinkServiceConnections: [
      {
        name: 'vault'
        properties: {
          privateLinkServiceId: vault.id
          groupIds: ['vault']
        }
      }
    ]
  }
}

resource endpointDns 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-05-01' = {
  parent: endpoint
  name: 'vault'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'vault'
        properties: { privateDnsZoneId: dnsZone.id }
      }
    ]
  }
}

output vaultName string = vault.name
output vaultId string = vault.id
