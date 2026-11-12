// Artifact Signing account and one certificate profile. The signer identity gets only the
// "Artifact Signing Certificate Profile Signer" role, scoped to this profile.
param location string
@minLength(3)
@maxLength(24)
param accountName string
@minLength(5)
@maxLength(100)
param profileName string
@allowed(['Basic', 'Premium'])
param sku string
@allowed(['PrivateTrust', 'PrivateTrustCIPolicy', 'PublicTrust', 'PublicTrustTest', 'VBSEnclave'])
param profileType string
@description('Identity validation ID from the portal. It cannot be created through ARM.')
param identityValidationId string
param signerPrincipalId string

// Built-in role "Artifact Signing Certificate Profile Signer" (formerly Trusted Signing /
// Code Signing Certificate Profile Signer). Data action:
// Microsoft.CodeSigning/certificateProfiles/Sign/action.
var profileSignerRoleId = '2837e146-70d7-4cfd-ad55-7efa6464f958'

resource account 'Microsoft.CodeSigning/codeSigningAccounts@2025-10-13' = {
  name: accountName
  location: location
  properties: {
    sku: {
      name: sku
    }
  }
}

resource profile 'Microsoft.CodeSigning/codeSigningAccounts/certificateProfiles@2025-10-13' = {
  parent: account
  name: profileName
  properties: {
    profileType: profileType
    identityValidationId: identityValidationId
    includeStreetAddress: false
    includePostalCode: false
  }
}

resource signer 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: profile
  name: guid(profile.id, signerPrincipalId, profileSignerRoleId)
  properties: {
    principalId: signerPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', profileSignerRoleId)
  }
}

output accountUri string = account.properties.accountUri
output accountName string = account.name
output profileName string = profile.name
output profileId string = profile.id
