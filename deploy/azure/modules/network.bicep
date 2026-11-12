// VNet with three subnets: the VM, delegated PostgreSQL, and private endpoints.
param location string
param prefix string
@description('Source CIDR allowed to reach the TLS proxy on 443.')
param httpsSourceCidr string
@description('Allow SSH to the VM. Off by default.')
param enableSsh bool
@description('Source CIDR for SSH when enableSsh is true.')
param sshSourceCidr string
param addressPrefix string = '10.40.0.0/16'

var vmSubnet = cidrSubnet(addressPrefix, 24, 0)
var dbSubnet = cidrSubnet(addressPrefix, 24, 1)
var endpointSubnet = cidrSubnet(addressPrefix, 24, 2)

var sshRule = enableSsh ? [
  {
    name: 'allow-ssh-explicit'
    properties: {
      priority: 110
      direction: 'Inbound'
      access: 'Allow'
      protocol: 'Tcp'
      sourceAddressPrefix: sshSourceCidr
      sourcePortRange: '*'
      destinationAddressPrefix: vmSubnet
      destinationPortRange: '22'
    }
  }
] : []

resource vmNsg 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: '${prefix}-vm-nsg'
  location: location
  properties: {
    securityRules: concat([
      {
        name: 'allow-https-proxy'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: httpsSourceCidr
          sourcePortRange: '*'
          destinationAddressPrefix: vmSubnet
          destinationPortRange: '443'
        }
      }
    ], sshRule, [
      {
        name: 'deny-other-inbound'
        properties: {
          priority: 4000
          direction: 'Inbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
    ])
  }
}

resource dbNsg 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: '${prefix}-db-nsg'
  location: location
  properties: {
    securityRules: [
      {
        name: 'allow-postgres-from-vm'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: vmSubnet
          sourcePortRange: '*'
          destinationAddressPrefix: dbSubnet
          destinationPortRange: '5432'
        }
      }
      {
        name: 'deny-other-inbound'
        properties: {
          priority: 4000
          direction: 'Inbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
    ]
  }
}

resource endpointNsg 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: '${prefix}-pe-nsg'
  location: location
  properties: {
    securityRules: [
      {
        name: 'allow-https-from-vm'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: vmSubnet
          sourcePortRange: '*'
          destinationAddressPrefix: endpointSubnet
          destinationPortRange: '443'
        }
      }
      {
        name: 'deny-other-inbound'
        properties: {
          priority: 4000
          direction: 'Inbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
    ]
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: '${prefix}-vnet'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [addressPrefix]
    }
    subnets: [
      {
        name: 'vm'
        properties: {
          addressPrefix: vmSubnet
          networkSecurityGroup: { id: vmNsg.id }
        }
      }
      {
        name: 'postgres'
        properties: {
          addressPrefix: dbSubnet
          networkSecurityGroup: { id: dbNsg.id }
          delegations: [
            {
              name: 'postgres'
              properties: {
                serviceName: 'Microsoft.DBforPostgreSQL/flexibleServers'
              }
            }
          ]
        }
      }
      {
        name: 'endpoints'
        properties: {
          addressPrefix: endpointSubnet
          networkSecurityGroup: { id: endpointNsg.id }
          privateEndpointNetworkPolicies: 'Enabled'
        }
      }
    ]
  }
}

output vnetId string = vnet.id
output vmSubnetId string = vnet.properties.subnets[0].id
output dbSubnetId string = vnet.properties.subnets[1].id
output endpointSubnetId string = vnet.properties.subnets[2].id
