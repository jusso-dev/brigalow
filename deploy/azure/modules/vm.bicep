// One Linux VM running the repository's deploy/production Compose reference through
// scripts/production.py. Cloud-init embeds those files unchanged; secrets are read from Key Vault
// into tmpfs at every boot by brigalow-boot.py. One replica only: there is no scale set.
param location string
param prefix string
param subnetId string
param identityId string
param identityClientId string
param vaultName string
param vmSize string
param adminUsername string
@description('SSH public key (not a secret). Required by Azure even when SSH is closed in the NSG.')
param sshPublicKey string

var cloudInit = replace(replace(replace(replace(replace(replace(
  loadTextContent('../cloud-init/cloud-init.yml'),
  '__COMPOSE__', loadFileAsBase64('../../production/compose.yml')),
  '__NGINX__', loadFileAsBase64('../../production/nginx.conf')),
  '__PRODUCTION__', loadFileAsBase64('../../../scripts/production.py')),
  '__BOOT__', loadFileAsBase64('../cloud-init/brigalow-boot.py')),
  '__VAULT__', vaultName),
  '__CLIENT_ID__', identityClientId)

resource publicIp 'Microsoft.Network/publicIPAddresses@2024-05-01' = {
  name: '${prefix}-pip'
  location: location
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
    publicIPAddressVersion: 'IPv4'
  }
}

resource nic 'Microsoft.Network/networkInterfaces@2024-05-01' = {
  name: '${prefix}-nic'
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'primary'
        properties: {
          subnet: { id: subnetId }
          privateIPAllocationMethod: 'Dynamic'
          publicIPAddress: { id: publicIp.id }
        }
      }
    ]
  }
}

resource vm 'Microsoft.Compute/virtualMachines@2024-07-01' = {
  name: '${prefix}-vm'
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${identityId}': {}
    }
  }
  properties: {
    hardwareProfile: {
      vmSize: vmSize
    }
    securityProfile: {
      securityType: 'TrustedLaunch'
      uefiSettings: {
        secureBootEnabled: true
        vTpmEnabled: true
      }
    }
    osProfile: {
      computerName: '${prefix}-vm'
      adminUsername: adminUsername
      customData: base64(cloudInit)
      linuxConfiguration: {
        disablePasswordAuthentication: true
        ssh: {
          publicKeys: [
            {
              path: '/home/${adminUsername}/.ssh/authorized_keys'
              keyData: sshPublicKey
            }
          ]
        }
        patchSettings: {
          patchMode: 'AutomaticByPlatform'
          assessmentMode: 'AutomaticByPlatform'
        }
      }
    }
    storageProfile: {
      imageReference: {
        publisher: 'Canonical'
        offer: 'ubuntu-24_04-lts'
        sku: 'server'
        version: 'latest'
      }
      osDisk: {
        createOption: 'FromImage'
        managedDisk: {
          storageAccountType: 'Premium_LRS'
        }
        deleteOption: 'Delete'
      }
    }
    networkProfile: {
      networkInterfaces: [
        { id: nic.id }
      ]
    }
  }
}

output publicIpAddress string = publicIp.properties.ipAddress
output vmName string = vm.name
