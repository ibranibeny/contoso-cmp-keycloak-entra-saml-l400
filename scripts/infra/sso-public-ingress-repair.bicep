targetScope = 'resourceGroup'

resource subnetNsg 'Microsoft.Network/networkSecurityGroups@2024-05-01' existing = {
  name: 'cmpsso-vnet-keycloak-nsg-indonesiacentral'
}

resource publicIngress 'Microsoft.Network/networkSecurityGroups/securityRules@2024-05-01' = [for (port, index) in ['443', '80']: {
  parent: subnetNsg
  name: 'HttpsAcme-${port}'
  properties: {
    priority: 100 + index
    direction: 'Inbound'
    access: 'Allow'
    protocol: 'Tcp'
    sourcePortRange: '*'
    destinationPortRange: port
    sourceAddressPrefix: 'Internet'
    destinationAddressPrefix: '10.42.4.4'
    description: 'Restore only the existing Keycloak HTTPS and ACME ingress'
  }
}]
