targetScope = 'resourceGroup'
param prefix string
param vaultName string
@allowed(['indonesiacentral'])
param location string = 'indonesiacentral'
param tags object = { workload: 'entra-cmp', environment: 'poc' }
var effectiveTags = union(tags, { costcontrol: 'ignore' })

resource vnet 'Microsoft.Network/virtualNetworks@2024-05-01' existing ={
  name: '${prefix}-vnet'
}
resource vault 'Microsoft.KeyVault/vaults@2023-07-01' existing = {
  name: vaultName
}
resource subnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' = {
  parent: vnet
  name: 'private-endpoints'
  properties: {
    addressPrefix: '10.42.3.0/24'
    privateEndpointNetworkPolicies: 'Disabled'
    defaultOutboundAccess: false
  }
}
resource zone 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  name: 'privatelink.vaultcore.azure.net'
  location: 'global'
  tags: effectiveTags
}
resource link 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: zone
  name: '${prefix}-vault-link'
  location: 'global'
  tags: effectiveTags
  properties: {
    registrationEnabled: false
    virtualNetwork: { id: vnet.id }
  }
}
resource endpoint 'Microsoft.Network/privateEndpoints@2024-05-01' = {
  name: '${prefix}-vault-pe'
  location: location
  tags: effectiveTags
  properties: {
    customNetworkInterfaceName: '${prefix}-vault-pe-nic'
    subnet: { id: subnet.id }
    privateLinkServiceConnections: [{
      name: '${prefix}-vault'
      properties: {
        privateLinkServiceId: vault.id
        groupIds: ['vault']
      }
    }]
  }
}
resource zoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-05-01' = {
  parent: endpoint
  name: 'vault'
  properties: {
    privateDnsZoneConfigs: [{
      name: 'vault'
      properties: { privateDnsZoneId: zone.id }
    }]
  }
}
resource nic 'Microsoft.Network/networkInterfaces@2024-05-01' existing = {
  name: '${prefix}-vault-pe-nic'
}
resource nicTags 'Microsoft.Resources/tags@2021-04-01' = {
  scope: nic
  name: 'default'
  properties: { tags: effectiveTags }
  dependsOn: [endpoint]
}
output privateEndpointId string = endpoint.id
