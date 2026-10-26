targetScope = 'resourceGroup'
@allowed(['cmpsso'])
param prefix string = 'cmpsso'
@allowed(['indonesiacentral'])
param location string = 'indonesiacentral'
param vaultUri string
param postgresHost string
param frontendOrigin string
@allowed(['aaaabbbb-0000-cccc-1111-dddd2222eeee'])
param tenantId string
param sshPublicKey string
param vmSize string = 'Standard_D2s_v5'
param tags object = { workload: 'cmp-sso', environment: 'poc' }
var effectiveTags = union(tags, { costcontrol: 'ignore' })
var label = '${prefix}-${take(uniqueString(subscription().id, resourceGroup().id), 10)}'
var publicRules = [for (port, i) in ['443', '80']: {
  name: 'HttpsAcme-${port}'
  properties: {
    priority: 100 + i
    direction: 'Inbound'
    access: 'Allow'
    protocol: 'Tcp'
    sourcePortRange: '*'
    destinationPortRange: port
    sourceAddressPrefix: 'Internet'
    destinationAddressPrefix: '*'
  }
}]
resource vnet 'Microsoft.Network/virtualNetworks@2024-05-01' existing = { name: '${prefix}-vnet' }
resource ip 'Microsoft.Network/publicIPAddresses@2024-05-01' = {
  name: '${prefix}-keycloak-ip'
  location: location
  tags: effectiveTags
  sku: { name: 'Standard' }
  properties: {
    publicIPAllocationMethod: 'Static'
    dnsSettings: { domainNameLabel: label }
  }
}
resource nsg 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: '${prefix}-keycloak-nsg'
  location: location
  tags: effectiveTags
  properties: {
    securityRules: concat(publicRules, [{
      name: 'DenyOtherInbound'
      properties: {
        priority: 200
        direction: 'Inbound'
        access: 'Deny'
        protocol: '*'
        sourcePortRange: '*'
        destinationPortRange: '*'
        sourceAddressPrefix: '*'
        destinationAddressPrefix: '*'
      }
    }])
  }
}
resource nic 'Microsoft.Network/networkInterfaces@2024-05-01' = {
  name: '${prefix}-keycloak-nic'
  location: location
  tags: effectiveTags
  properties: {
    networkSecurityGroup: { id: nsg.id }
    ipConfigurations: [{
      name: 'primary'
      properties: {
        privateIPAllocationMethod: 'Static'
        privateIPAddress: '10.42.4.4'
        subnet: { id: '${vnet.id}/subnets/keycloak' }
        publicIPAddress: { id: ip.id }
      }
    }]
  }
}
var origin = 'https://${label}.${location}.cloudapp.azure.com'
var config = { vault_uri: vaultUri, host: postgresHost, origin: origin, frontend_origin: frontendOrigin, tenant_id: tenantId }
var cloudInit = replace(
  replace(loadTextContent('sso-keycloak-cloud-init.yml'), '__INSTALLER_BASE64__', base64(loadTextContent('../bootstrap/sso-keycloak.py'))),
  '__CONFIG_BASE64__', base64(string(config)))
resource vm 'Microsoft.Compute/virtualMachines@2024-07-01' = {
  name: '${prefix}-keycloak-vm'
  location: location
  tags: effectiveTags
  identity: { type: 'SystemAssigned' }
  properties: {
    hardwareProfile: { vmSize: vmSize }
    securityProfile: { securityType: 'TrustedLaunch', uefiSettings: { secureBootEnabled: true, vTpmEnabled: true } }
    storageProfile: {
      diskControllerType: 'SCSI'
      imageReference: { publisher: 'Canonical', offer: 'ubuntu-24_04-lts', sku: 'server', version: 'latest' }
      osDisk: {
        name: '${prefix}-keycloak-os'
        createOption: 'FromImage'
        deleteOption: 'Detach'
        managedDisk: { storageAccountType: 'Premium_LRS' }
      }
    }
    osProfile: {
      computerName: '${prefix}-keycloak'
      adminUsername: 'cmpvmadmin'
      customData: base64(cloudInit)
      linuxConfiguration: {
        disablePasswordAuthentication: true
        provisionVMAgent: true
        ssh: { publicKeys: [{ path: '/home/cmpvmadmin/.ssh/authorized_keys', keyData: sshPublicKey }] }
      }
    }
    networkProfile: { networkInterfaces: [{ id: nic.id, properties: { deleteOption: 'Detach' } }] }
  }
}
resource osDisk 'Microsoft.Compute/disks@2024-03-02' existing = { name: '${prefix}-keycloak-os' }
resource diskTags 'Microsoft.Resources/tags@2021-04-01' = {
  scope: osDisk
  name: 'default'
  properties: { tags: effectiveTags }
  dependsOn: [vm]
}
output keycloak object = {
  origin: origin
  vmId: vm.id
  principalId: vm.identity.principalId
  metadataUrl: '${origin}/realms/cmp-pdf/protocol/saml/descriptor'
  issuer: '${origin}/realms/cmp-pdf'
}
