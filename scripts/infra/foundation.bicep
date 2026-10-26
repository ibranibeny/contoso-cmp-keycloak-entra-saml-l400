targetScope = 'resourceGroup'

@minLength(3)
@maxLength(12)
@description('Lowercase alphanumeric prefix beginning with a letter; deploy.ps1 validates the pattern.')
param prefix string
@allowed(['indonesiacentral'])
param location string = 'indonesiacentral'
@allowed(['cmpbootstrap'])
param postgresAdminUsername string = 'cmpbootstrap'
@description('Object ID of the explicitly signed-in deployment user, recorded for commissioning context. No vault-wide data-plane role is granted.')
param deploymentPrincipalId string
@allowed(['Basic', 'Standard', 'Premium'])
param registrySku string = 'Basic'
param postgresVmSize string = 'Standard_D2s_v5'
@minLength(40)
@description('SSH public key only. No private key is generated or accepted. Port 22 remains denied.')
param sshPublicKey string
@description('Default-off isolated SSO PoC only. Never enable on an existing non-SSO foundation.')
param ssoMode bool = false
@minValue(64)
param postgresDataDiskGiB int = 64
@allowed(['Premium_LRS'])
param postgresDataDiskSku string = 'Premium_LRS'
@description('Single-region POC: no zone HA, no multi-region failover, one replica per application.')
param tags object = { workload: 'entra-cmp', environment: 'poc' }
var effectiveTags = union(tags, { costcontrol: 'ignore' })

var suffix = uniqueString(subscription().id, resourceGroup().id, prefix)
var names = {
  registry: '${prefix}${suffix}acr'
  vault: '${prefix}-${take(suffix, 6)}-kv'
  postgres: '${prefix}-postgres-vm'
  environment: '${prefix}-env'
}
resource registry 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: names.registry
  location: location
  tags: effectiveTags
  sku: { name: registrySku }
  properties: {
    adminUserEnabled: false
    publicNetworkAccess: 'Enabled'
  }
}
resource identities 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = [for role in ['frontend', 'backend', 'keycloak', 'dbbootstrap']: {
  name: '${prefix}-${role}-id'
  location: location
  tags: effectiveTags
}]
resource pulls 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for (role, index) in ['frontend', 'backend', 'keycloak', 'dbbootstrap']: {
  scope: registry
  name: guid(registry.id, identities[index].id, 'acrpull')
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '7f951dda-4ed3-4680-a7ca-43fe172d538d')
    principalId: identities[index].properties.principalId
    principalType: 'ServicePrincipal'
  }
}]
resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: names.vault
  location: location
  tags: effectiveTags
  properties: {
    tenantId: tenant().tenantId
    sku: { name: 'standard', family: 'A' }
    enableRbacAuthorization: true
    enableSoftDelete: true
    enablePurgeProtection: true
    enabledForTemplateDeployment: !ssoMode
    softDeleteRetentionInDays: 90
    publicNetworkAccess: 'Disabled'
    networkAcls: { bypass: 'None', defaultAction: 'Deny' }
  }
}
resource egressIp 'Microsoft.Network/publicIPAddresses@2024-05-01' = {
  name: '${prefix}-postgres-egress'
  location: location
  tags: effectiveTags
  sku: { name: 'Standard' }
  properties: { publicIPAllocationMethod: 'Static' }
}
resource postgresNat 'Microsoft.Network/natGateways@2024-05-01' = {
  name: '${prefix}-postgres-nat'
  location: location
  tags: effectiveTags
  sku: { name: 'Standard' }
  properties: {
    idleTimeoutInMinutes: 10
    publicIpAddresses: [{ id: egressIp.id }]
  }
}
resource postgresNsg 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: '${prefix}-postgres-nsg'
  location: location
  tags: effectiveTags
  properties: {
    securityRules: concat([
      {
        name: 'PostgresFromContainerApps'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '5432'
          sourceAddressPrefix: '10.42.0.0/23'
          destinationAddressPrefix: '10.42.2.4'
        }
      }
      {
        name: 'DenyOtherPostgres'
        properties: {
          priority: 110
          direction: 'Inbound'
          access: 'Deny'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '5432'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
        }
      }
      {
        name: 'DenySsh'
        properties: {
          priority: 120
          direction: 'Inbound'
          access: 'Deny'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '22'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
        }
      }
      {
        name: 'DenyOtherInbound'
        properties: {
          priority: 130
          direction: 'Inbound'
          access: 'Deny'
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRange: '*'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
        }
      }
    ], ssoMode ? [{
      name: 'PostgresFromKeycloakVm'
      properties: {
        priority: 105
        direction: 'Inbound'
        access: 'Allow'
        protocol: 'Tcp'
        sourcePortRange: '*'
        destinationPortRange: '5432'
        sourceAddressPrefix: '10.42.4.0/24'
        destinationAddressPrefix: '10.42.2.4'
      }
    }] : [])
  }
}
resource vnet 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: '${prefix}-vnet'
  location: location
  tags: effectiveTags
  properties: {
    addressSpace: { addressPrefixes: ['10.42.0.0/16'] }
    subnets: concat([
      {
        name: 'container-apps'
        properties: {
          addressPrefix: '10.42.0.0/23'
          delegations: [{
            name: 'container-apps'
            properties: { serviceName: 'Microsoft.App/environments' }
          }]
        }
      }
      {
        name: 'postgres'
        properties: {
          addressPrefix: '10.42.2.0/24'
          defaultOutboundAccess: false
          natGateway: { id: postgresNat.id }
          networkSecurityGroup: { id: postgresNsg.id }
        }
      }
      {
        name: 'private-endpoints'
        properties: {
          addressPrefix: '10.42.3.0/24'
          privateEndpointNetworkPolicies: 'Disabled'
          defaultOutboundAccess: false
        }
      }
    ], ssoMode ? [{
      name: 'keycloak'
      properties: {
        addressPrefix: '10.42.4.0/24'
        defaultOutboundAccess: false
        natGateway: { id: postgresNat.id }
      }
    }] : [])
  }
}
resource postgresDns 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  name: '${prefix}.internal'
  location: 'global'
  tags: effectiveTags
}
resource dnsLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: postgresDns
  name: '${prefix}-link'
  location: 'global'
  tags: effectiveTags
  properties: {
    registrationEnabled: false
    virtualNetwork: { id: vnet.id }
  }
}
resource postgresRecord 'Microsoft.Network/privateDnsZones/A@2024-06-01' = {
  parent: postgresDns
  name: 'postgres'
  properties: { ttl: 300, aRecords: [{ ipv4Address: '10.42.2.4' }] }
}
resource postgresData 'Microsoft.Compute/disks@2024-03-02' = {
  name: '${prefix}-postgres-data'
  location: location
  tags: effectiveTags
  sku: { name: postgresDataDiskSku }
  properties: {
    creationData: { createOption: 'Empty' }
    diskSizeGB: postgresDataDiskGiB
  }
}
resource postgresNic 'Microsoft.Network/networkInterfaces@2024-05-01' = {
  name: '${prefix}-postgres-nic'
  location: location
  tags: effectiveTags
  properties: {
    ipConfigurations: [{
      name: 'private'
      properties: {
        privateIPAllocationMethod: 'Static'
        privateIPAddress: '10.42.2.4'
        subnet: { id: '${vnet.id}/subnets/postgres' }
      }
    }]
  }
}
var vmConfig = {
  version: 'cmp-bootstrap-config-v1'
  vault_uri: vault.properties.vaultUri
  host: 'postgres.${postgresDns.name}'
  ip: '10.42.2.4'
  admin: postgresAdminUsername
}
var legacyCloudInit = replace(
  replace(loadTextContent('postgres-cloud-init.yml'), '__INSTALLER_BASE64__', base64(loadTextContent('../bootstrap/postgres-vm.py'))),
  '__CONFIG_BASE64__', base64(string(vmConfig))
)
var ssoCloudInit = replace(
  replace(
    replace(loadTextContent('sso-postgres-cloud-init.yml'),
      '__COMMON_BASE64__', base64(loadTextContent('../bootstrap/postgres-vm.py'))),
    '__INSTALLER_BASE64__', base64(loadTextContent('../bootstrap/sso-postgres.py'))),
  '__CONFIG_BASE64__', base64(string(vmConfig))
)
var cloudInit = ssoMode ? ssoCloudInit : legacyCloudInit
resource postgresVm 'Microsoft.Compute/virtualMachines@2024-07-01' = {
  name: names.postgres
  location: location
  tags: effectiveTags
  identity: { type: 'SystemAssigned' }
  properties: {
    hardwareProfile: { vmSize: postgresVmSize }
    securityProfile: {
      securityType: 'TrustedLaunch'
      uefiSettings: { secureBootEnabled: true, vTpmEnabled: true }
    }
    storageProfile: {
      diskControllerType: 'SCSI'
      imageReference: { publisher: 'Canonical', offer: 'ubuntu-24_04-lts', sku: 'server', version: 'latest' }
      osDisk: {
        name: '${prefix}-postgres-os'
        createOption: 'FromImage'
        deleteOption: 'Detach'
        managedDisk: { storageAccountType: 'Premium_LRS' }
      }
      dataDisks: [{
        lun: 0
        name: postgresData.name
        createOption: 'Attach'
        deleteOption: 'Detach'
        caching: 'None'
        managedDisk: { id: postgresData.id }
      }]
    }
    osProfile: {
      computerName: '${prefix}-postgres'
      adminUsername: 'cmpvmadmin'
      customData: base64(cloudInit)
      linuxConfiguration: {
        disablePasswordAuthentication: true
        provisionVMAgent: true
        ssh: { publicKeys: [{ path: '/home/cmpvmadmin/.ssh/authorized_keys', keyData: sshPublicKey }] }
      }
    }
    networkProfile: { networkInterfaces: [{ id: postgresNic.id, properties: { deleteOption: 'Detach' } }] }
  }
  dependsOn: [dnsLink, postgresRecord]
}
// Azure does not inherit VM tags onto an implicitly created OS disk.
resource postgresOsDisk 'Microsoft.Compute/disks@2024-03-02' existing = { name: '${prefix}-postgres-os' }
resource postgresOsDiskTags 'Microsoft.Resources/tags@2021-04-01' = {
  scope: postgresOsDisk
  name: 'default'
  properties: { tags: effectiveTags }
  dependsOn: [postgresVm]
}
resource logs 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: '${prefix}-logs'
  location: location
  tags: effectiveTags
  properties: { sku: { name: 'PerGB2018' }, retentionInDays: 30 }
}
resource environment 'Microsoft.App/managedEnvironments@2025-07-01' = {
  name: names.environment
  location: location
  tags: effectiveTags
  properties: {
    vnetConfiguration: {
      infrastructureSubnetId: '${vnet.id}/subnets/container-apps'
      internal: false
    }
    workloadProfiles: [{ name: 'Consumption', workloadProfileType: 'Consumption' }]
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logs.properties.customerId
        sharedKey: logs.listKeys().primarySharedKey
      }
    }
  }
}
output foundation object = {
  prefix: prefix
  deploymentPrincipalId: deploymentPrincipalId
  location: location
  environmentName: environment.name
  environmentId: environment.id
  defaultDomain: environment.properties.defaultDomain
  registryName: registry.name
  registryId: registry.id
  registryServer: registry.properties.loginServer
  vaultName: vault.name
  vaultId: vault.id
  vaultUri: vault.properties.vaultUri
  databaseHosting: 'vm'
  postgresHost: 'postgres.${postgresDns.name}'
  postgresVmName: postgresVm.name
  postgresVmId: postgresVm.id
  postgresDataDiskId: postgresData.id
  postgresPrincipalId: postgresVm.identity.principalId
  postgresAdminUsername: postgresAdminUsername
  frontendIdentityId: identities[0].id
  backendIdentityId: identities[1].id
  backendPrincipalId: identities[1].properties.principalId
  backendClientId: identities[1].properties.clientId
  keycloakIdentityId: identities[2].id
  bootstrapIdentityId: identities[3].id
}
