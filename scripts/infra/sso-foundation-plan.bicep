targetScope = 'subscription'

@allowed(['cmpsso'])
param prefix string = 'cmpsso'
@allowed(['indonesiacentral'])
param location string = 'indonesiacentral'
param deploymentPrincipalId string
param sshPublicKey string
param postgresVmSize string = 'Standard_D2s_v5'
@allowed([true])
param ssoMode bool = true
param tags object = { workload: 'cmp-sso', environment: 'poc' }

resource group 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: 'rg-cmp-sso-indonesia-poc'
  location: location
  tags: { costcontrol: 'ignore', 'cmp-sso-scope': 'isolated-v1' }
}

module foundation 'foundation.bicep' = {
  name: 'cmpsso-foundation'
  scope: group
  params: {
    prefix: prefix
    location: location
    deploymentPrincipalId: deploymentPrincipalId
    sshPublicKey: sshPublicKey
    postgresVmSize: postgresVmSize
    ssoMode: ssoMode
    tags: tags
  }
}
