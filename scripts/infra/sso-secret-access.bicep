param vaultName string
param principalId string
@allowed(['read', 'write'])
param access string = 'read'
param secretNames array
resource vault 'Microsoft.KeyVault/vaults@2023-07-01' existing = { name: vaultName }
resource secret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' existing = [for name in secretNames: {
  parent: vault
  name: name
}]
resource role 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for (name, i) in secretNames: {
  scope: secret[i]
  name: guid(vault.id, name, principalId, access, 'cmp-sso')
  properties: {
    principalId: principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions',
      access == 'write' ? 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7' : '4633458b-17de-408a-b874-0445c86b69e6')
  }
}]
