targetScope = 'resourceGroup'

@minLength(36)
@maxLength(36)
param guestObjectId string

resource reader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, guestObjectId, 'cmp-poc-test-reader')
  properties: {
    principalId: guestObjectId
    principalType: 'User'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'acdd72a7-3385-48ef-bd42-f606fba81ae7')
  }
}

output roleAssignmentId string = reader.id
