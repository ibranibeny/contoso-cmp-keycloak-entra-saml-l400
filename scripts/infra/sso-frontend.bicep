@allowed(['cmpsso'])
param prefix string = 'cmpsso'
@allowed(['indonesiacentral'])
param location string = 'indonesiacentral'
param environmentName string
param defaultDomain string
param registryServer string
param applicationImage string
param vaultUri string
param keycloakOrigin string
@allowed(['aaaabbbb-0000-cccc-1111-dddd2222eeee'])
param tenantId string
param projectsJson string = '[]'
param adminOrigin string = ''
@allowed(['disabled', 'enabled'])
param cloudRegistryMode string = 'disabled'
param tags object = { workload: 'cmp-sso', environment: 'poc' }
var effectiveTags = union(tags, { costcontrol: 'ignore' })
resource environment 'Microsoft.App/managedEnvironments@2025-07-01' existing = { name: environmentName }
resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' existing = { name: '${prefix}-frontend-id' }
var secretNames = ['cmp-database-url', 'session-secret', 'keycloak-client-secret', 'postgres-ca']
var origin = 'https://${prefix}-frontend.${defaultDomain}'
resource frontend 'Microsoft.App/containerApps@2025-07-01' = {
  name: '${prefix}-frontend'
  location: location
  tags: effectiveTags
  identity: { type: 'UserAssigned', userAssignedIdentities: { '${identity.id}': {} } }
  properties: {
    environmentId: environment.id
    workloadProfileName: 'Consumption'
    configuration: {
      activeRevisionsMode: 'Single'
      registries: [{ server: registryServer, identity: identity.id }]
      secrets: [for name in secretNames: {
        name: name
        keyVaultUrl: '${vaultUri}secrets/${name}'
        identity: identity.id
      }]
      ingress: { external: true, targetPort: 8080, transport: 'auto', allowInsecure: false }
    }
    template: {
      volumes: [{ name: 'postgres-tls', storageType: 'Secret', secrets: [{ secretRef: 'postgres-ca', path: 'ca.crt' }] }]
      containers: [{
        name: 'frontend'
        image: applicationImage
        resources: { cpu: json('0.5'), memory: '1Gi' }
        volumeMounts: [{ volumeName: 'postgres-tls', mountPath: '/mnt/postgres-tls' }]
        env: [
          { name: 'NODE_ENV', value: 'production' }
          { name: 'NODE_USE_SYSTEM_CA', value: '1' }
          { name: 'APP_MODE', value: 'live' }
          { name: 'APP_ROLE', value: 'frontend' }
          { name: 'PORT', value: '8080' }
          { name: 'IDENTITY_FLOW', value: 'keycloak-federation' }
          { name: 'KEYCLOAK_REALM', value: 'cmp-pdf' }
          { name: 'KEYCLOAK_CLIENT_ID', value: 'cmp-frontend' }
          { name: 'KEYCLOAK_URL', value: keycloakOrigin }
          { name: 'ENTRA_TENANT_ID', value: tenantId }
          { name: 'PUBLIC_ORIGIN', value: origin }
          { name: 'CMP_PROJECTS_JSON', value: projectsJson }
          { name: 'ADMIN_ORIGIN', value: adminOrigin }
          { name: 'CMP_CLOUD_REGISTRY', value: cloudRegistryMode }
          { name: 'DATABASE_URL', secretRef: 'cmp-database-url' }
          { name: 'SESSION_SECRET', secretRef: 'session-secret' }
          { name: 'KEYCLOAK_CLIENT_SECRET', secretRef: 'keycloak-client-secret' }
        ]
        probes: [for kind in ['Startup', 'Readiness', 'Liveness']: {
          type: kind
          httpGet: { path: '/health', port: 8080, scheme: 'HTTP' }
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: kind == 'Startup' ? 60 : 3
        }]
      }]
      scale: { minReplicas: 1, maxReplicas: 1 }
    }
  }
}
output frontendOrigin string = origin
