#requires -Version 7.0
<#
.SYNOPSIS
Isolated, additive Indonesia Central SSO PoC. No tenant mutations, existing PoC changes or local secret material.
.DESCRIPTION
Validate/Plan are read-only. First Plan uses subscription-scoped ARM what-if before the new RG exists.
Apply incrementally commissions NEW resources, private VM-generated secrets, Keycloak VM and frontend.
Resume never redeploys/replaces existing VMs. Changed bootstrap fingerprints need explicit maintenance.
Verify checks HTTPS discovery, SAML metadata, blocked management paths and frontend health.
No identities, Entra consent, federation links, MFA claims or end-to-end login evidence are fabricated.
Single nodes are not HA; back up retained PostgreSQL volume and Caddy state before maintenance.
#>
[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
param(
    [ValidateSet('Validate','Plan','Apply','Verify')][string]$Phase='Validate',
    [ValidateSet('aaaa0a0a-bb1b-cc2c-dd3d-eeeeee4e4e4e')][string]$SubscriptionId='aaaa0a0a-bb1b-cc2c-dd3d-eeeeee4e4e4e',
    [ValidateSet('aaaabbbb-0000-cccc-1111-dddd2222eeee')][string]$TenantId='aaaabbbb-0000-cccc-1111-dddd2222eeee',
    [ValidateSet('rg-cmp-sso-indonesia-poc')][string]$ResourceGroupName='rg-cmp-sso-indonesia-poc',
    [ValidateSet('cmpsso')][string]$Prefix='cmpsso',
    [ValidateSet('indonesiacentral')][string]$Location='indonesiacentral',
    [ValidateSet('admin@contoso.com')][string]$ExpectedAccount='admin@contoso.com',
    [string]$SshPublicKey,
    [string]$PostgresVmSize='Standard_D2s_v5',
    [string]$KeycloakVmSize='Standard_D2s_v5',
    [string]$ProjectsJson='[]',
    [switch]$RebuildApplication,
    [switch]$Offline
)
. (Join-Path $PSScriptRoot 'sso-common.ps1')
$root=Split-Path $PSScriptRoot
$statePath=Get-CmpProjectPath $root '.azure\sso-deployment-state.json'
if ($Phase -in @('Plan','Apply') -and
    (Test-Path -LiteralPath (Join-Path $root '.azure\sso-admin-state.json'))) {
    throw 'Use deploy-sso-admin.ps1 for Plan/Apply after admin commissioning; the original rollout would remove the admin integration. Preserve the admin state file.'
}
$scope=@{subscriptionId=$SubscriptionId;tenantId=$TenantId;resourceGroup=$ResourceGroupName;prefix=$Prefix}
Assert-SsoScope $scope
if ($Offline -and $Phase -ne 'Validate') { throw 'Offline is supported only for Validate.' }
try { $projects=ConvertFrom-Json -InputObject $ProjectsJson -NoEnumerate } catch { throw 'ProjectsJson must be a JSON array.' }
if ($projects -isnot [array]) { throw 'ProjectsJson must be an array; default [] explicitly means no configured projects.' }
foreach ($tool in @('az','node')) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) { throw "Missing dependency $tool. Install explicitly; no tools/extensions are auto-installed." }
}
$script:CmpSubscriptionId=$SubscriptionId
$script:CmpTenantId=$TenantId
$templates=@{}
foreach ($name in @('foundation','private-vault','sso-keycloak','sso-frontend','sso-secret-access','sso-seed-secrets','sso-foundation-plan')) {
    $templates[$name]=Get-CmpTemplate (Join-Path $root "infra\$name.bicep")
}
if ($Offline) {
    [pscustomobject]@{status='OfflineValidationOnly';writes='None';templates="$($templates.Count) Bicep templates compiled";cloudReadiness='NOT VERIFIED'}
    return
}
Initialize-CmpContext $SubscriptionId $TenantId $ExpectedAccount
$account=Invoke-CmpAz @('account','show') -Json
if ($account.environmentName -cne 'AzureCloud' -or $account.state -cne 'Enabled') { throw 'Only an Enabled AzureCloud subscription is approved.' }
Assert-SsoToken (Get-CmpToken)
$principalId=Get-CmpDeploymentPrincipal
$hash=Get-SsoBootstrapHash $root
$state=$null
if (Test-Path -LiteralPath $statePath) {
    $state=Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json -AsHashtable
    Assert-SsoSavedState $state $root
    foreach ($name in @('PostgresVmSize','KeycloakVmSize','SshPublicKey')) {
        if ($PSBoundParameters.ContainsKey($name) -and (Get-Variable $name -ValueOnly) -cne $state[$name]) {
            throw 'Existing VM size or SSH key differs; no automatic VM mutation.'
        }
        Set-Variable -Name $name -Value $state[$name]
    }
    if ($state.ContainsKey('foundation')) { Assert-CmpPrivateInventory $state }
    if ($state.ContainsKey('keycloak')) { Assert-SsoKeycloakInventory $state }
}
$groupUri="https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/${ResourceGroupName}?api-version=2024-03-01"
$group=Invoke-CmpRest -Uri $groupUri -AllowNotFound
if ($group -and (-not $state -or $group.location -ne $Location -or $group.tags.'cmp-sso-scope' -cne 'isolated-v1')) {
    throw 'Existing SSO RG lacks matching state/location/ownership marker. No adoption or mutation is attempted; recover the SSO state manually.'
}
if ($state -and -not $group) { throw 'Saved SSO RG is missing; explicit recovery required, not recreation.' }
if ($Phase -eq 'Verify') {
    if (-not $state -or -not $state.ContainsKey('keycloak') -or -not $state.ContainsKey('applicationImage')) { throw 'Verify needs completed SSO state.' }
    Test-SsoPublicEndpoints $state
    [pscustomobject]@{status='HttpsInfrastructureVerified';frontendOrigin=$state.frontendOrigin;issuer=$state.keycloak.issuer;
        metadataUrl=$state.keycloak.metadataUrl;identityLogin='NOT VERIFIED: real user linking/federation and interactive sign-in are separate'}
    return
}
Test-SsoProviders
$usage=Invoke-CmpAz @('vm','list-usage','--location',$Location) -Json
$additional=@{}
$regional=0
foreach ($vm in @(@{name='postgres';size=$PostgresVmSize},@{name='keycloak';size=$KeycloakVmSize})) {
    $skus=Invoke-CmpAz @('vm','list-skus','--location',$Location,'--resource-type','virtualMachines','--size',$vm.size,'--all') -Json
    $allocated=$state -and (($vm.name -eq 'postgres' -and $state.ContainsKey('foundation')) -or
        ($vm.name -eq 'keycloak' -and $state.ContainsKey('keycloak')))
    Assert-CmpVmCapability $skus $usage $vm.size $Location -ExistingAllocationVerified:$allocated
    if (-not $allocated) {
        $sku=@($skus | Where-Object { $_.name -ceq $vm.size })[0]
        $cores=[int](@($sku.capabilities | Where-Object name -eq 'vCPUs')[0].value)
        if (-not $additional.ContainsKey($sku.family)) { $additional[$sku.family]=0 }
        $additional[$sku.family]+=$cores
        $regional+=$cores
    }
}
$additional['cores']=$regional
foreach ($family in $additional.Keys) {
    $q=@($usage | Where-Object { $_.name.value -ceq $family })[0]
    if ([double]$q.limit-[double]$q.currentValue -lt $additional[$family]) { throw "Combined two-VM regional/family quota is insufficient: $family." }
}
if ($Phase -eq 'Validate') {
    [pscustomobject]@{status='ReadOnlyValidation';writes='None';groupExists=[bool]$group;capacity='SKU/quota checked; capacity NOT reserved';
        preconditions='Resource deployment + scoped role-assignment rights; outbound Ubuntu/Docker/Quay/ACME access; registered Azure providers'}
    return
}
if (-not $SshPublicKey) {
    $oldVmId="/subscriptions/$SubscriptionId/resourceGroups/rg-cmp-indonesia-poc/providers/Microsoft.Compute/virtualMachines/cmppoc-postgres-vm"
    $old=Invoke-CmpAz @('vm','show','--ids',$oldVmId) -Json
    $keys=@($old.osProfile.linuxConfiguration.ssh.publicKeys)
    if ($keys.Count -ne 1) { throw 'Supply -SshPublicKey with an existing public key value; old VM has no unambiguous public key metadata.' }
    $SshPublicKey=$keys[0].keyData
}
Assert-CmpSshPublicKey $SshPublicKey
$foundationParameters=@{prefix=$Prefix;location=$Location;deploymentPrincipalId=$principalId;sshPublicKey=$SshPublicKey;
    postgresVmSize=$PostgresVmSize;ssoMode=$true;tags=@{workload='cmp-sso';environment='poc'}}
if ($Phase -eq 'Plan') {
    if (-not $group) {
        $changes = @(Invoke-CmpDeployment '' 'cmpsso-foundation-plan' $templates['sso-foundation-plan'] `
            $foundationParameters -Preview -SubscriptionScope)
        [pscustomobject]@{status='ArmFoundationCreationPlan';writes='None';resourceGroup=$ResourceGroupName;region=$Location;
            changes=$changes;next='Foundation preview only; private-vault, Keycloak and frontend are staged after foundation outputs exist.'}
    } else {
        if (-not $state.ContainsKey('foundation')) { throw 'Partial foundation: inspect deployment operations before proceeding.' }
        # Existing VMs are inventory-only: never plan their redeployment.
        if ($state.ContainsKey('applicationImage') -and $state.ContainsKey('keycloak')) {
            $f=$state.foundation
            Invoke-CmpDeployment $ResourceGroupName 'cmpsso-frontend' $templates['sso-frontend'] @{
                prefix=$Prefix;environmentName=$f.environmentName;defaultDomain=$f.defaultDomain;registryServer=$f.registryServer;
                applicationImage=$state.applicationImage;vaultUri=$f.vaultUri;keycloakOrigin=$state.keycloak.origin;tenantId=$TenantId;projectsJson=$ProjectsJson
            } -Preview
        } else { [pscustomobject]@{status='PartialSsoPlan';writes='None';next='Apply resumes missing bootstrap/build/frontend stages only'} }
    }
    return
}
if (-not $PSCmdlet.ShouldProcess("$SubscriptionId/$ResourceGroupName",'Incrementally commission isolated SSO resources and build images on the new private VM')) { return }
function Save-SsoState {
    $directory=Split-Path $statePath
    if (-not (Test-Path -LiteralPath $directory)) { $null=New-Item -ItemType Directory -Path $directory }
    $pending="$statePath.pending"
    $state | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $pending -Encoding utf8
    Move-Item -LiteralPath $pending -Destination $statePath -Force
}
if (-not $group) {
    $null=Invoke-CmpRest -Uri $groupUri -Method PUT -Body @{location=$Location;tags=@{costcontrol='ignore';'cmp-sso-scope'='isolated-v1'}}
    $state=@{}+$scope
    $state.bootstrapHash=$hash
    $state.PostgresVmSize=$PostgresVmSize
    $state.KeycloakVmSize=$KeycloakVmSize
    $state.PostgresDataDiskGiB=64
    $state.SshPublicKey=$SshPublicKey
    $state.databaseHosting='vm'
    $state.vmBootstrapHash=Get-CmpVmBootstrapHash $root
    Save-SsoState
}
if (-not $state.ContainsKey('foundation')) {
    $orphan=Invoke-CmpRest -Uri "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Compute/virtualMachines/cmpsso-postgres-vm?api-version=2024-07-01" -AllowNotFound
    if ($orphan) { throw 'Existing foundation VM without completed checkpoint. Recover cmpsso-foundation outputs into SSO state manually; never rerun blindly.' }
    $outputs=Invoke-CmpDeployment $ResourceGroupName 'cmpsso-foundation' $templates.foundation $foundationParameters
    $state.foundation=$outputs.foundation.value | ConvertTo-Json -Depth 30 | ConvertFrom-Json -AsHashtable
    $state.frontendOrigin="https://cmpsso-frontend.$($state.foundation.defaultDomain)"
    Save-SsoState
}
$f=$state.foundation
Assert-CmpPrivateInventory $state
$null=Invoke-CmpDeployment $ResourceGroupName 'cmpsso-private-vault' $templates['private-vault'] @{prefix=$Prefix;vaultName=$f.vaultName}
$missing=@(Get-SsoMissingSecrets $f)
if ($missing.Count) {
    $null=Invoke-CmpDeployment $ResourceGroupName 'cmpsso-seed-secrets' $templates['sso-seed-secrets'] @{vaultName=$f.vaultName;missingNames=$missing}
}
function Grant-SsoSecrets([string]$Name,[string]$Principal,[string]$Access,[string[]]$Names) {
    $null=Invoke-CmpDeployment $ResourceGroupName $Name $templates['sso-secret-access'] @{
        vaultName=$f.vaultName;principalId=$Principal;access=$Access;secretNames=$Names}
}
Grant-SsoSecrets 'cmpsso-db-secrets' $f.postgresPrincipalId 'write' @('cmp-database-url','postgres-ca','session-secret','keycloak-db-password','keycloak-admin-password')
$null=Invoke-SsoGuest $f.postgresVmId 'postgres'
if (-not $state.ContainsKey('keycloak')) {
    $orphan=Invoke-CmpRest -Uri "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Compute/virtualMachines/cmpsso-keycloak-vm?api-version=2024-07-01" -AllowNotFound
    if ($orphan) { throw 'Existing Keycloak VM without completed checkpoint. Recover cmpsso-keycloak outputs into SSO state manually; never redeploy blindly.' }
    $outputs=Invoke-CmpDeployment $ResourceGroupName 'cmpsso-keycloak' $templates['sso-keycloak'] @{
        vaultUri=$f.vaultUri;postgresHost=$f.postgresHost;frontendOrigin=$state.frontendOrigin;tenantId=$TenantId;
        sshPublicKey=$SshPublicKey;vmSize=$KeycloakVmSize}
    $state.keycloak=$outputs.keycloak.value | ConvertTo-Json -Depth 20 | ConvertFrom-Json -AsHashtable
    $state.keycloakOrigin=$state.keycloak.origin
    $state.metadataUrl=$state.keycloak.metadataUrl
    Save-SsoState
}
Assert-SsoKeycloakInventory $state
Grant-SsoSecrets 'cmpsso-keycloak-read' $state.keycloak.principalId 'read' @('postgres-ca','keycloak-db-password','keycloak-admin-password')
Grant-SsoSecrets 'cmpsso-keycloak-write' $state.keycloak.principalId 'write' @('keycloak-client-secret')
$null=Invoke-SsoGuest $state.keycloak.vmId 'keycloak'
$frontendIdentity=Invoke-CmpAz @('identity','show','--ids',$f.frontendIdentityId) -Json
Grant-SsoSecrets 'cmpsso-frontend-read' $frontendIdentity.principalId 'read' @('postgres-ca','cmp-database-url','session-secret','keycloak-client-secret')
if ($RebuildApplication -or -not $state.ContainsKey('applicationImage')) {
    $built=Build-CmpInRegionImages -State $state -Root $root -Confirm:$false
    $state.applicationImage=$built.applicationImage
    $state.sourceHash=$built.sourceHash
    Save-SsoState
}
$null=Invoke-CmpDeployment $ResourceGroupName 'cmpsso-frontend' $templates['sso-frontend'] @{
    prefix=$Prefix;environmentName=$f.environmentName;defaultDomain=$f.defaultDomain;registryServer=$f.registryServer;
    applicationImage=$state.applicationImage;vaultUri=$f.vaultUri;keycloakOrigin=$state.keycloak.origin;tenantId=$TenantId;projectsJson=$ProjectsJson}
Test-SsoPublicEndpoints $state
$state.status='HttpsInfrastructureVerified'
Save-SsoState
[pscustomobject]@{status=$state.status;statePath=$statePath;frontendOrigin=$state.frontendOrigin;keycloakOrigin=$state.keycloak.origin;
    metadataUrl=$state.keycloak.metadataUrl;identityLogin='NOT VERIFIED: link real identities and configure Entra federation separately'}
