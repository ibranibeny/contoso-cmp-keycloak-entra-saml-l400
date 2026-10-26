#requires -Version 7.0
<#
.SYNOPSIS
Commission only the private CMP user-administration service; never provision a human user.
.DESCRIPTION
Preview is read-only (and supports -Offline). Plan is real ARM what-if. Apply adds private NSG child rules,
exact-host private DNS, one scoped secret and an owned loopback service client.
Verify makes no guest configuration changes, but creates one ARM managed RunCommand artifact.
Old Caddy with admin off cannot reload: -AllowCaddyRestart explicitly permits a Caddy-only
restart after validation/backup; Keycloak is never restarted. No image build is invoked.
#>
[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
param(
    [ValidateSet('Preview','Plan','Apply','Verify')][string]$Phase='Preview',
    [switch]$Offline,
    [switch]$AllowCaddyRestart,
    [switch]$IncludeSubnetNsg,
    [ValidateSet('cmpsso-vnet-keycloak-nsg-indonesiacentral')]
    [string]$SubnetNsgName='cmpsso-vnet-keycloak-nsg-indonesiacentral'
)
$UserAdminInvocation=@{}+$PSBoundParameters
$UserAdminRequestedPhase=$Phase
$UserAdminRequestedOffline=$Offline
. (Join-Path $PSScriptRoot 'deploy-sso-admin.ps1')
$Phase=$UserAdminRequestedPhase
$Offline=$UserAdminRequestedOffline

function Get-UserAdminPayload($State,[ValidateSet('preflight','apply','verify')][string]$Operation,[string]$Root,[bool]$AllowRestart) {
    $source=[IO.File]::ReadAllText((Join-Path $Root 'bootstrap\sso-keycloak.py')).Replace("`r`n","`n")
    return @{operation=$Operation;ownershipId=$State.ownershipId;operationId=$State.operationId;baseAdminOwner=$State.baseAdminOwner
        foundationHash=$State.foundationHash;bootstrapHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData(
            [Text.Encoding]::UTF8.GetBytes($source))).ToLowerInvariant()
        tenantId=$State.tenantId;vaultUri='https://cmpsso-contoso-kv.vault.azure.net/';privateEndpoint=(Get-UserAdminEndpoint)
        allowCaddyRestart=$AllowRestart}
}
function ConvertFrom-UserAdminProof([string]$Raw,[string]$Operation,$Deployment) {
    if (-not $Raw -or [Text.Encoding]::UTF8.GetByteCount($Raw) -gt 4096) { throw 'Missing/oversized user-admin guest proof.' }
    try { $proof=$Raw|ConvertFrom-Json -AsHashtable -Depth 6 } catch { throw 'Invalid user-admin guest proof; suppressed.' }
    if ($proof -isnot [Collections.IDictionary] -or $proof['status'] -cne 'ready' -or $proof['operation'] -cne $Operation -or
        $proof['issuer'] -cne $Deployment.keycloak.issuer -or $proof['privateEndpoint'] -cne (Get-UserAdminEndpoint) -or
        $proof['loginVerified'] -isnot [bool] -or $proof.loginVerified) { throw 'User-admin guest did not prove the fixed private contract.' }
    $safe=@{status='ready';operation=$Operation;issuer=$proof.issuer;privateEndpoint=$proof.privateEndpoint;loginVerified=$false}
    if ($Operation -cne 'preflight') {
        if ($proof['clientUuid'] -cnotmatch '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$' -or
            $proof['secretVersion'] -cnotmatch ('^'+[regex]::Escape("$($Deployment.foundation.vaultUri)secrets/$(Get-UserAdminSecretName)/")+'[a-f0-9]{32}$') -or
            $proof['caddyHash'] -cnotmatch '^[a-f0-9]{64}$' -or $proof['smtpConfigured'] -isnot [bool] -or
            $proof['queryVerified'] -isnot [bool] -or -not $proof.queryVerified) { throw 'User-admin service/secret/TLS proof is incomplete.' }
        foreach($name in @('clientUuid','secretVersion','caddyHash','smtpConfigured','queryVerified')) { $safe[$name]=$proof[$name] }
    }
    return $safe
}
function Invoke-UserAdminGuest($Deployment,$State,[string]$Operation,[hashtable]$Payload,[string]$Root) {
    if ($State.commandName -cnotmatch ("^sso-user-admin-"+$Operation+"-[a-f0-9]{32}$")) { throw 'A durable owned guest intention is required.' }
    $source=@'
set -eu
umask 077
test "$(id -u)" = 0
python3 -B - <<'CMP_USER_ADMIN_RUN'
import base64
exec(compile(base64.b64decode('__CODE__'), '/opt/cmp/sso-user-admin.py', 'exec'), {'__name__':'__main__'})
CMP_USER_ADMIN_RUN
'@
    $encoded=[Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $Root 'bootstrap\sso-user-admin.py')))
    $uri="https://management.azure.com$($Deployment.keycloak.vmId)/runCommands/$($State.commandName)?api-version=2024-07-01"
    $properties=@{source=@{script=$source.Replace('__CODE__',$encoded).Replace("`r`n","`n")}
        timeoutInSeconds=900;asyncExecution=$true;treatFailureAsDeploymentFailure=$true
        protectedParameters=@(@{name='CMP_USER_ADMIN_PAYLOAD';value=($Payload|ConvertTo-Json -Depth 6 -Compress)})}
    try {
        $null=Invoke-CmpRest -Uri $uri -Method PUT -Body @{location='indonesiacentral';tags=@{costcontrol='ignore'};properties=$properties}
    } catch { throw "User-admin guest submission uncertain: $($State.commandName). Inspect before recovery; no retry." }
    finally { $null=$properties.Remove('protectedParameters');$Payload.Clear() }
    $deadline=[DateTime]::UtcNow.AddMinutes(17)
    do {
        $response=Invoke-CmpRest -Uri "$uri&`$expand=instanceView"
        $p=$response.properties
        if ($p.PSObject.Properties.Name -contains 'instanceView' -and $p.instanceView) {
            $view=$p.instanceView
            if ($view.executionState -in @('Failed','Canceled','TimedOut')) {
                $stage='guest-failed'
                if ($view.PSObject.Properties.Name -contains 'output' -and $view.output -is [string] -and $view.output.Length -le 4096) {
                    try {
                        $failure=$view.output|ConvertFrom-Json -AsHashtable -Depth 4
                        if ($failure['status'] -ceq 'failed' -and $failure['stage'] -cmatch '^[a-z0-9-]{1,100}$') { $stage=$failure.stage }
                    } catch {}
                }
                throw "User-admin $stage; inspect $($State.commandName) and private journal. No unknown client adoption/secret rotation."
            }
            if ($view.executionState -ceq 'Succeeded') {
                if ($view.PSObject.Properties.Name -notcontains 'exitCode' -or $view.exitCode -ne 0) { throw 'User-admin guest exit was not proven.' }
                return ConvertFrom-UserAdminProof $view.output $Operation $Deployment
            }
        }
        if ($p.provisioningState -in @('Failed','Canceled')) { throw 'User-admin managed command provisioning failed; no retry.' }
        Start-Sleep -Seconds 5
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "User-admin guest deadline exceeded: $($State.commandName). No automatic retry or secret regeneration."
}
function Invoke-UserAdminMain {
    [CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
    param()
    $root=Split-Path $PSScriptRoot
    if ($Offline -and $Phase -cne 'Preview') { throw '-Offline is only supported for Preview.' }
    $deployment=Get-Content -LiteralPath (Get-CmpProjectPath $root '.azure\sso-deployment-state.json') -Raw|ConvertFrom-Json -AsHashtable
    Assert-AdminFoundation $deployment $root
    $base=Read-AdminState (Get-AdminPaths $root).state $deployment
    $path=Get-UserAdminStatePath $root
    Assert-UserAdminPath $path
    if (Test-Path -LiteralPath "$path.pending") { throw 'User-admin local checkpoint is uncertain; inspect before recovery.' }
    $state=if (Test-Path -LiteralPath $path) { Read-UserAdminState $path $deployment $base } else { $null }
    $script:CmpSubscriptionId=$deployment.subscriptionId;$script:CmpTenantId=$deployment.tenantId
    $templates=@{}
    foreach($name in @('sso-user-admin-network','sso-user-admin-access','sso-seed-secrets')) {
        $templates[$name]=Get-CmpTemplate (Join-Path $root "infra\$name.bicep")
    }
    if ($Offline) { return [pscustomobject]@{status='OfflinePreviewOnly';writes='None';templates=3;userAdministration='Disabled until explicitly commissioned and deployed'} }
    Initialize-CmpContext $deployment.subscriptionId $deployment.tenantId 'admin@contoso.com'
    $account=Invoke-CmpAz @('account','show') -Json
    if ($account.environmentName -cne 'AzureCloud' -or $account.state -cne 'Enabled') { throw 'Only the approved Enabled AzureCloud context is accepted.' }
    Assert-SsoToken (Get-CmpToken)
    Assert-CmpPrivateInventory $deployment
    Assert-SsoKeycloakInventory $deployment
    $network=@{IncludeSubnetNsg=[bool]$IncludeSubnetNsg;SubnetNsgName=$SubnetNsgName}
    $inventory=Get-UserAdminNetworkInventory $deployment $state @network
    if ($Phase -ceq 'Preview') {
        return [pscustomobject]@{status='ReadOnlyPreview';writes='None';privateEndpoint=(Get-UserAdminEndpoint)
            stage=$(if ($state) {$state.stage} else {'NotInitialized'});smtpPrecondition='Verified only during private commissioning; never assume Gmail is verified'}
    }
    $candidate=if ($state) { $state } else { New-UserAdminState $deployment $base $(if ($IncludeSubnetNsg) { $SubnetNsgName } else { '' }) }
    $networkParameters=@{ownershipId=$candidate.ownershipId;includeSubnetNsg=[bool]$IncludeSubnetNsg;subnetNsgName=$SubnetNsgName}
    $access=@{keycloakPrincipalId=$deployment.keycloak.principalId;backendPrincipalId=$deployment.foundation.backendPrincipalId}
    if ($Phase -ceq 'Plan') {
        if (-not $inventory.metadata) {
            Invoke-CmpDeployment $deployment.resourceGroup 'cmpsso-user-admin-seed' $templates['sso-seed-secrets'] @{
                vaultName=$deployment.foundation.vaultName;missingNames=@((Get-UserAdminSecretName))} -Preview
        }
        Invoke-CmpDeployment $deployment.resourceGroup 'cmpsso-user-admin-access' $templates['sso-user-admin-access'] $access -Preview
        Invoke-CmpDeployment $deployment.resourceGroup 'cmpsso-user-admin-network' $templates['sso-user-admin-network'] $networkParameters -Preview
        return
    }
    if ($candidate.stage.EndsWith('-intent')) { throw "Uncertain user-admin stage $($candidate.stage): inspect $($candidate.commandName) before explicit recovery." }
    if ($Phase -ceq 'Verify') { Assert-UserAdminState $candidate $deployment $base -RequireComplete }
    if (-not $PSCmdlet.ShouldProcess("$($deployment.subscriptionId)/$($deployment.resourceGroup)/cmpsso-keycloak-vm",
        "$Phase private user administration only; Caddy-only restart allowed=$([bool]$AllowCaddyRestart); subnet NSG opt-in=$([bool]$IncludeSubnetNsg); no human-user reset/Keycloak restart/image build")) { return }
    $state=$candidate
    function CheckpointUser([string]$Stage) { $state.stage=$Stage;Save-UserAdminState $state $path $deployment $base }
    if ($Phase -ceq 'Verify') {
        $state.commandName='sso-user-admin-verify-'+[guid]::NewGuid().ToString('N')
        CheckpointUser 'verify-intent'
        $proof=Invoke-UserAdminGuest $deployment $state 'verify' (Get-UserAdminPayload $state 'verify' $root ([bool]$AllowCaddyRestart)) $root
        foreach($key in @('clientUuid','secretVersion','caddyHash','smtpConfigured')) {
            if ($state[$key] -cne $proof[$key]) { throw 'Verified public proof differs from owned commissioning state.' }
        }
        CheckpointUser 'verified'
        return $proof
    }
    if ($state.stage -cin @('commissioned','verified')) {
        return [pscustomobject]@{status='AlreadyCommissioned';privateEndpoint=$state.privateEndpoint;smtpConfigured=$state.smtpConfigured;loginVerified=$false}
    }
    if ($state.stage -ceq 'new') {
        $state.commandName='sso-user-admin-preflight-'+[guid]::NewGuid().ToString('N')
        CheckpointUser 'preflight-intent'
        $null=Invoke-UserAdminGuest $deployment $state 'preflight' (Get-UserAdminPayload $state 'preflight' $root ([bool]$AllowCaddyRestart)) $root
        CheckpointUser 'preflight-ready'
    }
    if ($state.stage -ceq 'preflight-ready') {
        if (Get-UserAdminMetadata $deployment) { throw 'User-admin secret appeared before seed; never overwrite an initialized secret.' }
        CheckpointUser 'seed-intent'
        $null=Invoke-CmpDeployment $deployment.resourceGroup 'cmpsso-user-admin-seed' $templates['sso-seed-secrets'] @{
            vaultName=$deployment.foundation.vaultName;missingNames=@((Get-UserAdminSecretName))}
        CheckpointUser 'seeded'
    }
    if ($state.stage -ceq 'seeded') {
        CheckpointUser 'grant-intent'
        $null=Invoke-CmpDeployment $deployment.resourceGroup 'cmpsso-user-admin-access' $templates['sso-user-admin-access'] $access
        CheckpointUser 'granted'
    }
    if ($state.stage -ceq 'granted') {
        CheckpointUser 'network-intent'
        $null=Invoke-CmpDeployment $deployment.resourceGroup 'cmpsso-user-admin-network' $templates['sso-user-admin-network'] $networkParameters
        CheckpointUser 'network-ready'
    }
    if ($state.stage -ceq 'network-ready') {
        $state.commandName='sso-user-admin-apply-'+[guid]::NewGuid().ToString('N')
        CheckpointUser 'guest-intent'
        $proof=Invoke-UserAdminGuest $deployment $state 'apply' (Get-UserAdminPayload $state 'apply' $root ([bool]$AllowCaddyRestart)) $root
        foreach($key in @('clientUuid','secretVersion','caddyHash','smtpConfigured')) { $state[$key]=$proof[$key] }
        CheckpointUser 'commissioned'
        return $proof
    }
}
if ($MyInvocation.InvocationName -ne '.') {
    $common=@{}
    foreach($name in @('WhatIf','Confirm')) { if ($UserAdminInvocation.ContainsKey($name)) { $common[$name]=$UserAdminInvocation[$name] } }
    Invoke-UserAdminMain @common
}
