#requires -Version 7.0
. (Join-Path $PSScriptRoot 'private-images.ps1')

function Assert-SsoScope($State) {
    if ($State.subscriptionId -cne 'aaaa0a0a-bb1b-cc2c-dd3d-eeeeee4e4e4e' -or
        $State.tenantId -cne 'aaaabbbb-0000-cccc-1111-dddd2222eeee' -or
        $State.resourceGroup -cne 'rg-cmp-sso-indonesia-poc' -or $State.prefix -cne 'cmpsso') {
        throw 'Only the approved NEW rg-cmp-sso-indonesia-poc/cmpsso subscription and tenant are allowed. Old resources cannot be targeted.'
    }
}
function Assert-SsoToken([string]$Token) {
    try {
        $part=$Token.Split('.')[1].Replace('-','+').Replace('_','/')
        $part=$part.PadRight($part.Length+((4-$part.Length%4)%4),'=')
        $claims=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($part)) | ConvertFrom-Json -AsHashtable
    } catch { throw 'ARM interactive-user token is not inspectable.' }
    $names=@('upn','preferred_username','unique_name' | Where-Object { $claims.ContainsKey($_) } | ForEach-Object { $claims[$_] })
    if ($claims['tid'] -cne 'aaaabbbb-0000-cccc-1111-dddd2222eeee' -or
        -not $names.Count -or @($names | Where-Object { $_ -ine 'admin@contoso.com' }).Count -or
        -not $claims.ContainsKey('oid') -or $claims.oid -notmatch '^[a-f0-9-]{36}$' -or
        ($claims.ContainsKey('idtyp') -and $claims.idtyp -eq 'app') -or
        $claims['aud'] -notin @('https://management.azure.com/','https://management.core.windows.net/','https://management.core.windows.net')) {
        throw 'ARM token tenant/user differs from approved admin@contoso.com interactive identity.'
    }
}
function Assert-SsoSavedState($State,[string]$Root) {
    Assert-SsoScope $State
    if ($State['bootstrapHash'] -cne (Get-SsoBootstrapHash $Root)) { throw 'SSO bootstrap code differs from the saved VM contract; explicit maintenance required.' }
    if ($State.ContainsKey('foundation')) {
        Assert-CmpImageState $State $Root
        $f=$State.foundation
        $scope="/subscriptions/$($State.subscriptionId)/resourceGroups/$($State.resourceGroup)/providers"
        if ($f.prefix -cne 'cmpsso' -or $f.environmentName -cne 'cmpsso-env' -or
            $f.environmentId -ine "$scope/Microsoft.App/managedEnvironments/cmpsso-env" -or
            $f.frontendIdentityId -ine "$scope/Microsoft.ManagedIdentity/userAssignedIdentities/cmpsso-frontend-id" -or
            $State.frontendOrigin -cne "https://cmpsso-frontend.$($f.defaultDomain)") {
            throw 'SSO environment/frontend identifiers differ from the isolated foundation contract.'
        }
        if ($State.ContainsKey('applicationImage') -and
            $State.applicationImage -cnotmatch "^$([regex]::Escape($f.registryServer))/cmp@sha256:[a-f0-9]{64}$") {
            throw 'Saved SSO application image must be a digest from the isolated ACR registry.'
        }
    }
    if ($State.ContainsKey('keycloak')) {
        $scope="/subscriptions/$($State.subscriptionId)/resourceGroups/$($State.resourceGroup)/providers"
        $k=$State.keycloak
        if ($k.vmId -ine "$scope/Microsoft.Compute/virtualMachines/cmpsso-keycloak-vm" -or
            $k.origin -cnotmatch '^https://cmpsso-[a-z0-9]{10}\.indonesiacentral\.cloudapp\.azure\.com$' -or
            $k.issuer -cne "$($k.origin)/realms/cmp-pdf" -or
            $k.metadataUrl -cne "$($k.issuer)/protocol/saml/descriptor") {
            throw 'Saved SSO Keycloak issuer/VM differs from the isolated contract.'
        }
    }
}
function Test-SsoProviders {
    $requirements=@{
        'Microsoft.App'=@('managedEnvironments','containerApps')
        'Microsoft.Compute'=@('virtualMachines','disks')
        'Microsoft.ContainerRegistry'=@('registries')
        'Microsoft.KeyVault'=@('vaults')
        'Microsoft.ManagedIdentity'=@('userAssignedIdentities')
        'Microsoft.Network'=@('virtualNetworks','networkInterfaces','networkSecurityGroups','natGateways','publicIPAddresses','privateEndpoints')
        'Microsoft.OperationalInsights'=@('workspaces')
    }
    foreach ($provider in $requirements.Keys) {
        $metadata=Invoke-CmpAz @('provider','show','--namespace',$provider) -Json
        if ($metadata.registrationState -cne 'Registered') { throw "Provider $provider is not Registered. Review and register manually; no automatic permission changes." }
        foreach ($type in $requirements[$provider]) {
            $matches=@($metadata.resourceTypes | Where-Object { $_.resourceType -ceq $type })
            if ($matches.Count -ne 1 -or 'indonesiacentral' -notin @($matches[0].locations | ForEach-Object { ($_ -replace '\s','').ToLowerInvariant() })) {
                throw "$provider/$type does not advertise Indonesia Central. No region fallback."
            }
        }
    }
}
function Get-SsoBootstrapHash([string]$Root) {
    $text=(@('bootstrap\postgres-vm.py','bootstrap\sso-postgres.py','bootstrap\sso-keycloak.py',
        'infra\sso-postgres-cloud-init.yml','infra\sso-keycloak-cloud-init.yml') |
        ForEach-Object { [IO.File]::ReadAllText((Join-Path $Root $_)).Replace("`r`n","`n") }) -join "`n"
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($text))).ToLowerInvariant()
}
function ConvertFrom-SsoProof([string]$Output,[string]$Operation) {
    if (-not $Output -or [Text.Encoding]::UTF8.GetByteCount($Output) -gt 4096) { throw 'Missing/bounded SSO guest completion evidence.' }
    try { $value=$Output | ConvertFrom-Json -AsHashtable } catch { throw 'SSO guest returned invalid completion evidence; suppressed.' }
    if ($value -isnot [Collections.IDictionary] -or $value['status'] -cne 'ready' -or $value['operation'] -cne $Operation) {
        throw 'SSO guest did not prove the requested operation completed.'
    }
    return @{status='ready';operation=$Operation}
}
function Invoke-SsoGuest([string]$VmId,[ValidateSet('postgres','keycloak')][string]$Operation) {
    $service=if ($Operation -eq 'postgres') { 'cmp-sso-postgres' } else { 'cmp-sso-keycloak-install' }
    $source=@'
set -eu
timeout 1800 cloud-init status --wait >/dev/null 2>&1
timeout 2400 sh -c 'while [ "$(systemctl show -p ActiveState --value __SERVICE__.service)" = activating ]; do sleep 5; done'
systemctl start __SERVICE__.service >/dev/null 2>&1
test "$(systemctl show -p Result --value __SERVICE__.service)" = success
test "$(systemctl show -p ExecMainStatus --value __SERVICE__.service)" = 0
__PROOF__
'@
    $proof=if ($Operation -eq 'postgres') { 'printf ''{"status":"ready","operation":"postgres"}\n''' } else {
        'python3 -B /opt/cmp/sso-keycloak.py configure'
    }
    $source=$source.Replace('__SERVICE__',$service).Replace('__PROOF__',$proof).Replace("`r`n","`n")
    $name='sso-'+$Operation+'-'+[guid]::NewGuid().ToString('N')
    $uri="https://management.azure.com$VmId/runCommands/${name}?api-version=2024-07-01"
    $null=Invoke-CmpRest -Uri $uri -Method PUT -Body @{
        location='indonesiacentral'; tags=@{costcontrol='ignore'}
        properties=@{source=@{script=$source};timeoutInSeconds=6000;asyncExecution=$true;treatFailureAsDeploymentFailure=$true}
    }
    $deadline=[DateTime]::UtcNow.AddMinutes(110)
    do {
        $response=Invoke-CmpRest -Uri "$uri&`$expand=instanceView"
        $p=$response.properties
        if ($p.provisioningState -in @('Failed','Canceled')) { throw "SSO $Operation managed command provisioning failed: $name. Output suppressed." }
        if ($p.PSObject.Properties.Name -contains 'instanceView' -and $p.instanceView) {
            $view=$p.instanceView
            if ($view.executionState -in @('Failed','Canceled','TimedOut')) {
                throw "SSO $Operation guest failed: $name. Check guest service result, scoped vault RBAC and packages; no readiness claim."
            }
            if ($view.executionState -eq 'Succeeded') {
                if ($view.PSObject.Properties.Name -notcontains 'exitCode' -or $view.exitCode -ne 0) {
                    throw "SSO $Operation completion lacks a zero guest exit code."
                }
                return ConvertFrom-SsoProof $view.output $Operation
            }
        }
        Start-Sleep -Seconds 10
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "SSO $Operation guest deadline exceeded. Inspect managed command $name before retry; never blindly replace the VM."
}
function Get-SsoMissingSecrets($Foundation) {
    $missing=@()
    foreach ($name in @('cmp-database-url','postgres-ca','session-secret','keycloak-db-password',
        'keycloak-admin-password','keycloak-client-secret')) {
        $metadata=Invoke-CmpRest -Uri "https://management.azure.com$($Foundation.vaultId)/secrets/${name}?api-version=2023-07-01" -AllowNotFound
        if ($null -eq $metadata) { $missing+=$name }
    }
    return $missing
}
function Assert-SsoKeycloakInventory($State) {
    $vm=Invoke-CmpAz @('vm','show','--ids',$State.keycloak.vmId) -Json
    $scope="/subscriptions/$($State.subscriptionId)/resourceGroups/$($State.resourceGroup)/providers"
    if ($vm.id -ine "$scope/Microsoft.Compute/virtualMachines/cmpsso-keycloak-vm" -or
        $vm.identity.principalId -ine $State.keycloak.principalId -or
        $vm.hardwareProfile.vmSize -cne $State.KeycloakVmSize -or
        $vm.storageProfile.osDisk.deleteOption -cne 'Detach' -or
        $vm.storageProfile.osDisk.managedDisk.id -ine "$scope/Microsoft.Compute/disks/cmpsso-keycloak-os") {
        throw 'Existing Keycloak VM identity, size or retained disk differs from saved contract; explicit recovery required.'
    }
    if ((Get-CmpVmPowerState (Invoke-CmpAz @('vm','get-instance-view','--ids',$State.keycloak.vmId) -Json)) -ne 'PowerState/running') {
        throw 'Existing Keycloak VM must already be running; never started or replaced automatically.'
    }
    $ip=Invoke-CmpRest -Uri "https://management.azure.com$scope/Microsoft.Network/publicIPAddresses/cmpsso-keycloak-ip?api-version=2024-05-01"
    if ($State.keycloak.origin -cne "https://$($ip.properties.dnsSettings.fqdn)" -or $ip.location -cne 'indonesiacentral') {
        throw 'Stable Keycloak public DNS/IP does not match the saved issuer.'
    }
}
function Test-SsoPublicEndpoints($State) {
    $issuer="$($State.keycloak.origin)/realms/cmp-pdf"
    Wait-CmpHttp "$issuer/.well-known/openid-configuration"
    $discovery=Invoke-RestMethod -Uri "$issuer/.well-known/openid-configuration" -TimeoutSec 30
    if ($discovery.issuer -cne $issuer -or -not $discovery.authorization_endpoint.StartsWith("$issuer/")) {
        throw 'Public Keycloak HTTPS discovery issuer differs from stable expected issuer.'
    }
    Wait-CmpHttp $State.keycloak.metadataUrl
    $xml=[xml](Invoke-WebRequest -Uri $State.keycloak.metadataUrl -TimeoutSec 30).Content
    if ($xml.DocumentElement.GetAttribute('entityID') -cne $issuer -or
        -not $xml.SelectSingleNode("//*[local-name()='KeyDescriptor'][@use='signing']//*[local-name()='X509Certificate']")) {
        throw 'Public SAML metadata issuer/signing certificate is missing or unexpected.'
    }
    foreach ($path in @('/admin','/admin/','/admin/master/console/','/realms/master','/health','/metrics')) {
        $response=Invoke-WebRequest -Uri "$($State.keycloak.origin)$path" -MaximumRedirection 0 -SkipHttpErrorCheck -TimeoutSec 30
        if ($response.StatusCode -ne 404) { throw "Public management path is not closed: $path" }
    }
    Wait-CmpHttp "$($State.frontendOrigin)/health"
    $response=Invoke-WebRequest -Uri $State.frontendOrigin -TimeoutSec 30
    if ($response.StatusCode -ne 200) { throw 'Frontend HTTPS was not verified.' }
}
