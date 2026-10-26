#requires -Version 7.0
<#
.SYNOPSIS
Add the isolated CMP cloud-sso admin backend without replacing VMs or changing Entra.
.DESCRIPTION
Validate is read-only; -Offline compiles templates and validates saved ownership locally.
Plan performs real ARM what-if only. Apply checkpoints every write, creates an independent
Windows DPAPI credential before protected transfer, and deploys one digest to both roles.
An interrupted write stage requires explicit inspection/recovery, never implicit rotation.
Verify performs only ARM/HTTPS reads. No command claims interactive SSO is operational.
#>
[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
param(
    [ValidateSet('Validate','Plan','Apply','Verify')][string]$Phase='Validate',
    [switch]$RebuildApplication,
    [switch]$EnableUserAdmin,
    [switch]$Offline
)
. (Join-Path $PSScriptRoot 'sso-common.ps1')
. (Join-Path $PSScriptRoot 'sso-user-admin-common.ps1')

function Get-AdminSecretNames { return @('cmp-admin-password-hash','cmp-admin-session') }
function Test-AdminLocation($Location) {
    if ($Location -isnot [string] -or $Location.Length -gt 64 -or $Location -cnotmatch '\A[A-Za-z ]+\z') { return $false }
    return $Location.Replace(' ','').ToLowerInvariant() -ceq 'indonesiacentral'
}
function Test-AdminProperty($Value,[string]$Name) {
    if ($Value -is [Collections.IDictionary]) { return $Value.Contains($Name) }
    return $null -ne $Value -and $Value.PSObject.Properties.Name -contains $Name
}
function Get-AdminPaths([string]$Root) {
    $base=[IO.Path]::GetFullPath($Root)
    return @{state=(Join-Path $base '.azure\sso-admin-state.json');store=(Join-Path $base '.azure\sso-admin.credential.xml')}
}
function Assert-AdminPath([string]$Path,[ValidateSet('state','store')][string]$Kind) {
    $name=if ($Kind -ceq 'state') { 'sso-admin-state.json' } else { 'sso-admin.credential.xml' }
    if (-not [IO.Path]::IsPathFullyQualified($Path) -or (Split-Path $Path -Leaf) -cne $name -or
        (Split-Path (Split-Path $Path) -Leaf) -cne '.azure') { throw 'Only the fixed admin .azure filenames are allowed.' }
    $current=$Path
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            $item=Get-Item -LiteralPath $current -Force
            if ($item.LinkType -or $item.Target) { throw 'Admin paths cannot traverse links or junctions.' }
        }
        $parent=Split-Path $current
        if ($parent -ceq $current) { break }
        $current=$parent
    }
}
function Get-AdminFoundationHash($Deployment) {
    $f=$Deployment.foundation
    $parts=@($Deployment.subscriptionId,$Deployment.tenantId,$Deployment.resourceGroup,$Deployment.prefix,
        $Deployment.bootstrapHash,$Deployment.vmBootstrapHash,$Deployment.keycloak.vmId,$Deployment.keycloak.principalId,
        $Deployment.keycloak.issuer)
    foreach($key in @('environmentId','defaultDomain','registryId','registryServer','vaultId','vaultUri','postgresVmId',
        'postgresDataDiskId','postgresPrincipalId','backendIdentityId','backendPrincipalId','backendClientId','frontendIdentityId')) {
        $parts+=@($f[$key])
    }
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData(
        [Text.Encoding]::UTF8.GetBytes(($parts -join "`n")))).ToLowerInvariant()
}
function New-AdminState($Deployment) {
    Assert-SsoScope $Deployment
    return @{schemaVersion='cmp-sso-admin-v1';ownershipId=[guid]::NewGuid().ToString();subscriptionId=$Deployment.subscriptionId
        tenantId=$Deployment.tenantId;resourceGroup=$Deployment.resourceGroup;prefix=$Deployment.prefix
        foundationHash=(Get-AdminFoundationHash $Deployment);stage='new';storeHash='';commandName=''
        applicationImage=$Deployment.applicationImage;sourceHash=$Deployment.sourceHash;secretUris=@{};brandingVerified=$false
        backendOrigin="https://cmpsso-backend.$($Deployment.foundation.defaultDomain)";frontendOrigin=$Deployment.frontendOrigin
        issuer=$Deployment.keycloak.issuer;projectsJson='[]'}
}
function Assert-AdminState($State,$Deployment) {
    $keys=@('schemaVersion','ownershipId','subscriptionId','tenantId','resourceGroup','prefix','foundationHash','stage',
        'storeHash','commandName','applicationImage','sourceHash','secretUris','brandingVerified','backendOrigin',
        'frontendOrigin','issuer','projectsJson')
    if ($State -isnot [Collections.IDictionary] -or $State.Count -ne $keys.Count -or
        @($State.Keys | Where-Object { $_ -cnotin $keys }).Count) { throw 'Admin state has unknown or missing fields; explicit recovery required.' }
    Assert-SsoScope $State
    if ($State.schemaVersion -cne 'cmp-sso-admin-v1' -or $State.ownershipId -cnotmatch '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$' -or
        $State.ownershipId -ceq [guid]::Empty.ToString() -or $State.foundationHash -cne (Get-AdminFoundationHash $Deployment) -or
        $State.backendOrigin -cne "https://cmpsso-backend.$($Deployment.foundation.defaultDomain)" -or
        $State.frontendOrigin -cne $Deployment.frontendOrigin -or $State.issuer -cne $Deployment.keycloak.issuer -or
        $State.stage -cnotin @('new','store-intent','prepared','seeding','seeded','granting','granted','writing','secrets-ready',
            'branding','branded','building','image-ready','deploying-backend','backend-ready','deploying-frontend','deployed','verified') -or
        $State.storeHash -isnot [string] -or $State.sourceHash -cnotmatch '^[a-f0-9]{64}$' -or
        $State.applicationImage -cnotmatch "^$([regex]::Escape($Deployment.foundation.registryServer))/cmp@sha256:[a-f0-9]{64}$" -or
        $State.brandingVerified -isnot [bool] -or $State.secretUris -isnot [Collections.IDictionary] -or
        $State.commandName -isnot [string] -or
        ($State.commandName -and $State.commandName -cnotmatch '^sso-admin-(initialize|brand)-[a-f0-9]{32}$')) {
        throw 'Admin ownership/scope/source/image/stage differs from the approved contract.'
    }
    if (($State.stage -cin @('new','store-intent') -and $State.storeHash -cne '') -or
        ($State.stage -cnotin @('new','store-intent') -and $State.storeHash -cnotmatch '^[a-f0-9]{64}$')) {
        throw 'Admin credential ownership hash is missing or unexpected.'
    }
    if ($State.secretUris.Count -notin @(0,2)) { throw 'Incomplete admin private secret version evidence.' }
    if ($State.stage -cin @('secrets-ready','branding','branded','building','image-ready','deploying-backend','backend-ready','deploying-frontend','deployed','verified') -and
        $State.secretUris.Count -ne 2) { throw 'Initialized admin stage requires both private secret version URIs.' }
    if ($State.stage -cin @('branded','building','image-ready','deploying-backend','backend-ready','deploying-frontend','deployed','verified') -and
        -not $State.brandingVerified) { throw 'Admin stage requires completed additive branding proof.' }
    foreach($name in $State.secretUris.Keys) {
        if ($name -cnotin (Get-AdminSecretNames) -or $State.secretUris[$name] -cnotmatch
            ('^'+[regex]::Escape("$($Deployment.foundation.vaultUri)secrets/$name/")+'[a-f0-9]{32}$')) {
            throw 'Admin secret version URI differs from the private vault contract.'
        }
    }
    try { $projects=ConvertFrom-Json -InputObject $State.projectsJson -NoEnumerate -Depth 10 } catch { throw 'Invalid saved frontend projects JSON.' }
    if ($projects -isnot [array] -or $State.projectsJson.Length -gt 16384) { throw 'Saved frontend project configuration is not bounded JSON array.' }
}
function Save-AdminState($State,[string]$Path) {
    Assert-AdminPath $Path 'state'
    $deployment=$script:AdminDeployment
    Assert-AdminState $State $deployment
    $raw=$State | ConvertTo-Json -Depth 10 -Compress
    $stream=[IO.File]::Open("$Path.pending",[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {
        $bytes=[Text.Encoding]::UTF8.GetBytes($raw)
        $stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)
    } finally { $stream.Dispose() }
    [IO.File]::Move("$Path.pending",$Path,$true)
}
function Read-AdminState([string]$Path,$Deployment) {
    Assert-AdminPath $Path 'state'
    if ((Test-Path -LiteralPath "$Path.pending") -or (Get-Item -LiteralPath $Path).Length -gt 32768) {
        throw 'Admin state checkpoint is incomplete or oversized; explicit recovery required.'
    }
    try { $state=[IO.File]::ReadAllText($Path) | ConvertFrom-Json -AsHashtable -Depth 10 }
    catch { throw 'Admin state is invalid; explicit recovery required.' }
    Assert-AdminState $state $Deployment
    return $state
}
function New-AdminRandom {
    return [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(48)).TrimEnd('=').Replace('+','-').Replace('/','_')
}
function Assert-AdminStore($Store,[string]$OwnershipId) {
    if (-not $IsWindows -or $Store -isnot [Collections.IDictionary] -or $Store.Count -ne 5 -or
        $Store['schemaVersion'] -cne 'cmp-admin-dpapi-v1' -or $Store['ownershipId'] -cne $OwnershipId -or
        $Store['credential'] -isnot [Management.Automation.PSCredential] -or $Store.credential.UserName -cne 'cmpadmin' -or
        $Store['session'] -isnot [Management.Automation.PSCredential] -or $Store.session.UserName -cne 'cmp-admin-session' -or
        $Store['salt'] -cnotmatch '^[a-f0-9]{32}$') { throw 'Windows DPAPI credential envelope ownership/shape differs; no plaintext fallback.' }
    $password=$Store.credential.GetNetworkCredential().Password
    $session=$Store.session.GetNetworkCredential().Password
    try {
        if ($password -cnotmatch '^[A-Za-z0-9_-]{64}$' -or $session -cnotmatch '^[A-Za-z0-9_-]{64}$' -or
            $password -ceq $session) { throw 'Independent admin credential/session cannot be decrypted or are invalid.' }
    } finally { $password=$null;$session=$null }
}
function Read-AdminStore($State,$Paths) {
    Assert-AdminPath $Paths.store 'store'
    if (-not $IsWindows) { throw 'Windows DPAPI is required; use the original Windows user/computer.' }
    if ($State.stage -cin @('new','store-intent') -or -not (Test-Path -LiteralPath $Paths.store) -or
        (Test-Path -LiteralPath "$($Paths.store).pending") -or (Get-Item -LiteralPath $Paths.store).Length -gt 65536 -or
        (Get-FileHash -LiteralPath $Paths.store -Algorithm SHA256).Hash.ToLowerInvariant() -cne $State.storeHash) {
        throw 'Admin credential store is missing, changed, unowned or uncertain; it is never regenerated or rotated.'
    }
    try { $store=Import-Clixml -LiteralPath $Paths.store } catch { throw 'DPAPI import failed; no plaintext fallback.' }
    Assert-AdminStore $store $State.ownershipId
    return $store
}
function Initialize-AdminStore($State,$Paths) {
    if (-not $IsWindows) { throw 'Admin initial credentials require Windows DPAPI; no plaintext fallback.' }
    Assert-AdminPath $Paths.store 'store'
    Assert-AdminPath $Paths.state 'state'
    if ($State.stage -cne 'new') { return Read-AdminStore $State $Paths }
    foreach($path in @($Paths.store,$Paths.state,"$($Paths.store).pending","$($Paths.state).pending")) {
        if (Test-Path -LiteralPath $path) { throw 'Unowned/partial admin artifacts exist; explicit recovery required.' }
    }
    $State.stage='store-intent'
    Save-AdminState $State $Paths.state
    $store=@{schemaVersion='cmp-admin-dpapi-v1';ownershipId=$State.ownershipId
        credential=[pscredential]::new('cmpadmin',(ConvertTo-SecureString (New-AdminRandom) -AsPlainText -Force))
        session=[pscredential]::new('cmp-admin-session',(ConvertTo-SecureString (New-AdminRandom) -AsPlainText -Force))
        salt=[Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(16)).ToLowerInvariant()}
    Assert-AdminStore $store $State.ownershipId
    $store | Export-Clixml -LiteralPath "$($Paths.store).pending" -Depth 5 -NoClobber
    $stream=[IO.File]::Open("$($Paths.store).pending",[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try { $stream.Flush($true) } finally { $stream.Dispose() }
    [IO.File]::Move("$($Paths.store).pending",$Paths.store)
    $State.storeHash=(Get-FileHash -LiteralPath $Paths.store -Algorithm SHA256).Hash.ToLowerInvariant()
    $State.stage='prepared'
    Save-AdminState $State $Paths.state
    return Read-AdminStore $State $Paths
}
function Get-AdminCredentialDisplay($Store) {
    Assert-AdminStore $Store $Store.ownershipId
    return [pscustomobject]@{username=$Store.credential.UserName}
}
function Invoke-AdminNode([string]$Code,[hashtable]$InputObject) {
    $start=[Diagnostics.ProcessStartInfo]::new()
    $start.FileName=(Get-Command node -CommandType Application -ErrorAction Stop).Source
    $start.ArgumentList.Add('--input-type=module');$start.ArgumentList.Add('-e');$start.ArgumentList.Add($Code)
    $start.WorkingDirectory=Split-Path $PSScriptRoot
    $start.UseShellExecute=$false;$start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    $process=[Diagnostics.Process]::new();$process.StartInfo=$start
    try {
        $null=$process.Start()
        $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
        $process.StandardInput.Write(($InputObject|ConvertTo-Json -Depth 4 -Compress));$process.StandardInput.Close()
        if (-not $process.WaitForExit(30000)) { $process.Kill($true);throw 'Admin hash child deadline exceeded; output suppressed.' }
        if ($process.ExitCode -ne 0) { throw 'Admin hash child failed; output suppressed.' }
        $result=$stdout.GetAwaiter().GetResult()
        if ($result.Length -gt 512) { throw 'Admin hash child output oversized; suppressed.' }
        return $result.Trim()
    } finally { $InputObject.Clear();$process.Dispose() }
}
function Get-AdminPasswordHash($Store) {
    Assert-AdminStore $Store $Store.ownershipId
    $code=@'
import {scryptSync} from 'node:crypto';
let raw=''; for await (const chunk of process.stdin) raw+=chunk;
const x=JSON.parse(raw);
if (!/^[a-f0-9]{32}$/.test(x.salt) || !/^[A-Za-z0-9_-]{64}$/.test(x.password)) process.exit(2);
const hash=scryptSync(x.password,x.salt,64,{N:16384,r:8,p:1}).toString('hex');
process.stdout.write(`scrypt$16384$8$1$${x.salt}$${hash}`);
'@
    $result=Invoke-AdminNode $code @{password=$Store.credential.GetNetworkCredential().Password;salt=$Store.salt}
    if ($result -cnotmatch '^scrypt\$16384\$8\$1\$[a-f0-9]{32}\$[a-f0-9]{128}$') { throw 'Admin hash child returned an invalid runtime format.' }
    return $result
}
function Get-AdminProtectedPayload($State,$Store,[ValidateSet('initialize','brand')][string]$Operation) {
    $payload=@{operation=$Operation;ownershipId=$State.ownershipId;storeHash=$State.storeHash
        tenantId=$State.tenantId;vaultUri='https://cmpsso-contoso-kv.vault.azure.net/'}
    if ($Operation -ceq 'initialize') {
        Assert-AdminStore $Store $State.ownershipId
        $payload.passwordHash=Get-AdminPasswordHash $Store
        $payload.session=$Store.session.GetNetworkCredential().Password
    }
    return $payload
}
function ConvertFrom-AdminProof([string]$Raw,[string]$Operation,$Deployment) {
    if (-not $Raw -or [Text.Encoding]::UTF8.GetByteCount($Raw) -gt 4096) { throw 'Missing/oversized admin guest evidence.' }
    try { $proof=$Raw|ConvertFrom-Json -AsHashtable -Depth 6 } catch { throw 'Invalid admin guest evidence; raw output suppressed.' }
    if ($proof -isnot [Collections.IDictionary] -or $proof['status'] -cne 'ready' -or $proof['operation'] -cne $Operation) {
        throw 'Admin guest readiness was not proven; raw output suppressed.'
    }
    if ($Operation -ceq 'initialize') {
        if ($proof['secretUris'] -isnot [Collections.IDictionary] -or $proof.secretUris.Count -ne 2) { throw 'Private secret version evidence incomplete.' }
        $uris=@{}
        foreach($name in Get-AdminSecretNames) {
            if ($proof.secretUris[$name] -cnotmatch ('^'+[regex]::Escape("$($Deployment.foundation.vaultUri)secrets/$name/")+'[a-f0-9]{32}$')) {
                throw 'Private admin secret URI does not match approved vault.'
            }
            $uris[$name]=$proof.secretUris[$name]
        }
        return @{status='ready';operation=$Operation;secretUris=$uris}
    }
    if ($proof['issuer'] -cne $Deployment.keycloak.issuer -or $proof['displayName'] -cne 'CMP' -or
        $proof['clientName'] -cne 'CMP (Cloud Management Platform)' -or $proof['loginVerified'] -isnot [bool] -or
        $proof.loginVerified) { throw 'Branding proof changed immutable issuer or did not preserve approved branding.' }
    return @{status='ready';operation='brand';issuer=$proof.issuer;displayName='CMP'
        clientName='CMP (Cloud Management Platform)';loginVerified=$false}
}
function Invoke-AdminGuest($Deployment,$State,[ValidateSet('initialize','brand')][string]$Operation,[hashtable]$Payload) {
    if ($State.commandName -cnotmatch ("^sso-admin-"+$Operation+"-[a-f0-9]{32}$")) { throw 'A durable command intention is required.' }
    $encoded=[Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path (Split-Path $PSScriptRoot) 'bootstrap\sso-admin.py')))
    $source=@'
set -eu
umask 077
test "$(id -u)" = 0
python3 -B - <<'CMP_ADMIN_RUN'
import base64
exec(compile(base64.b64decode('__CODE__'), '/opt/cmp/sso-admin.py', 'exec'), {'__name__':'__main__'})
CMP_ADMIN_RUN
'@
    $vmId=if ($Operation -ceq 'brand') { $Deployment.keycloak.vmId } else { $Deployment.foundation.postgresVmId }
    $uri="https://management.azure.com$vmId/runCommands/$($State.commandName)?api-version=2024-07-01"
    $properties=@{source=@{script=$source.Replace('__CODE__',$encoded).Replace("`r`n","`n")}
        timeoutInSeconds=600;asyncExecution=$true;treatFailureAsDeploymentFailure=$true
        protectedParameters=@(@{name='CMP_ADMIN_PAYLOAD';value=($Payload|ConvertTo-Json -Depth 6 -Compress)})}
    try {
        $null=Invoke-CmpRest -Uri $uri -Method PUT -Body @{location='indonesiacentral';tags=@{costcontrol='ignore'};properties=$properties}
    } catch { throw "Admin $Operation command submission uncertain: $($State.commandName). Inspect before recovery; output suppressed." }
    finally { $null=$properties.Remove('protectedParameters');$Payload.Clear() }
    $deadline=[DateTime]::UtcNow.AddMinutes(12)
    do {
        $response=Invoke-CmpRest -Uri "$uri&`$expand=instanceView"
        $p=$response.properties
        if ($p.provisioningState -in @('Failed','Canceled')) { throw "Admin $Operation provisioning failed; inspect $($State.commandName); no blind retry." }
        if ($p.PSObject.Properties.Name -contains 'instanceView' -and $p.instanceView) {
            $view=$p.instanceView
            if ($view.executionState -in @('Failed','Canceled','TimedOut')) { throw "Admin $Operation guest failed; inspect private journal and $($State.commandName); output suppressed." }
            if ($view.executionState -ceq 'Succeeded') {
                if ($view.PSObject.Properties.Name -notcontains 'exitCode' -or $view.exitCode -isnot [int] -and $view.exitCode -isnot [long] -or $view.exitCode -ne 0) {
                    throw 'Admin guest completion lacks a zero exit code.'
                }
                return ConvertFrom-AdminProof $view.output $Operation $Deployment
            }
        }
        Start-Sleep -Seconds 5
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Admin command completion uncertain: $($State.commandName). Inspect before explicit recovery; never rotate/retry blindly."
}
function Assert-AdminFoundation($Deployment,[string]$Root) {
    Assert-SsoSavedState $Deployment $Root
    $f=$Deployment.foundation
    $scope="/subscriptions/$($Deployment.subscriptionId)/resourceGroups/$($Deployment.resourceGroup)/providers"
    if ($f.backendIdentityId -ine "$scope/Microsoft.ManagedIdentity/userAssignedIdentities/cmpsso-backend-id" -or
        $f.registryName -cne 'cmpssocontosoacr' -or
        $f.registryId -ine "$scope/Microsoft.ContainerRegistry/registries/cmpssocontosoacr" -or
        $f.vaultName -cne 'cmpsso-contoso-kv' -or
        $f.vaultUri -cne 'https://cmpsso-contoso-kv.vault.azure.net/' -or
        $f.defaultDomain -cne 'xxxxxxxx.indonesiacentral.azurecontainerapps.io' -or
        $Deployment.keycloak.origin -cne 'https://cmpsso-xxxxxxxxxx.indonesiacentral.cloudapp.azure.com' -or
        $f.backendPrincipalId -cnotmatch '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$' -or
        $f.backendClientId -cnotmatch '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$') {
        throw 'Admin foundation differs from the fixed approved isolated environment/vault/registry/backend identity.'
    }
}
function Get-AdminSecretMetadata($Deployment) {
    $found=@{}
    foreach($name in Get-AdminSecretNames) {
        $id="$($Deployment.foundation.vaultId)/secrets/$name"
        $metadata=Invoke-CmpRest -Uri "https://management.azure.com${id}?api-version=2023-07-01" -AllowNotFound
        if ($null -ne $metadata) {
            if ($metadata.id -ine $id) { throw 'Untrusted admin secret ARM metadata identifier.' }
            $found[$name]=$metadata
        }
    }
    return $found
}
function Assert-AdminIdentityRoles {
    param($Deployment,[switch]$RequireSecretReads,$UserFeature=$null,[switch]$RequireUserAdminRead)
    $f=$Deployment.foundation
    $base="https://management.azure.com/subscriptions/$($Deployment.subscriptionId)/providers/Microsoft.Authorization/roleAssignments"
    $uri="$base`?api-version=2022-04-01&`$filter="+[uri]::EscapeDataString("assignedTo('$($f.backendPrincipalId)')")
    $seen=@{};$pull=$false;$reads=@{}
    $allowed=@('cmp-database-url','postgres-ca')+(Get-AdminSecretNames) | ForEach-Object { "$($f.vaultId)/secrets/$_" }
    $required=@($allowed)
    if ($UserFeature) {
        Assert-UserAdminState $UserFeature $Deployment @{ownershipId=$UserFeature.baseAdminOwner} -RequireComplete
        $scope="$($f.vaultId)/secrets/$(Get-UserAdminSecretName)"
        $allowed+=@($scope)
        if ($RequireUserAdminRead) { $required+=@($scope) }
    } elseif ($RequireUserAdminRead) { throw 'User-admin secret read cannot be required without commissioned feature ownership.' }
    do {
        $parsed=[uri]$uri
        if ($parsed.Scheme -cne 'https' -or $parsed.Host -cne 'management.azure.com' -or $parsed.Port -ne 443 -or
            $parsed.UserInfo -or $parsed.Fragment -or $parsed.AbsolutePath -ine ([uri]$base).AbsolutePath -or
            $seen.ContainsKey($uri) -or $seen.Count -ge 100) { throw 'Untrusted identity-role inventory continuation.' }
        $seen[$uri]=$true
        $page=Invoke-CmpRest -Uri $uri
        if ($page.PSObject.Properties.Name -notcontains 'value') { throw 'Backend role inventory is incomplete.' }
        foreach($assignment in $page.value) {
            $p=$assignment.properties
            $role=([string]$p.roleDefinitionId).Split('/')[-1]
            if ($p.principalId -ine $f.backendPrincipalId) { throw 'Backend role inventory principal differs.' }
            if ($role -ceq '7f951dda-4ed3-4680-a7ca-43fe172d538d' -and $p.scope -ieq $f.registryId) { $pull=$true;continue }
            if ($role -cne '4633458b-17de-408a-b874-0445c86b69e6' -or $p.scope -notin $allowed) {
                throw 'Backend identity has an unexpected/broad role. This workflow never grants vault-wide access or repairs existing grants.'
            }
            $reads[[string]$p.scope]=$true
        }
        $uri=if ($page.PSObject.Properties.Name -contains 'nextLink') { [string]$page.nextLink } else { $null }
    } while ($uri)
    if (-not $pull) { throw 'Existing backend identity registry-scoped AcrPull is required; no automatic registry access expansion.' }
    if ($RequireSecretReads -and @($required|Where-Object { -not $reads.ContainsKey($_) }).Count) {
        throw 'Backend exact owned private secret read grants are incomplete.'
    }
}
function Get-AdminInventory($Deployment,$State,$UserFeature=$null,[bool]$UserAdminEnabled=$false) {
    if ($UserFeature) {
        Assert-UserAdminState $UserFeature $Deployment $State -RequireComplete
        $null=Get-UserAdminNetworkInventory $Deployment $UserFeature -IncludeSubnetNsg:([bool]$UserFeature.subnetNsgName)
    } elseif ($UserAdminEnabled) { throw 'User-admin opt-in requires commissioned private configuration proof.' }
    Assert-CmpPrivateInventory $Deployment
    Assert-SsoKeycloakInventory $Deployment
    $f=$Deployment.foundation
    $identity=Invoke-CmpRest -Uri "https://management.azure.com$($f.backendIdentityId)?api-version=2023-01-31"
    if ($identity.id -ine $f.backendIdentityId -or -not (Test-AdminLocation $identity.location) -or
        $identity.properties.principalId -ine $f.backendPrincipalId -or $identity.properties.clientId -ine $f.backendClientId) {
        throw 'Existing backend managed identity changed.'
    }
    $requireReads=$State -and $State.stage -cin @('backend-ready','deploying-frontend','deployed','verified')
    Assert-AdminIdentityRoles $Deployment -RequireSecretReads:$requireReads -UserFeature $UserFeature -RequireUserAdminRead:($requireReads -and $UserAdminEnabled)
    $env=Invoke-CmpRest -Uri "https://management.azure.com$($f.environmentId)?api-version=2025-07-01"
    if ($env.id -ine $f.environmentId -or -not (Test-AdminLocation $env.location) -or
        $env.properties.defaultDomain -cne $f.defaultDomain) { throw 'Existing Container Apps environment changed.' }
    $scope="/subscriptions/$($Deployment.subscriptionId)/resourceGroups/$($Deployment.resourceGroup)/providers/Microsoft.App/containerApps"
    $frontend=Invoke-CmpRest -Uri "https://management.azure.com$scope/cmpsso-frontend?api-version=2025-07-01"
    if ($frontend.id -ine "$scope/cmpsso-frontend" -or -not (Test-AdminLocation $frontend.location) -or
        $frontend.properties.environmentId -ine $f.environmentId -or
        @($frontend.identity.userAssignedIdentities.PSObject.Properties.Name) -inotcontains $f.frontendIdentityId) {
        throw 'Existing frontend environment/identity differs.'
    }
    $backend=Invoke-CmpRest -Uri "https://management.azure.com$scope/cmpsso-backend?api-version=2025-07-01" -AllowNotFound
    if ($backend -and (-not $State -or $backend.tags.cmpAdminOwner -cne $State.ownershipId -or
        $backend.id -ine "$scope/cmpsso-backend" -or $backend.properties.environmentId -ine $f.environmentId -or
        -not (Test-AdminLocation $backend.location) -or $backend.identity.type -cne 'UserAssigned' -or
        @($backend.identity.userAssignedIdentities.PSObject.Properties.Name).Count -ne 1 -or
        @($backend.identity.userAssignedIdentities.PSObject.Properties.Name) -inotcontains $f.backendIdentityId)) {
        throw 'An unowned/different backend already exists; never adopt or replace it.'
    }
    if ($backend -and -not $UserAdminEnabled -and (Test-AdminProperty $backend.properties 'template')) {
        $enabled=@($backend.properties.template.containers[0].env|Where-Object { $_.name -ceq 'CMP_USER_ADMIN' -and $_.value -ceq 'enabled' })
        if ($enabled.Count) { throw 'Existing user administration must be preserved with explicit -EnableUserAdmin; never implicitly remove it.' }
    }
    $metadata=Get-AdminSecretMetadata $Deployment
    if (-not $State -and $metadata.Count) { throw 'Unknown existing admin vault secrets; lost state cannot be regenerated or adopted.' }
    if ($State -and $State.stage -cin @('new','store-intent','prepared') -and $metadata.Count) {
        throw 'Admin secrets appeared before the recorded seed intention; explicit recovery required.'
    }
    if ($State -and $State.secretUris.Count -eq 2) {
        foreach($name in Get-AdminSecretNames) {
            if (-not $metadata.ContainsKey($name) -or $metadata[$name].properties.secretUriWithVersion -cne $State.secretUris[$name]) {
                throw 'Initialized admin secret version changed or disappeared; no implicit adoption or rotation.'
            }
        }
    }
    return @{frontend=$frontend;backend=$backend;metadata=$metadata}
}
function Get-AdminAppParameters($Deployment,$State) {
    $f=$Deployment.foundation
    return @{prefix='cmpsso';location='indonesiacentral';environmentName=$f.environmentName;defaultDomain=$f.defaultDomain
        registryServer=$f.registryServer;applicationImage=$State.applicationImage;vaultUri=$f.vaultUri
        keycloakOrigin=$Deployment.keycloak.origin;tenantId=$Deployment.tenantId}
}
function Test-AdminDeployment($Deployment,$State,$UserFeature=$null,[bool]$UserAdminEnabled=$false) {
    if ($State.stage -cnotin @('deployed','verified') -or -not $State.brandingVerified -or $State.secretUris.Count -ne 2) {
        throw 'Admin deployment has not reached a complete stage; no readiness claim.'
    }
    if ($UserAdminEnabled -and -not $UserFeature) { throw 'User-admin opt-in requires commissioned feature ownership.' }
    if ($UserAdminEnabled) { Assert-UserAdminState $UserFeature $Deployment $State -RequireComplete }
    $inventory=Get-AdminInventory $Deployment $State $UserFeature $UserAdminEnabled
    foreach($role in @('frontend','backend')) {
        $app=$inventory[$role]
        if (-not $app -or $app.properties.provisioningState -cne 'Succeeded' -or
            $app.properties.configuration.activeRevisionsMode -cne 'Single' -or
            $app.properties.configuration.ingress.allowInsecure -ne $false -or
            $app.properties.configuration.ingress.targetPort -ne 8080 -or
            $app.properties.template.containers.Count -ne 1 -or
            $app.properties.template.scale.minReplicas -ne 1 -or $app.properties.template.scale.maxReplicas -ne 1 -or
            $app.properties.template.containers[0].resources.cpu -ne 0.5 -or
            $app.properties.template.containers[0].resources.memory -cne '1Gi' -or
            $app.properties.template.containers[0].image -cne $State.applicationImage) {
            throw 'Both roles must be healthy, HTTPS-only and run the same approved digest.'
        }
        $variables=@{}
        foreach($entry in $app.properties.template.containers[0].env) {
            if ($variables.ContainsKey($entry.name)) { throw 'Duplicate deployed environment variable.' }
            $variables[$entry.name]=$entry
        }
        $required=if ($role -ceq 'backend') {
            @{APP_MODE='live';APP_ROLE='backend';CMP_ADMIN_MODE='cloud-sso';IDENTITY_FLOW='keycloak-federation'
                KEYCLOAK_REALM='cmp-pdf';KEYCLOAK_URL=$Deployment.keycloak.origin;ADMIN_USERNAME='cmpadmin';PUBLIC_ORIGIN=$State.backendOrigin}
        } else { @{APP_MODE='live';APP_ROLE='frontend';ADMIN_ORIGIN=$State.backendOrigin;CMP_CLOUD_REGISTRY='enabled'
            IDENTITY_FLOW='keycloak-federation';KEYCLOAK_REALM='cmp-pdf';PUBLIC_ORIGIN=$State.frontendOrigin} }
        foreach($name in $required.Keys) {
            if (-not $variables.ContainsKey($name) -or $variables[$name].value -cne $required[$name]) { throw 'Deployed role environment differs from approved admin contract.' }
        }
        if ($role -ceq 'backend') {
            if ($variables.ContainsKey('CMP_USER_ADMIN_SMTP_CONFIGURED') -and $variables.CMP_USER_ADMIN_SMTP_CONFIGURED.value -cne 'disabled') {
                throw 'SMTP delivery is not commissioned by this workflow; do not enable verify-email without separate SMTP proof and approval.'
            }
            if ($UserAdminEnabled) {
                foreach($entry in @{CMP_USER_ADMIN='enabled';KEYCLOAK_USER_ADMIN_URL=(Get-UserAdminEndpoint);KEYCLOAK_USER_ADMIN_CLIENT_ID='cmp-user-admin'}.GetEnumerator()) {
                    if (-not $variables.ContainsKey($entry.Key) -or $variables[$entry.Key].value -cne $entry.Value) { throw 'Backend private user-admin environment differs.' }
                }
                if (-not $variables.ContainsKey('KEYCLOAK_USER_ADMIN_CLIENT_SECRET') -or
                    $variables.KEYCLOAK_USER_ADMIN_CLIENT_SECRET.secretRef -cne (Get-UserAdminSecretName) -or
                    ((Test-AdminProperty $variables.KEYCLOAK_USER_ADMIN_CLIENT_SECRET 'value') -and $variables.KEYCLOAK_USER_ADMIN_CLIENT_SECRET.value)) {
                    throw 'Backend user-admin secret binding differs.'
                }
            } elseif ($variables.ContainsKey('CMP_USER_ADMIN') -and $variables.CMP_USER_ADMIN.value -cne 'disabled') {
                throw 'Backend user administration enabled without explicit owned opt-in.'
            }
            if (-not $UserAdminEnabled -and @($variables.Keys|Where-Object { $_ -clike 'KEYCLOAK_USER_ADMIN_*' }).Count) {
                throw 'Disabled backend contains private user-admin configuration.'
            }
            $registries=@($app.properties.configuration.registries)
            if ($registries.Count -ne 1 -or $registries[0].server -cne $Deployment.foundation.registryServer -or
                $registries[0].identity -ine $Deployment.foundation.backendIdentityId) { throw 'Backend registry identity differs.' }
            if ($variables.ADMIN_PASSWORD_HASH.secretRef -cne 'cmp-admin-password-hash' -or
                $variables.SESSION_SECRET.secretRef -cne 'cmp-admin-session' -or
                $variables.DATABASE_URL.secretRef -cne 'cmp-database-url') { throw 'Backend secret bindings differ.' }
            $ca=@($app.properties.template.volumes|Where-Object name -CEQ 'postgres-tls')
            $mount=@($app.properties.template.containers[0].volumeMounts|Where-Object volumeName -CEQ 'postgres-tls')
            if ($ca.Count -ne 1 -or $ca[0].storageType -cne 'Secret' -or $ca[0].secrets.Count -ne 1 -or
                $ca[0].secrets[0].secretRef -cne 'postgres-ca' -or $ca[0].secrets[0].path -cne 'ca.crt' -or
                $mount.Count -ne 1 -or $mount[0].mountPath -cne '/mnt/postgres-tls') { throw 'Backend private PostgreSQL CA mount differs.' }
            $expected=@('cmp-database-url','postgres-ca')+(Get-AdminSecretNames)
            if ($UserAdminEnabled) { $expected+=@((Get-UserAdminSecretName)) }
            if ($app.properties.configuration.secrets.Count -ne $expected.Count) { throw 'Unexpected backend secret count.' }
            $secretSeen=@{}
            foreach($secret in $app.properties.configuration.secrets) {
                if ($secretSeen.ContainsKey($secret.name) -or $secret.name -cnotin $expected -or $secret.keyVaultUrl -cne "$($Deployment.foundation.vaultUri)secrets/$($secret.name)" -or
                    $secret.identity -ine $Deployment.foundation.backendIdentityId) { throw 'Backend secret reference scope differs.' }
                $secretSeen[$secret.name]=$true
            }
        } elseif (@($variables.Keys|Where-Object { $_ -clike 'KEYCLOAK_USER_ADMIN_*' -or $_ -clike 'CMP_USER_ADMIN*' }).Count -or
            @($app.properties.configuration.secrets|Where-Object name -CEQ (Get-UserAdminSecretName)).Count) {
            throw 'Private user administration must never be exposed to the frontend role.'
        }
        Wait-CmpHttp "$($State[$role+'Origin'])/health"
    }
    $discovery=Invoke-RestMethod -Uri "$($State.issuer)/.well-known/openid-configuration" -TimeoutSec 30
    if ($discovery.issuer -cne $State.issuer) { throw 'Keycloak immutable issuer changed.' }
    foreach($path in @('/admin','/admin/','/admin/master/console/','/realms/master','/health','/metrics')) {
        $response=Invoke-WebRequest -Uri "$($Deployment.keycloak.origin)$path" -MaximumRedirection 0 -SkipHttpErrorCheck -TimeoutSec 30
        if ($response.StatusCode -ne 404) { throw 'Keycloak public management path is not closed.' }
    }
    return [pscustomobject]@{status='AdminInfrastructureVerified';backendOrigin=$State.backendOrigin;frontendOrigin=$State.frontendOrigin
        issuer=$State.issuer;applicationImage=$State.applicationImage;identityLogin='NOT VERIFIED: interactive Azure/Entra federation remains separate'}
}
function Invoke-AdminMain {
    [CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
    param()
    $root=Split-Path $PSScriptRoot
    $paths=Get-AdminPaths $root
    foreach($kind in @('state','store')) { Assert-AdminPath $paths[$kind] $kind }
    if ($Offline -and $Phase -cne 'Validate') { throw '-Offline is allowed only for Validate.' }
    if ($RebuildApplication -and $Phase -cne 'Apply') { throw '-RebuildApplication is allowed only for Apply; Plan shows the currently bound digest.' }
    $deploymentPath=Get-CmpProjectPath $root '.azure\sso-deployment-state.json'
    $deployment=Get-Content -LiteralPath $deploymentPath -Raw | ConvertFrom-Json -AsHashtable
    Assert-AdminFoundation $deployment $root
    $script:AdminDeployment=$deployment
    $script:CmpSubscriptionId=$deployment.subscriptionId;$script:CmpTenantId=$deployment.tenantId
    $templates=@{}
    foreach($name in @('sso-admin','sso-frontend','sso-seed-secrets','sso-secret-access')) {
        $templates[$name]=Get-CmpTemplate (Join-Path $root "infra\$name.bicep")
    }
    $state=$null
    if (Test-Path -LiteralPath $paths.state) {
        $state=Read-AdminState $paths.state $deployment
        $null=Read-AdminStore $state $paths
    } elseif ((Test-Path -LiteralPath $paths.store) -or (Test-Path -LiteralPath "$($paths.state).pending") -or
        (Test-Path -LiteralPath "$($paths.store).pending")) { throw 'Unowned admin local artifacts; never adopt/regenerate lost state.' }
    $userFeature=Get-UserAdminFeature $deployment $state $root
    if ($EnableUserAdmin -and -not $userFeature) { throw '-EnableUserAdmin requires completed owned private commissioning first.' }
    if ($Offline) {
        return [pscustomobject]@{status='OfflineValidationOnly';writes='None';templates=4;cloudReadiness='NOT VERIFIED'}
    }
    Initialize-CmpContext $deployment.subscriptionId $deployment.tenantId 'admin@contoso.com'
    $account=Invoke-CmpAz @('account','show') -Json
    if ($account.environmentName -cne 'AzureCloud' -or $account.state -cne 'Enabled') { throw 'Only Enabled AzureCloud context is approved.' }
    Assert-SsoToken (Get-CmpToken)
    $inventory=Get-AdminInventory $deployment $state $userFeature ([bool]$EnableUserAdmin)
    if ($Phase -ceq 'Verify') {
        if (-not $state) { throw 'Verify requires owned completed admin state.' }
        return Test-AdminDeployment $deployment $state $userFeature ([bool]$EnableUserAdmin)
    }
    if ($Phase -ceq 'Validate') {
        return [pscustomobject]@{status='ValidatedOnly';writes='None';adminStage=$(if ($state) {$state.stage} else {'NotInitialized'});identityLogin='NOT VERIFIED'}
    }
    $candidate=if ($state) { $state } else { New-AdminState $deployment }
    if (-not $state) {
        $projects=@($inventory.frontend.properties.template.containers[0].env | Where-Object name -CEQ 'CMP_PROJECTS_JSON')
        if ($projects.Count -ne 1) { throw 'Existing frontend projects configuration is ambiguous; refusing to reset it.' }
        $candidate.projectsJson=[string]$projects[0].value
        Assert-AdminState $candidate $deployment
    }
    $parameters=Get-AdminAppParameters $deployment $candidate
    if ($Phase -ceq 'Plan') {
        $missing=@(Get-AdminSecretNames | Where-Object { -not $inventory.metadata.ContainsKey($_) })
        if ($missing.Count) {
            Invoke-CmpDeployment $deployment.resourceGroup 'cmpsso-admin-seed' $templates['sso-seed-secrets'] @{
                vaultName=$deployment.foundation.vaultName;missingNames=$missing} -Preview
        }
        Invoke-CmpDeployment $deployment.resourceGroup 'cmpsso-admin-write' $templates['sso-secret-access'] @{
            vaultName=$deployment.foundation.vaultName;principalId=$deployment.foundation.postgresPrincipalId;access='write';secretNames=(Get-AdminSecretNames)} -Preview
        Invoke-CmpDeployment $deployment.resourceGroup 'cmpsso-admin' $templates['sso-admin'] (
            $parameters+@{vaultName=$deployment.foundation.vaultName;ownershipId=$candidate.ownershipId;backendPrincipalId=$deployment.foundation.backendPrincipalId;userAdminEnabled=[bool]$EnableUserAdmin}) -Preview
        Invoke-CmpDeployment $deployment.resourceGroup 'cmpsso-admin-frontend' $templates['sso-frontend'] (
            $parameters+@{projectsJson=$candidate.projectsJson;adminOrigin=$candidate.backendOrigin;cloudRegistryMode='enabled'}) -Preview
        return
    }
    if (-not $IsWindows) { throw 'Apply requires Windows DPAPI.' }
    if ($candidate.stage -cin @('store-intent','seeding','granting','writing','branding','building','deploying-backend','deploying-frontend')) {
        throw "Admin stage '$($candidate.stage)' is an uncertain write. Inspect deployments/command $($candidate.commandName) and private journal before explicit recovery; no automatic retry."
    }
    if (-not $PSCmdlet.ShouldProcess("$($deployment.subscriptionId)/$($deployment.resourceGroup)",
        'Commission independent cmpadmin credentials, exact private secret access, additive branding and backend/frontend on one image; never replace VMs')) { return }
    $state=$candidate
    $store=Initialize-AdminStore $state $paths
    function Checkpoint([string]$Stage) { $state.stage=$Stage;Save-AdminState $state $paths.state }
    if ($state.stage -cin @('deployed','verified')) {
        if (-not $RebuildApplication) { return Test-AdminDeployment $deployment $state $userFeature ([bool]$EnableUserAdmin) }
        Checkpoint 'branded'
    }
    if ($state.stage -ceq 'prepared') {
        $metadata=Get-AdminSecretMetadata $deployment
        $missing=@(Get-AdminSecretNames | Where-Object { -not $metadata.ContainsKey($_) })
        if ($missing.Count -ne 2) { throw 'Initial admin secrets must both be missing; unknown existing secrets are never reset.' }
        Checkpoint 'seeding'
        $null=Invoke-CmpDeployment $deployment.resourceGroup 'cmpsso-admin-seed' $templates['sso-seed-secrets'] @{
            vaultName=$deployment.foundation.vaultName;missingNames=$missing}
        Checkpoint 'seeded'
    }
    if ($state.stage -ceq 'seeded') {
        Checkpoint 'granting'
        $null=Invoke-CmpDeployment $deployment.resourceGroup 'cmpsso-admin-write' $templates['sso-secret-access'] @{
            vaultName=$deployment.foundation.vaultName;principalId=$deployment.foundation.postgresPrincipalId;access='write';secretNames=(Get-AdminSecretNames)}
        Checkpoint 'granted'
    }
    if ($state.stage -ceq 'granted') {
        $state.commandName='sso-admin-initialize-'+[guid]::NewGuid().ToString('N')
        Checkpoint 'writing'
        $proof=Invoke-AdminGuest $deployment $state 'initialize' (Get-AdminProtectedPayload $state $store 'initialize')
        $state.secretUris=$proof.secretUris
        Checkpoint 'secrets-ready'
    }
    if ($state.stage -ceq 'secrets-ready') {
        $state.commandName='sso-admin-brand-'+[guid]::NewGuid().ToString('N')
        Checkpoint 'branding'
        $null=Invoke-AdminGuest $deployment $state 'brand' (Get-AdminProtectedPayload $state $null 'brand')
        $state.brandingVerified=$true
        Checkpoint 'branded'
    }
    if ($state.stage -ceq 'branded') {
        $snapshot=New-CmpImageSource $root
        if ($RebuildApplication) {
            Checkpoint 'building'
            $built=Build-CmpInRegionImages -State $deployment -Root $root -Confirm:$false
            if ($built.sourceHash -cne $snapshot.sourceHash) { throw 'Built source changed during commissioning; no deployment.' }
            $state.applicationImage=$built.applicationImage;$state.sourceHash=$built.sourceHash
        } elseif ($state.sourceHash -cne $snapshot.sourceHash) {
            throw 'Current runtime differs from bound image source. Invoke Apply -RebuildApplication after runtime is ready.'
        }
        Checkpoint 'image-ready'
    }
    $snapshot=New-CmpImageSource $root
    if ($snapshot.sourceHash -cne $state.sourceHash) { throw 'Application source changed since the bound build; no deployment.' }
    $parameters=Get-AdminAppParameters $deployment $state
    if ($state.stage -ceq 'image-ready') {
        Checkpoint 'deploying-backend'
        $null=Invoke-CmpDeployment $deployment.resourceGroup 'cmpsso-admin' $templates['sso-admin'] (
            $parameters+@{vaultName=$deployment.foundation.vaultName;ownershipId=$state.ownershipId;backendPrincipalId=$deployment.foundation.backendPrincipalId;userAdminEnabled=[bool]$EnableUserAdmin})
        Checkpoint 'backend-ready'
    }
    if ($state.stage -ceq 'backend-ready') {
        Wait-CmpHttp "$($state.backendOrigin)/health"
        Checkpoint 'deploying-frontend'
        $null=Invoke-CmpDeployment $deployment.resourceGroup 'cmpsso-admin-frontend' $templates['sso-frontend'] (
            $parameters+@{projectsJson=$state.projectsJson;adminOrigin=$state.backendOrigin;cloudRegistryMode='enabled'})
        Checkpoint 'deployed'
    }
    $proof=Test-AdminDeployment $deployment $state $userFeature ([bool]$EnableUserAdmin)
    Checkpoint 'verified'
    return $proof
}

if ($MyInvocation.InvocationName -ne '.') {
    $common=@{}
    foreach($name in @('WhatIf','Confirm')) {
        if ($PSBoundParameters.ContainsKey($name)) { $common[$name]=$PSBoundParameters[$name] }
    }
    Invoke-AdminMain @common
}
