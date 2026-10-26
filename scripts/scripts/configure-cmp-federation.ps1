#requires -Version 7.0
<#
.SYNOPSIS
Exports reviewed public Keycloak SAML metadata for Entra domainless B2B federation.
.DESCRIPTION
Preview is the default and performs no Azure calls when MetadataFile is supplied.
Verify performs read-only Graph requests. Domainless creation uses the documented
Entra admin-center workflow; no undocumented wildcard Graph payload is generated.
This script never converts a native domain, changes MFA policies, resets guests,
sends invitations, assigns roles, or claims an end-to-end SSO demonstration.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][guid]$SubscriptionId,
    [Parameter(Mandatory)][guid]$TenantId,
    [Parameter(Mandatory)][string]$KeycloakOrigin,
    [string]$Realm = 'cmp-pdf',
    [string]$DisplayName = 'CMP Keycloak PDF SSO',
    [string]$ExpectedAccount = 'admin@contoso.com',
    [string]$MetadataFile,
    [string]$OutputPath,
    [switch]$Verify
)
. (Join-Path $PSScriptRoot 'sso-federation-common.ps1')
if ($SubscriptionId -eq [guid]::Empty) { throw 'SubscriptionId must be nonempty.' }
Assert-ExactOrigin $KeycloakOrigin
if ($Realm -cnotmatch '^[a-zA-Z0-9_-]{1,80}$' -or $Realm -ceq 'master') { throw 'A non-administrative Keycloak realm is required.' }
if ($MetadataFile) {
    $file = Get-Item -LiteralPath $MetadataFile
    if ($file.PSIsContainer -or $file.Length -gt 1048576) { throw 'MetadataFile must be a public XML file no larger than 1 MiB.' }
    $xml = [IO.File]::ReadAllText($file.FullName)
} else {
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(15)
    $client.MaxResponseContentBufferSize = 1048576
    $response = $null
    try {
        $response = $client.GetAsync("$KeycloakOrigin/realms/$Realm/protocol/saml/descriptor").GetAwaiter().GetResult()
        if ([int]$response.StatusCode -ne 200) { throw "Public SAML metadata returned HTTP $([int]$response.StatusCode); redirects are refused." }
        $xml = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
    } finally {
        if ($response) { $response.Dispose() }
        $client.Dispose()
    }
}
$setup = New-CmpSamlFederationSetup -XmlText $xml -KeycloakOrigin $KeycloakOrigin `
    -TenantId $TenantId -Realm $Realm -DisplayName $DisplayName
$result = $setup
if ($Verify) {
    Initialize-CmpContext $SubscriptionId.ToString() $TenantId.ToString() $ExpectedAccount
    $uri = 'https://graph.microsoft.com/v1.0/directory/federationConfigurations/microsoft.graph.samlOrWsFedExternalDomainFederation'
    $records = [Collections.Generic.List[object]]::new()
    for ($page = 0; $page -lt 20; $page++) {
        $response = Invoke-CmpRest -Uri $uri -Resource 'https://graph.microsoft.com/'
        foreach ($record in $response.value) { $records.Add($record) }
        $next = $response.PSObject.Properties['@odata.nextLink']
        if (-not $next -or -not $next.Value) { break }
        $nextUri = [uri]$next.Value
        if ($nextUri.Scheme -cne 'https' -or $nextUri.Host -cne 'graph.microsoft.com' -or
            $nextUri.UserInfo -or $nextUri.AbsolutePath -cne '/v1.0/directory/federationConfigurations/microsoft.graph.samlOrWsFedExternalDomainFederation') {
            throw 'Untrusted federation pagination URL refused.'
        }
        if ($page -eq 19) { throw 'Federation pagination exceeded the safety limit.' }
        $uri = $nextUri.AbsoluteUri
    }
    $result = Confirm-CmpSamlFederationRecord -Setup $setup -Records $records.ToArray()
}
$json = $result | ConvertTo-Json -Depth 8
if ($OutputPath) {
    $destination = [IO.Path]::GetFullPath($OutputPath)
    if (Test-Path -LiteralPath $destination) { throw 'OutputPath already exists; preserve the previous reviewed configuration and choose a new path.' }
    $null = [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination))
    [IO.File]::WriteAllText($destination, $json, [Text.UTF8Encoding]::new($false))
}
Write-Output $json
