#requires -Version 7.0
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'deployment-common.ps1')

function New-CmpSamlFederationSetup {
    param(
        [Parameter(Mandatory)][string]$XmlText,
        [Parameter(Mandatory)][string]$KeycloakOrigin,
        [Parameter(Mandatory)][guid]$TenantId,
        [string]$Realm = 'cmp-pdf',
        [string]$DisplayName = 'CMP Keycloak PDF SSO'
    )
    Assert-ExactOrigin $KeycloakOrigin
    if ($TenantId -eq [guid]::Empty -or $Realm -cnotmatch '^[a-zA-Z0-9_-]{1,80}$' -or $Realm -ceq 'master') {
        throw 'A nonempty resource tenant ID and a non-administrative realm are required.'
    }
    if ($DisplayName.Length -lt 3 -or $DisplayName.Length -gt 120 -or $DisplayName -match '[\x00-\x1f\x7f]') {
        throw 'DisplayName must contain 3-120 printable characters.'
    }
    if ([Text.Encoding]::UTF8.GetByteCount($XmlText) -gt 1048576) { throw 'SAML metadata exceeds the 1 MiB limit.' }
    $settings = [Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $settings.MaxCharactersInDocument = 1048576
    $stringReader = [IO.StringReader]::new($XmlText)
    $reader = [Xml.XmlReader]::Create($stringReader, $settings)
    $document = [Xml.XmlDocument]::new()
    $document.XmlResolver = $null
    try { $document.Load($reader) }
    finally { $reader.Dispose(); $stringReader.Dispose() }
    $namespaces = [Xml.XmlNamespaceManager]::new($document.NameTable)
    $namespaces.AddNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata')
    $namespaces.AddNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#')
    $entity = $document.SelectSingleNode('/md:EntityDescriptor', $namespaces)
    $issuer = "$KeycloakOrigin/realms/$Realm"
    if (-not $entity -or $entity.GetAttribute('entityID') -cne $issuer) {
        throw 'SAML metadata issuer does not match the exact configured Keycloak realm.'
    }
    $idps = $entity.SelectNodes('md:IDPSSODescriptor', $namespaces)
    if ($idps.Count -ne 1 -or 'urn:oasis:names:tc:SAML:2.0:protocol' -notin
        $idps[0].GetAttribute('protocolSupportEnumeration').Split(' ', [StringSplitOptions]::RemoveEmptyEntries)) {
        throw 'Exactly one SAML 2.0 identity-provider descriptor is required.'
    }
    $endpoints = $idps[0].SelectNodes('md:SingleSignOnService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]', $namespaces)
    if ($endpoints.Count -ne 1 -or $endpoints[0].GetAttribute('Location') -cne "$issuer/protocol/saml") {
        throw 'The SAML redirect endpoint must be the exact configured Keycloak realm endpoint.'
    }
    $certificates = $idps[0].SelectNodes('md:KeyDescriptor[@use="signing" or not(@use)]/ds:KeyInfo/ds:X509Data/ds:X509Certificate', $namespaces)
    if ($certificates.Count -ne 1) { throw 'Exactly one current public SAML signing certificate is required; review rollover metadata explicitly.' }
    $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new(
        [Convert]::FromBase64String(($certificates[0].InnerText -replace '\s', '')))
    $rsa = $null
    try {
        $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($certificate)
        if (-not $rsa -or $rsa.KeySize -lt 2048 -or
            $certificate.NotBefore.ToUniversalTime() -gt [DateTime]::UtcNow -or
            $certificate.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow.AddDays(7)) {
            throw 'The SAML signing certificate must have an RSA key of at least 2048 bits and more than seven days of validity.'
        }
        return [pscustomobject][ordered]@{
            schemaVersion = 'cmp-domainless-saml-setup-v1'
            mode = 'PreviewOnlyNoCloudWrites'
            tenantId = $TenantId.ToString()
            displayName = $DisplayName
            preferredAuthenticationProtocol = 'saml'
            domainless = $true
            issuerUri = $issuer
            passiveSignInUri = "$issuer/protocol/saml"
            metadataExchangeUri = "$issuer/protocol/saml/descriptor"
            signingCertificate = [Convert]::ToBase64String($certificate.RawData)
            certificateThumbprint = $certificate.Thumbprint
            certificateExpiresUtc = $certificate.NotAfter.ToUniversalTime().ToString('o')
            audience = "https://login.microsoftonline.com/$TenantId/"
            assertionConsumerService = 'https://login.microsoftonline.com/login.srf'
            nameIdFormat = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'
            requiredClaims = @('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress')
            requiredDirectoryRole = 'External Identity Provider Administrator'
            requiredDelegatedPermission = 'IdentityProvider.ReadWrite.All'
            adminCenterUrl = 'https://entra.microsoft.com/'
            adminCenterNavigation = 'Entra ID > External Identities > All identity providers > New SAML/WS-Fed IdP > Domainless'
            administrationSteps = @(
                'An authorized administrator must first inspect the tenant for an existing domainless/wildcard identity provider. Only one is supported. Do not replace it.'
                'Create a new external SAML identity provider using these public metadata fields and select Domainless. Do not convert any native Entra domain authentication.'
                'Provision only approved B2B test guests. During redemption, use a domain_hint equal to issuerUri as documented by Microsoft.'
                'Preserve existing guest redemption methods and cross-tenant policies unless a separate change is approved.'
                'Demonstrate real CMP login and subsequent Azure Portal access. Record consent and MFA prompts; metadata configuration alone is not SSO evidence.'
            )
            documentation = 'https://learn.microsoft.com/entra/external-id/direct-federation#domainless-saml-idp-federation'
            graphApiBoundary = 'The documented v1.0 resource does not specify a domainless request property. This tool does not invent a wildcard Graph payload or perform tenant writes.'
            ssoVerified = $false
        }
    } finally {
        if ($rsa) { $rsa.Dispose() }
        $certificate.Dispose()
    }
}

function Confirm-CmpSamlFederationRecord {
    param([Parameter(Mandatory)]$Setup, [object[]]$Records = @())
    $matches = @($Records | Where-Object { $_.issuerUri -ceq $Setup.issuerUri })
    if ($matches.Count -ne 1) { throw 'The expected issuer must match exactly one existing external federation. No creation or overwrite was attempted.' }
    $record = $matches[0]
    if ($record.preferredAuthenticationProtocol -cne 'saml' -or
        $record.passiveSignInUri -cne $Setup.passiveSignInUri -or
        [Convert]::ToBase64String([Convert]::FromBase64String($record.signingCertificate)) -cne $Setup.signingCertificate) {
        throw 'Existing federation protocol, endpoint or certificate differs from the reviewed public metadata. No update was attempted.'
    }
    return [pscustomobject]@{
        federationId = $record.id
        issuerUri = $record.issuerUri
        configurationMatched = $true
        domainlessStatus = 'RequiresAdminCenterConfirmation'
        ssoVerified = $false
        nextEvidence = 'Confirm Domainless in the authorized admin center, then demonstrate sign-in with approved general-email and agency-Entra users.'
    }
}
