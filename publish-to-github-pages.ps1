#requires -Version 7.0
<#
.SYNOPSIS
Publishes this folder as a GitHub Pages site (branch main, root).
.DESCRIPTION
Requires git signed in to GitHub (Git Credential Manager opens a browser sign-in on first push).
The GitHub CLI (gh) is optional: when present, the script also creates the repository if it is
missing and switches Pages on. Works whether the repository is empty or already has commits.
The script publishes from a temporary copy, so no .git folder is created inside this
(OneDrive-synced) folder.
Review the content first: the repository and the Pages site are PUBLIC.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string]$Owner = 'ibranibeny',
    [string]$Repository = 'contoso-cmp-keycloak-entra-saml-l400',
    [ValidateSet('public', 'private')][string]$Visibility = 'public',
    [string]$WorkingCopy = (Join-Path ([IO.Path]::GetTempPath()) 'contoso-cmp-site')
)
$ErrorActionPreference = 'Stop'
if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw 'Missing git.' }
$full = "$Owner/$Repository"
if (-not $PSCmdlet.ShouldProcess($full, "Publish this folder as a $Visibility GitHub Pages site")) { return }

if (Test-Path $WorkingCopy) { Remove-Item $WorkingCopy -Recurse -Force }
Copy-Item -Path $PSScriptRoot -Destination $WorkingCopy -Recurse -Force
Set-Location $WorkingCopy

$hasGh = [bool](Get-Command gh -ErrorAction SilentlyContinue)
if ($hasGh) {
    gh repo view $full *> $null
    if ($LASTEXITCODE -ne 0) { gh repo create $full --$Visibility --description 'Contoso CMP identity: Keycloak x Microsoft Entra ID SAML federation (L400)' }
}
git init -b main | Out-Null
git remote add origin "https://github.com/$full.git"
git fetch origin main 2>$null
if ($LASTEXITCODE -eq 0) { git reset --soft FETCH_HEAD | Out-Null }   # build on any existing commit
git add -A
git commit -m 'Publish Contoso CMP Keycloak x Entra ID L400 guide' | Out-Null
git push -u origin main
if ($LASTEXITCODE -ne 0) { throw 'git push failed - see the message above.' }
if ($hasGh) {
    gh api -X POST "repos/$full/pages" -f 'source[branch]=main' -f 'source[path]=/' *> $null
    if ($LASTEXITCODE -ne 0) { gh api -X PUT "repos/$full/pages" -f 'source[branch]=main' -f 'source[path]=/' *> $null }
}
Write-Output "Pages URL (live about a minute after the push): https://$Owner.github.io/$Repository/"
