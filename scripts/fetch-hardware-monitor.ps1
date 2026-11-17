param(
    [ValidatePattern('^(latest|v[0-9]+\.[0-9]+\.[0-9]+)$')]
    [string]$Version = 'v0.9.6'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$projectRoot = Split-Path -Parent $PSScriptRoot
$releasePath = if ($Version -eq 'latest') { 'latest' } else { 'tags/' + $Version }
$release = Invoke-RestMethod -Uri ('https://api.github.com/repos/LibreHardwareMonitor/LibreHardwareMonitor/releases/' + $releasePath) -Headers @{ 'User-Agent' = 'AnVir-Next-build' } -TimeoutSec 30
if ($release.tag_name -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+$') { throw 'Unexpected upstream version.' }
$asset = @($release.assets | Where-Object { $_.name -eq 'LibreHardwareMonitor.zip' })
if ($asset.Count -ne 1 -or $asset[0].digest -notmatch '^sha256:[a-fA-F0-9]{64}$') { throw 'Missing authoritative release SHA-256.' }
if ($asset[0].size -gt 64MB) { throw 'Unexpected upstream archive size.' }
$expectedHash = $asset[0].digest.Substring(7).ToLowerInvariant()
$downloadUrl = [Uri]$asset[0].browser_download_url
if ($downloadUrl.Scheme -ne 'https' -or $downloadUrl.Host -ne 'github.com' -or -not $downloadUrl.AbsolutePath.StartsWith('/LibreHardwareMonitor/LibreHardwareMonitor/releases/download/')) { throw 'Unexpected upstream download URL.' }

$downloadDirectory = Join-Path $projectRoot 'work\downloads'
New-Item -ItemType Directory -Path $downloadDirectory -Force | Out-Null
$archivePath = Join-Path $downloadDirectory ('LibreHardwareMonitor-' + $release.tag_name + '.zip')
if (-not (Test-Path -LiteralPath $archivePath) -or (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedHash) {
    Invoke-WebRequest -Uri $downloadUrl.AbsoluteUri -OutFile $archivePath -TimeoutSec 90
}
if ((Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedHash) { throw 'LibreHardwareMonitor SHA-256 mismatch.' }

$vendorDirectory = Join-Path $projectRoot ('vendor\LibreHardwareMonitor\' + $release.tag_name)
$metadataPath = Join-Path $vendorDirectory 'source.json'
if (Test-Path -LiteralPath $vendorDirectory) {
    if (-not (Test-Path -LiteralPath $metadataPath)) { throw 'Existing vendor directory has no provenance; refusing to overwrite it.' }
    $metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
    if ($metadata.sha256 -ne $expectedHash) { throw 'Existing vendor provenance does not match the release.' }
} else {
    Expand-Archive -LiteralPath $archivePath -DestinationPath $vendorDirectory
    foreach ($noticeName in @('LICENSE', 'THIRD-PARTY-NOTICES.txt')) {
        Invoke-WebRequest -Uri ('https://raw.githubusercontent.com/LibreHardwareMonitor/LibreHardwareMonitor/' + $release.tag_name + '/' + $noticeName) -OutFile (Join-Path $vendorDirectory $noticeName) -TimeoutSec 30
    }
    @{ version = $release.tag_name; sha256 = $expectedHash; url = $downloadUrl.AbsoluteUri } | ConvertTo-Json | Set-Content -LiteralPath $metadataPath -Encoding utf8
}
Write-Host ('Verified LibreHardwareMonitor ' + $release.tag_name + ' (SHA-256 ' + $expectedHash + ')')
Write-Output $vendorDirectory
