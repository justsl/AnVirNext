param(
    [Parameter(Mandatory)]
    [ValidatePattern('^v[0-9]+\.[0-9]+\.[0-9]+$')]
    [string]$Tag
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path -Parent $PSScriptRoot
$version = $Tag.Substring(1)
$manifest = Select-String -LiteralPath (Join-Path $root 'Cargo.toml') -Pattern '^version = "([^"]+)"$' | Select-Object -First 1
if (!$manifest -or $Tag -cne ('v' + $manifest.Matches[0].Groups[1].Value)) {
    throw "Tag $Tag does not match Cargo.toml."
}
$commit = git -C $root rev-parse --verify "refs/tags/$Tag^{commit}"
if ($LASTEXITCODE -ne 0 -or $commit -ne (git -C $root rev-parse HEAD)) {
    throw "The checkout must be at tag $Tag."
}

$dist = Join-Path $root 'dist'
$distribution = Get-Item -LiteralPath (Join-Path $dist 'AnVir-Next')
$entries = @($distribution) + @(Get-ChildItem -LiteralPath $distribution.FullName -Force -Recurse)
if ($entries | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }) {
    throw 'The release folder contains a filesystem link.'
}
$exe = Get-Item -LiteralPath (Join-Path $distribution.FullName 'AnVir-Next.exe')
if ($exe.VersionInfo.ProductVersion -cne $version) {
    throw "The executable version does not match $Tag."
}
foreach ($required in @('LICENSE', 'README.md', 'hardware-monitor\AnVirNext.SensorBridge.exe', 'hardware-monitor\AnVirNext.SensorBridge.exe.config', 'hardware-monitor\LibreHardwareMonitorLib.dll', 'hardware-monitor\LICENSE', 'hardware-monitor\THIRD-PARTY-NOTICES.txt')) {
    if (!(Test-Path -LiteralPath (Join-Path $distribution.FullName $required) -PathType Leaf)) {
        throw "Missing release file $required."
    }
}

$mergedTags = git -C $root for-each-ref --merged=HEAD --sort=-version:refname '--format=%(refname:short)' refs/tags
if ($LASTEXITCODE -ne 0) { throw 'Could not list release tags.' }
$previous = $mergedTags | Where-Object {
    $candidate = $null
    $_ -cmatch '^v[0-9]+\.[0-9]+\.[0-9]+$' -and
        [version]::TryParse($_.Substring(1), [ref]$candidate) -and $candidate -lt [version]$version
} | Select-Object -First 1
$range = if ($previous) { "refs/tags/$previous..$commit" } else { $commit }
$changes = git -C $root log --no-merges '--format=- %s (%h)' $range --
if ($LASTEXITCODE -ne 0) { throw 'Could not generate the changelog.' }

$notesPath = Join-Path $dist "AnVir-Next-$Tag-notes.md"
$notes = @(
    'Переносимая сборка для Windows 11 x64. Распакуйте ZIP и запустите **AnVir-Next.exe** из папки **AnVir-Next**.'
    ''
    $(if ($previous) { "## Изменения с $previous" } else { '## Изменения' })
    ''
) + @($changes)
if ($previous -and $env:GITHUB_SERVER_URL -and $env:GITHUB_REPOSITORY) {
    $notes += @('', "[Список коммитов]($env:GITHUB_SERVER_URL/$env:GITHUB_REPOSITORY/compare/$previous...$Tag)")
}
$notes | Set-Content -LiteralPath $notesPath -Encoding UTF8

Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = Join-Path $dist "AnVir-Next-$Tag-windows-x64.zip"
$temporary = $archive + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
try {
    [IO.Compression.ZipFile]::CreateFromDirectory($distribution.FullName, $temporary, [IO.Compression.CompressionLevel]::Optimal, $true)
    Move-Item -LiteralPath $temporary -Destination $archive -Force
} finally {
    if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary }
}
[pscustomobject]@{ Archive = $archive; Notes = $notesPath }
