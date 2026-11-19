param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',
    [switch]$SensorsOnly,
    [switch]$SkipFetch,
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$projectRoot = Split-Path -Parent $PSScriptRoot
$vendorDirectory = Join-Path $projectRoot 'vendor\LibreHardwareMonitor\v0.9.6'
if (-not $SkipFetch) { $vendorDirectory = & (Join-Path $PSScriptRoot 'fetch-hardware-monitor.ps1') }
if (-not (Test-Path -LiteralPath (Join-Path $vendorDirectory 'LibreHardwareMonitorLib.dll'))) { throw 'Run scripts/fetch-hardware-monitor.ps1 first.' }
$frameworkDirectory = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319'
$compilerPath = Join-Path $frameworkDirectory 'csc.exe'
if (-not (Test-Path -LiteralPath $compilerPath)) { throw '.NET Framework 4.7.2 or later is required.' }
$bridgePath = Join-Path $vendorDirectory 'AnVirNext.SensorBridge.exe'
& $compilerPath /nologo /warnaserror /optimize+ /platform:x64 /target:exe (('/out:' + $bridgePath)) /r:System.Web.Extensions.dll (('/r:' + (Join-Path $vendorDirectory 'LibreHardwareMonitorLib.dll'))) (Join-Path $projectRoot 'sensor-bridge\Protocol.cs') (Join-Path $projectRoot 'sensor-bridge\Program.cs')
if ($LASTEXITCODE -ne 0) { throw 'Sensor companion compilation failed.' }
Copy-Item -LiteralPath (Join-Path $vendorDirectory 'LibreHardwareMonitor.exe.config') -Destination ($bridgePath + '.config') -Force
Write-Host ('Built ' + $bridgePath)
if ($SensorsOnly) { return }

$cargoCommand = Get-Command cargo -ErrorAction SilentlyContinue
$cargoPath = if ($cargoCommand) { $cargoCommand.Source } else { Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe' }
if (-not (Test-Path -LiteralPath $cargoPath)) { throw 'Rust is not installed. Install the stable x64 MSVC toolchain and Visual C++ Build Tools, then rerun this script.' }
Push-Location $projectRoot
try {
    $cargoArguments = @('build')
    if ($Configuration -eq 'Release') { $cargoArguments += '--release' }
    & $cargoPath @cargoArguments
    if ($LASTEXITCODE -ne 0) { throw 'Rust build failed.' }
    $targetDirectory = Join-Path $projectRoot ('target\' + $Configuration.ToLowerInvariant())
    $distributionDirectory = if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
        Join-Path $projectRoot 'dist\AnVir-Next'
    } elseif ([System.IO.Path]::IsPathRooted($OutputDirectory)) {
        [System.IO.Path]::GetFullPath($OutputDirectory)
    } else {
        [System.IO.Path]::GetFullPath((Join-Path $projectRoot $OutputDirectory))
    }
    New-Item -ItemType Directory -Path $distributionDirectory -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $targetDirectory 'anvir-next.exe') -Destination (Join-Path $distributionDirectory 'AnVir-Next.exe') -Force
    $sensorDestination = Join-Path $distributionDirectory 'hardware-monitor'
    New-Item -ItemType Directory -Path $sensorDestination -Force | Out-Null
    foreach ($file in Get-ChildItem -LiteralPath $vendorDirectory -File) {
        if ($file.Extension -in @('.dll', '.config') -or $file.Name -in @('AnVirNext.SensorBridge.exe', 'LICENSE', 'THIRD-PARTY-NOTICES.txt', 'source.json')) {
            Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $sensorDestination $file.Name) -Force
        }
    }
    Copy-Item -LiteralPath (Join-Path $projectRoot 'README.md') -Destination (Join-Path $distributionDirectory 'README.md') -Force
    Copy-Item -LiteralPath (Join-Path $projectRoot 'LICENSE') -Destination (Join-Path $distributionDirectory 'LICENSE') -Force
    Write-Host ('Portable application: ' + (Join-Path $distributionDirectory 'AnVir-Next.exe'))
} finally { Pop-Location }
