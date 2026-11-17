$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$testDirectory = Join-Path $projectRoot 'work\tests'
New-Item -ItemType Directory -Path $testDirectory -Force | Out-Null
$testPath = Join-Path $testDirectory 'SensorProtocol.Tests.exe'
$compilerPath = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
& $compilerPath /nologo /warnaserror /target:exe (('/out:' + $testPath)) /r:System.Web.Extensions.dll (Join-Path $projectRoot 'sensor-bridge\Protocol.cs') (Join-Path $projectRoot 'sensor-bridge\Protocol.Tests.cs')
if ($LASTEXITCODE -ne 0) { throw 'Protocol test compilation failed.' }
& $testPath
if ($LASTEXITCODE -ne 0) { throw 'Protocol tests failed.' }
