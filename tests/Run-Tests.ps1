<#
.SYNOPSIS
Runs the unit tests (tests\*.Tests.ps1). No dump, debugger, share or network access is needed.

.EXAMPLE
powershell -NoProfile -ExecutionPolicy Bypass -File tests\Run-Tests.ps1
#>
[CmdletBinding()]
param([string]$Filter = '*')

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestFramework.ps1')
$script:LibRoot = Join-Path (Split-Path $PSScriptRoot -Parent) 'skills\crash-dump-analysis\scripts\lib'
$script:ScriptRoot = Split-Path $script:LibRoot -Parent
$script:PerfLibRoot = Join-Path (Split-Path $PSScriptRoot -Parent) 'skills\perf-counter-analysis\scripts\lib'

foreach ($file in @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter "$Filter.Tests.ps1" | Sort-Object Name)) {
    try { . $file.FullName }
    catch { $script:TestResults.Add([pscustomobject]@{ Name = "$($file.Name) (load)"; Passed = $false; Message = $_.Exception.Message }) }
}

$failed = @($script:TestResults | Where-Object { -not $_.Passed })
foreach ($r in $script:TestResults) {
    if ($r.Passed) { Write-Host "  [pass] $($r.Name)" -ForegroundColor DarkGreen }
    else { Write-Host "  [FAIL] $($r.Name): $($r.Message)" -ForegroundColor Red }
}
Write-Host ''
Write-Host "$($script:TestResults.Count - $failed.Count) passed, $($failed.Count) failed"
if ($failed.Count -gt 0) { exit 1 }
