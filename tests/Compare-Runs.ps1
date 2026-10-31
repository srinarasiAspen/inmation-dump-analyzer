<#
.SYNOPSIS
Compares two collector runs (summary.json) dump by dump - a regression check for changes to the collector.

.DESCRIPTION
Dumps are matched by file name. For each dump the key facts are compared:
file version, exception, signature family, blocked state, assertion expression, build commit, Lua frame count, script
context count and errors. Differences are printed; exit code 1 if any.

Typical use: run the collector over a local corpus of dumps before and after a change, then compare:

  powershell -File skills\crash-dump-analysis\scripts\Invoke-CrashDumpAnalysis.ps1 -DumpPath D:\corpus -Recurse -SkipFetch -RepoPath C:\git\inmation-services -OutDir D:\runs\new
  powershell -File tests\Compare-Runs.ps1 -Baseline D:\runs\old\summary.json -Candidate D:\runs\new\summary.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Baseline,
    [Parameter(Mandatory = $true)][string]$Candidate,
    [string[]]$Ignore = @()
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Get-Value($Object, [string]$Path) {
    $v = $Object
    foreach ($part in $Path.Split('.')) {
        if ($null -eq $v -or -not $v.PSObject.Properties[$part]) { return $null }
        $v = $v.PSObject.Properties[$part].Value
    }
    return $v
}

function Get-Facts($Dump) {
    $family = Get-Value $Dump 'signatureFamily'
    if (-not $family) {
        # Older runs have no family: derive it by removing code offsets.
        $family = ([string](Get-Value $Dump 'signature')) -replace '\+0x[0-9a-f]+', ''
    }
    return [ordered]@{
        version    = Get-Value $Dump 'module.fileVersion'
        exception  = Get-Value $Dump 'exception.code'
        family     = $family
        blocked    = [bool](Get-Value $Dump 'blocked')
        assertion  = Get-Value $Dump 'assertion.expression'
        buildCommit = Get-Value $Dump 'build.commit'
        luaFrames  = @(Get-Value $Dump 'luaStack').Count
        scripts    = @(Get-Value $Dump 'scriptContext').Count
        errors     = @(Get-Value $Dump 'errors').Count
    }
}

$old = Get-Content -LiteralPath $Baseline -Raw -Encoding UTF8 | ConvertFrom-Json
$new = Get-Content -LiteralPath $Candidate -Raw -Encoding UTF8 | ConvertFrom-Json
$oldByName = @{}; $newByName = @{}
foreach ($d in @($old.dumps)) { $oldByName[[IO.Path]::GetFileName([string](Get-Value $d 'dump.path'))] = $d }
foreach ($d in @($new.dumps)) { $newByName[[IO.Path]::GetFileName([string](Get-Value $d 'dump.path'))] = $d }

$differences = 0
foreach ($name in @($oldByName.Keys + $newByName.Keys | Sort-Object -Unique)) {
    if (-not $oldByName.ContainsKey($name)) { Write-Host "+ $name only in candidate"; $differences++; continue }
    if (-not $newByName.ContainsKey($name)) { Write-Host "- $name only in baseline"; $differences++; continue }
    $a = Get-Facts $oldByName[$name]; $b = Get-Facts $newByName[$name]
    foreach ($k in $a.Keys) {
        if ($Ignore -contains $k) { continue }
        if ("$($a[$k])" -ne "$($b[$k])") {
            Write-Host "~ $name $k`: '$($a[$k])' -> '$($b[$k])'"
            $differences++
        }
    }
}
Write-Host "$differences difference(s) between $(@($old.dumps).Count) baseline and $(@($new.dumps).Count) candidate dumps."
if ($differences -gt 0) { exit 1 }
