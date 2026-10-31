<#
.SYNOPSIS
Checks a crash report for unfinished parts before it is handed over: placeholders left by the scripts, unconfirmed
pre-verdicts, missing sections and an invalid verdict.

.DESCRIPTION
Prints one REPORT_ISSUE=<text> line per problem and REPORT_OK when nothing is left to do. Exit code 1 if issues remain.
-Stage tells which stages are expected to be complete (default: the stages listed in the 'Stages done' row).

.EXAMPLE
.\Test-CrashReport.ps1 -ReportPath C:\dumps\inmation.exe.1234.dmp.crash-report.md
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ReportPath,
    [int[]]$Stage
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\Common.ps1')
. (Join-Path $PSScriptRoot 'lib\Frames.ps1')
. (Join-Path $PSScriptRoot 'lib\Report.ps1')

$text = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $ReportPath).Path)
$issues = New-Object Collections.Generic.List[string]

foreach ($n in 1..5) { if (-not $text.Contains("## $($script:ReportSections[$n])")) { $issues.Add("Section '## $($script:ReportSections[$n])' is missing.") } }
if ($text -notmatch '(?m)^# Crash analysis: \S') { $issues.Add('Title line "# Crash analysis: <short title>" is missing.') }

$stagesDone = [string](Get-ReportHeaderValue $ReportPath 'Stages done')
if (-not $Stage) { $Stage = @([regex]::Matches($stagesDone, '\b([123])\b') | ForEach-Object { [int]$_.Groups[1].Value } | Select-Object -Unique) }

function Get-SectionBody([int]$Number) {
    $heading = "## $($script:ReportSections[$Number])"
    $start = $text.IndexOf($heading)
    if ($start -lt 0) { return '' }
    $next = $text.IndexOf("`n## ", $start + $heading.Length)
    if ($next -lt 0) { $next = $text.Length }
    return $text.Substring($start + $heading.Length, $next - $start - $heading.Length)
}

if ($Stage -contains 2) {
    $body = Get-SectionBody 2
    if ($body -match '_Not done yet - stage 2\._') { $issues.Add('Section 2 still says "Not done yet" although stage 2 is listed as done.') }
    $header = [string](Get-ReportHeaderValue $ReportPath 'Existing work item')
    if ($header -match 'to confirm') { $issues.Add("Header 'Existing work item' still has an unconfirmed pre-verdict ('to confirm'): read the work item file and replace it with same / likely same / related / different.") }
    if ($body -match '\*\*Result:\*\*[^\r\n]*to confirm') { $issues.Add("A 'Result' line in section 2 still says 'to confirm': confirm or correct the verdict after reading the work item.") }
}
if ($Stage -contains 3) {
    foreach ($n in 3..5) {
        $body = Get-SectionBody $n
        if ($body -match '_Not done yet - stage 3\._') { $issues.Add("Section $n still says 'Not done yet' although stage 3 is listed as done.") }
        foreach ($m in [regex]::Matches($body, '_analyst:[^_\r\n]*_')) { $issues.Add("Section ${n}: placeholder left: $($m.Value)") }
    }
    $verdict = [string](Get-ReportHeaderValue $ReportPath 'Verdict')
    if ($verdict -match '^\s*not analyzed') { $issues.Add("Header 'Verdict' is still 'not analyzed'. Use: Fixed in <sha> / Fixed - related risk remains / Still present / Inconclusive (release), or Root cause identified / Hypothesis (<confidence>) (dev).") }
    elseif ($verdict -notmatch 'Fixed|Still present|Inconclusive|Root cause identified|Hypothesis|pending PDB') { $issues.Add("Header 'Verdict' ('$verdict') uses none of the allowed verdicts.") }
    if ([string](Get-ReportHeaderValue $ReportPath 'Compared against') -match '^\s*not yet') { $issues.Add("Header 'Compared against' still says 'not yet'.") }
    if ([string](Get-ReportHeaderValue $ReportPath 'Build commit') -match 'not verified before stage 3') { $issues.Add("Header 'Build commit' still says 'not verified before stage 3': check the estimated commit (stage3-decide.md step 1) and answer '## Build commit'.") }
}
if ($text -match '_analyst:' -and -not ($Stage -contains 3)) { $issues.Add("Placeholders '_analyst: ..._' exist but stage 3 is not listed in 'Stages done'.") }

foreach ($i in $issues) { Write-Host "REPORT_ISSUE=$i" }
if ($issues.Count -eq 0) { Write-Host 'REPORT_OK'; exit 0 }
exit 1
