<#
.SYNOPSIS
Completes a crash report from an answers file, so the model never edits the report itself: lists the open items
(stage 2 pre-verdicts to confirm, '_analyst: ..._' placeholders of stage 3, the Verdict header row), writes an answers
template, and applies the filled-in answers.

.DESCRIPTION
Step 1 - list:  Complete-CrashReport.ps1 -ReportPath <report>
  Prints OPEN_ITEM=<key> | <what to write> per open item and writes a new answers file (ANSWERS_FILE=<path>) with one
  '## <key>' heading and a 'TODO: ...' line per item. A new file is written every time (never overwritten).
Step 2 - answer: replace every TODO line in the answers file (several lines, lists and code blocks are allowed).
  Stage 2 items ('## 2A #12345'): start with same / likely same / related / different, then ' - ' and the reason.
  Header rows can be set with '## Verdict', '## Build commit', '## Existing work item', '## Compared against'.
Step 3 - apply:  Complete-CrashReport.ps1 -ReportPath <report> -AnswersFile <answers file>
  Prints ANSWER_APPLIED=<key> / ANSWER_ISSUE=<text>, updates 'Stages done', then runs Test-CrashReport.ps1
  (REPORT_ISSUE=... or REPORT_OK). Exit code 1 while issues remain: list again (step 1) for what is left.

.EXAMPLE
.\Complete-CrashReport.ps1 -ReportPath C:\dumps\crash-report.md
.\Complete-CrashReport.ps1 -ReportPath C:\dumps\crash-report.md -AnswersFile C:\dumps\crash-report.answers-1.md
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory = $true)][string]$ReportPath,
    [string]$AnswersFile
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\Common.ps1')
. (Join-Path $PSScriptRoot 'lib\Frames.ps1')
. (Join-Path $PSScriptRoot 'lib\Report.ps1')

$ReportPath = (Resolve-Path -LiteralPath $ReportPath).Path
$headerKeys = @('Verdict', 'Build commit', 'Existing work item', 'Compared against')
$stage2Verdicts = 'likely same|same|related|different'

function Split-TableRow([string]$Line) {
    $inner = $Line.Trim()
    if ($inner.StartsWith('|')) { $inner = $inner.Substring(1) }
    if ($inner.EndsWith('|') -and -not $inner.EndsWith('\|')) { $inner = $inner.Substring(0, $inner.Length - 1) }
    return @([regex]::Split($inner, '(?<!\\)\|') | ForEach-Object { $_.Trim() })
}

# Open items in document order. Keys: '2<letter> #<id>' (stage 2), '<section><letter> <label>' (placeholders), 'Verdict'.
function Get-OpenItems([string]$Text) {
    $items = New-Object Collections.Generic.List[object]
    $runDir = [regex]::Match($Text, '(?m)^- Run folder: (.+?) \(').Groups[1].Value
    $section = 0; $letter = ''; $fence = $false
    foreach ($line in ($Text -split "`r?`n")) {
        if ($line -match '^\s*```') { $fence = -not $fence; continue }
        if ($fence) { continue }
        if ($line -match '^## (\d)\. ') { $section = [int]$Matches[1]; $letter = ''; continue }
        if ($line -match '^## ') { $section = 0; continue }
        if ($line -match '^### Signature ([A-Z]+)\b') { $letter = $Matches[1]; continue }
        if ($section -eq 2 -and $letter -and $line -match '^\| \[#(\d+)\]') {
            $id = $Matches[1]
            $cells = Split-TableRow $line
            if ($cells.Count -ge 4 -and $cells[2] -match '^(same \(to confirm\)|likely same)$' -and $cells[3] -notmatch 'confirmed:') {
                $file = if ($runDir -and (Test-Path -LiteralPath (Join-Path $runDir "tfs-$id.md"))) { Join-Path $runDir "tfs-$id.md" } else { "tfs-$id.md" }
                $items.Add([pscustomobject]@{ Key = "2$letter #$id"; Kind = 'stage2'; Prompt = "same / likely same / related / different - one sentence why. Read $file (pre-verdict: $($cells[2]))." })
            }
            continue
        }
        if ($section -ge 3) {
            foreach ($m in [regex]::Matches($line, '\*\*(?<label>[^*]+?)\*\*\s*_analyst:\s*(?<prompt>[^_\r\n]*)_')) {
                $label = $m.Groups['label'].Value.Trim().TrimEnd(':').Trim()
                $key = "$section$letter $label"
                $n = 2; while (@($items | Where-Object { $_.Key -eq $key }).Count) { $key = "$section$letter $label ($n)"; $n++ }
                $items.Add([pscustomobject]@{ Key = $key; Kind = 'placeholder'; Prompt = $m.Groups['prompt'].Value.Trim() })
            }
        }
    }
    $verdict = [string](Get-ReportHeaderValue $ReportPath 'Verdict')
    $stagesDone = [string](Get-ReportHeaderValue $ReportPath 'Stages done')
    if ($verdict -match '^\s*not analyzed' -and ($stagesDone -match '\b3\b' -or @($items | Where-Object { $_.Kind -eq 'placeholder' }).Count)) {
        $binary = [string](Get-ReportHeaderValue $ReportPath 'Binary')
        $allowed = @()
        if ($binary -match 'release build') { $allowed += 'release: Fixed in <sha> / Fixed - related risk remains / Still present / Inconclusive' }
        if ($binary -match 'dev build') { $allowed += 'dev: Root cause identified / Hypothesis (<high|medium|low>)' }
        if (-not $allowed) { $allowed += 'Fixed in <sha> / Fixed - related risk remains / Still present / Inconclusive / Root cause identified / Hypothesis (<confidence>)' }
        $items.Add([pscustomobject]@{ Key = 'Verdict'; Kind = 'header'; Prompt = "one verdict per signature, e.g. 'A: ...; B: ...'. Allowed - $($allowed -join '; ')" })
    }
    $buildRow = [string](Get-ReportHeaderValue $ReportPath 'Build commit')
    if ($buildRow -match 'not verified before stage 3' -and ($stagesDone -match '\b3\b' -or @($items | Where-Object { $_.Kind -eq 'placeholder' }).Count)) {
        $items.Add([pscustomobject]@{ Key = 'Build commit'; Kind = 'header'; Prompt = "check the estimated build commit (stage3-decide.md step 1) and write per version '<version>: <sha10> (<confidence>, <method>; consistent with the PDB source line)' or '<version>: not trustworthy - <why>'. Now: $($buildRow -replace '<br>', ' / ')" })
    }
    return , $items.ToArray()
}

# '## key' headings and their text; headings inside code fences are text.
function Read-Answers([string]$Path) {
    $answers = [ordered]@{}
    $key = $null; $buffer = New-Object Collections.Generic.List[string]; $fence = $false
    $flush = { if ($key) { $answers[$key] = (($buffer -join "`r`n").Trim()) } }
    foreach ($line in [IO.File]::ReadAllLines((Resolve-Path -LiteralPath $Path).Path)) {
        if ($line -match '^\s*```') { $fence = -not $fence }
        if (-not $fence -and $line -match '^##\s+(.+?)\s*$') {
            & $flush
            $key = $Matches[1]; $buffer = New-Object Collections.Generic.List[string]
            continue
        }
        if ($key) { $buffer.Add($line) }
    }
    & $flush
    return $answers
}

$text = [IO.File]::ReadAllText($ReportPath)
$open = Get-OpenItems $text

if (-not $AnswersFile) {
    if ($open.Count -eq 0) {
        Write-Host 'OPEN_ITEMS=0'
        & (Join-Path $PSScriptRoot 'Test-CrashReport.ps1') -ReportPath $ReportPath
        exit $LASTEXITCODE
    }
    $dir = Split-Path $ReportPath -Parent
    $base = [IO.Path]::GetFileNameWithoutExtension($ReportPath)
    $n = 1; while (Test-Path -LiteralPath (Join-Path $dir "$base.answers-$n.md")) { $n++ }
    $answersPath = Join-Path $dir "$base.answers-$n.md"
    $sb = New-Object Text.StringBuilder
    [void]$sb.AppendLine("<!-- Answers for $([IO.Path]::GetFileName($ReportPath)). Replace every TODO line, keep the '## ' headings. Then run Complete-CrashReport.ps1 -ReportPath <report> -AnswersFile <this file>. -->")
    foreach ($item in $open) {
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine("## $($item.Key)")
        [void]$sb.AppendLine("TODO: $($item.Prompt)")
        Write-Host "OPEN_ITEM=$($item.Key) | $($item.Prompt)"
    }
    [IO.File]::WriteAllText($answersPath, $sb.ToString(), [Text.UTF8Encoding]::new($false))
    Write-Host "OPEN_ITEMS=$($open.Count)"
    Write-Host "ANSWERS_FILE=$answersPath"
    Write-Host "NEXT_STEP=Replace every TODO line in $answersPath, then run: powershell -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -ReportPath `"$ReportPath`" -AnswersFile `"$answersPath`""
    exit 0
}

$answers = Read-Answers $AnswersFile
$issues = New-Object Collections.Generic.List[string]
$placeholderAnswers = @{}
$stage2Answers = @{}
$headerAnswers = [ordered]@{}
foreach ($key in @($answers.Keys)) {
    $value = [string]$answers[$key]
    if (-not $value -or $value -match '^TODO\b') { $issues.Add("'## $key' is not answered (still TODO or empty)."); continue }
    if ($value -match '_analyst:') { $issues.Add("'## $key' still contains '_analyst:'."); continue }
    $header = $headerKeys | Where-Object { $_ -eq $key } | Select-Object -First 1
    if ($header) { $headerAnswers[$header] = $value; continue }
    if ($key -match '^2([A-Z]+) #(\d+)$') {
        if ($value -notmatch "(?is)^\s*\**($stage2Verdicts)\**\b\s*[-:,.]?\s*(.*)$") { $issues.Add("'## $key' must start with same / likely same / related / different."); continue }
        $stage2Answers[$key] = [pscustomobject]@{ Letter = ($key -replace '^2([A-Z]+) .*$', '$1'); Id = ($key -replace '^.*#', ''); Verdict = $Matches[1].ToLowerInvariant(); Reason = ($Matches[2] -replace '\s*\r?\n\s*', ' ').Trim() }
        continue
    }
    if (@($open | Where-Object { $_.Kind -eq 'placeholder' -and $_.Key -eq $key }).Count) { $placeholderAnswers[$key] = $value; continue }
    $issues.Add("'## $key' matches no open item. Open items: $(@($open | ForEach-Object { $_.Key }) -join '; ')")
}

# One pass over the report lines: placeholders and stage 2 rows/result lines, tracked by section and signature letter.
$out = New-Object Collections.Generic.List[string]
$section = 0; $letter = ''; $seen = @{}; $fence = $false
foreach ($line in ($text -split "`r?`n")) {
    if ($line -match '^\s*```') { $fence = -not $fence }
    if ($fence -or $line -match '^\s*```') { $out.Add($line); continue }
    if ($line -match '^## (\d)\. ') { $section = [int]$Matches[1]; $letter = '' }
    elseif ($line -match '^## ') { $section = 0 }
    elseif ($line -match '^### Signature ([A-Z]+)\b') { $letter = $Matches[1] }
    elseif ($section -eq 2 -and $letter) {
        if ($line -match '^\| \[#(\d+)\]' -and $stage2Answers.ContainsKey("2$letter #$($Matches[1])")) {
            $a = $stage2Answers["2$letter #$($Matches[1])"]
            $cells = Split-TableRow $line
            if ($cells.Count -ge 4) {
                $cells[2] = $a.Verdict
                $cells[3] = "$($cells[3]); confirmed: $(Format-MdCell $a.Reason)"
                $line = '| ' + ($cells -join ' | ') + ' |'
            }
        }
        elseif ($line -match '^\*\*Result:\*\*.*\[#(\d+)\]' -and $stage2Answers.ContainsKey("2$letter #$($Matches[1])")) {
            $a = $stage2Answers["2$letter #$($Matches[1])"]
            $line = [regex]::Replace($line, '\*\*(same \(to confirm\)|likely same|same)\*\*', "**$($a.Verdict)**")
            if ($a.Verdict -in 'related', 'different') { $line += " Judged $($a.Verdict) after reading the work item ($($a.Reason)): no confirmed existing work item for this signature." }
        }
    }
    elseif ($section -ge 3) {
        $line = [regex]::Replace($line, '\*\*(?<label>[^*]+?)\*\*\s*_analyst:\s*[^_\r\n]*_', {
                param($m)
                $label = $m.Groups['label'].Value.Trim().TrimEnd(':').Trim()
                $key = "$section$letter $label"
                $n = 2; while ($seen.ContainsKey($key)) { $key = "$section$letter $label ($n)"; $n++ }
                $seen[$key] = $true
                if (-not $placeholderAnswers.ContainsKey($key)) { return $m.Value }
                $value = $placeholderAnswers[$key]
                Write-Host "ANSWER_APPLIED=$key"
                if ($value -match "`n") { return "**$($m.Groups['label'].Value)**`r`n`r`n$value`r`n" }
                return "**$($m.Groups['label'].Value)** $value"
            })
    }
    $out.Add($line)
}
$text = $out -join "`r`n"

# Header rows: explicit answers, the stage 2 verdicts in 'Existing work item', and 'Stages done'.
function Set-HeaderRow([string]$Text, [string]$Row, [string]$Value) {
    return [regex]::Replace($Text, "(?m)^\| $([regex]::Escape($Row)) \|.*\|\r?$", { param($m) "| $Row | $(Format-MdCell $Value) |" })
}
foreach ($a in $stage2Answers.Values) {
    Write-Host "ANSWER_APPLIED=2$($a.Letter) #$($a.Id)"
    $text = [regex]::Replace($text, "(?m)^(\| Existing work item \|.*?\b$($a.Letter): #$($a.Id)\b[^<|]*?\()(same \(to confirm\)|likely same|same)(,)", { param($m) $m.Groups[1].Value + $a.Verdict + $m.Groups[3].Value })
}
foreach ($row in $headerAnswers.Keys) { $text = Set-HeaderRow $text $row $headerAnswers[$row]; Write-Host "ANSWER_APPLIED=$row" }
$stagesRow = [regex]::Match($text, '(?m)^\| Stages done \| (.*) \|\r?$')
if ($stagesRow.Success) {
    $stages = $stagesRow.Groups[1].Value
    if ($text -notmatch '\| same \(to confirm\) \||\*\*same \(to confirm\)\*\*|\(same \(to confirm\),') { $stages = $stages -replace ' \(pre-verdicts to confirm\)', '' }
    if ($text -notmatch '_analyst:') {
        $verdictNow = [regex]::Match($text, '(?m)^\| Verdict \| (.*) \|\r?$').Groups[1].Value
        if ($verdictNow -and $verdictNow -notmatch '^\s*not analyzed') { $stages = $stages -replace ' \(evidence generated; verdict pending\)', '' }
    }
    $text = Set-HeaderRow $text 'Stages done' $stages
}

$tmp = "$ReportPath.tmp"
[IO.File]::WriteAllText($tmp, $text, [Text.UTF8Encoding]::new($false))
Move-Item -LiteralPath $tmp -Destination $ReportPath -Force
foreach ($i in $issues) { Write-Host "ANSWER_ISSUE=$i" }
Write-Host "REPORT_PATH=$ReportPath"
& (Join-Path $PSScriptRoot 'Test-CrashReport.ps1') -ReportPath $ReportPath
$lint = $LASTEXITCODE
if ($issues.Count -gt 0 -or $lint -ne 0) {
    Write-Host "NEXT_STEP=Fix the ANSWER_ISSUE / REPORT_ISSUE lines: run Complete-CrashReport.ps1 -ReportPath `"$ReportPath`" again (without -AnswersFile) for a new answers file with the items that are still open."
    exit 1
}
exit 0
