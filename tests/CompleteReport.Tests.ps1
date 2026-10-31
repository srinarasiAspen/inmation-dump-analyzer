Describe 'Complete-CrashReport' {
    $script = Join-Path $script:ScriptRoot 'Complete-CrashReport.ps1'
    $dir = Join-Path ([IO.Path]::GetTempPath()) "cda-complete-tests-$PID"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $report = Join-Path $dir 'crash-report.md'
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'fixtures\report-open-items.md') -Destination $report -Force
    try {
        $listing = @(& $script -ReportPath $report 6>&1 | ForEach-Object { "$_" })
        $answersPath = ($listing | Where-Object { $_ -like 'ANSWERS_FILE=*' }) -replace '^ANSWERS_FILE=', ''

        It 'lists stage 2 confirmations, placeholders by section and signature, and the verdict' {
            $keys = @($listing | Where-Object { $_ -like 'OPEN_ITEM=*' } | ForEach-Object { ($_ -replace '^OPEN_ITEM=', '' -split ' \| ')[0] })
            Assert-Equal @('2A #40551', '2B #34716', '3A Still failing on the latest code?', '3B Still failing on the latest code?', '5A Mechanism', '5A Fix proposal', '5B Mechanism', '5B Fix proposal', 'Verdict', 'Build commit') $keys
            Assert-True (@($listing | Where-Object { $_ -like 'OPEN_ITEM=Verdict*dev: Root cause identified*' }).Count -eq 1) 'dev build verdicts offered'
        }
        It 'writes a template with one heading and a TODO line per item' {
            Assert-True (Test-Path -LiteralPath $answersPath)
            $t = [IO.File]::ReadAllText($answersPath)
            Assert-Equal 10 ([regex]::Matches($t, '(?m)^## ').Count)
            Assert-Equal 10 ([regex]::Matches($t, '(?m)^TODO: ').Count)
        }

        $answers = @'
## 2A #40551
Same - the dumps are attached to this bug.

## 2B #34716
different - other entry path

## 3A Still failing on the latest code?
no - fixed by 498a2dcd8a

## 5A Mechanism
Read past the end of the cached BSON buffer.

## 5A Fix proposal
Validate the length before inserting:

```diff
## not a heading inside a fence
- cache.insert(doc);
+ if (doc.isValid()) cache.insert(doc);
```

## Verdict
A: Root cause identified; B: Hypothesis (low)

## 3B Still failing on the latest code?
TODO: yes / no / unclear
'@
        $filled = Join-Path $dir 'answers.md'
        [IO.File]::WriteAllText($filled, $answers)
        $applied = @(& $script -ReportPath $report -AnswersFile $filled 6>&1 | ForEach-Object { "$_" })
        $text = [IO.File]::ReadAllText($report)

        It 'applies the stage 2 verdict to the table row, the result line and the header' {
            Assert-Match '\| same \| first frame found; confirmed: the dumps are attached to this bug\. \|' $text
            Assert-Match 'with pipe' $text
            Assert-Match '\*\*Result:\*\* \[#40551\][^\r\n]*\*\*same\*\*' $text
            Assert-Match 'A: #40551 Dumps found: crash \(same, Resolved/Fixed\)' $text
        }
        It 'turns a rejected candidate into "no confirmed existing work item"' {
            Assert-Match '\| different \| own caller found; confirmed: other entry path \|' $text
            Assert-Match '\*\*different\*\*[^\r\n]*no confirmed existing work item' $text
            Assert-Match 'B: #34716 burn-in crash \(different, Active/New\)' $text
        }
        It 'fills single-line and multi-line placeholders of the right signature' {
            Assert-Match '(?m)^\*\*Still failing on the latest code\?\*\* no - fixed by 498a2dcd8a\r?$' $text
            Assert-Match '\*\*Fix proposal:\*\*\r?\n\r?\nValidate the length' $text
            Assert-Match '## not a heading inside a fence' $text
            Assert-Equal 3 ([regex]::Matches($text, '_analyst:').Count) '3B, 5B Mechanism and 5B Fix proposal stay open'
        }
        It 'sets the header verdict and reports unanswered items' {
            Assert-Match '\| Verdict \| A: Root cause identified; B: Hypothesis \(low\) \|' $text
            Assert-True (@($applied | Where-Object { $_ -like "ANSWER_ISSUE='## 3B Still failing*not answered*" }).Count -eq 1)
            Assert-True (@($applied | Where-Object { $_ -like 'REPORT_ISSUE=*' }).Count -gt 0)
        }
        It 'removes "to confirm" from Stages done once all pre-verdicts are confirmed' {
            Assert-Match '\| Stages done \| 1 crash summary, 2 TFS search, 3 code analysis \(evidence generated; verdict pending\) \|' $text
        }
        It 'lists only the items still open on the next round' {
            $again = @(& $script -ReportPath $report 6>&1 | ForEach-Object { "$_" })
            $keys = @($again | Where-Object { $_ -like 'OPEN_ITEM=*' } | ForEach-Object { ($_ -replace '^OPEN_ITEM=', '' -split ' \| ')[0] })
            Assert-Equal @('3B Still failing on the latest code?', '5B Mechanism', '5B Fix proposal', 'Build commit') $keys
            Assert-True (@($again | Where-Object { $_ -like 'ANSWERS_FILE=*answers-2.md' }).Count -eq 1) 'a new file each round'
        }
    }
    finally { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
}
