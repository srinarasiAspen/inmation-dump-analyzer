# End-to-end flow of Search-AdoCrashBugs.ps1 without network: the MCP results the agent would save are written by the
# test. Also covers the section 2 rendering of both sources and Complete-CrashReport with new ADO items.

. (Join-Path $script:LibRoot 'Common.ps1')
. (Join-Path $script:LibRoot 'Frames.ps1')
. (Join-Path $script:LibRoot 'SearchTerms.ps1')
. (Join-Path $script:LibRoot 'TfsMatch.ps1')
. (Join-Path $script:LibRoot 'Report.ps1')
. (Join-Path $script:LibRoot 'WorkItems.ps1')
. (Join-Path $script:LibRoot 'Stage2Report.ps1')

$script:Sig = 'Access violation in BSONObjIterator::{ctor} <- cache::get'

function New-AdoTestRun([string]$Root) {
    $run = Join-Path $Root 'run'
    New-Item -ItemType Directory -Force -Path $run | Out-Null
    $report = Join-Path $run 'crash-report.md'
    $summary = [ordered]@{
        reportPath = $report
        groups     = @([ordered]@{ signature = $script:Sig; dumps = @('C:\d\a.dmp') })
        dumps      = @([ordered]@{
                dump           = [ordered]@{ path = 'C:\d\a.dmp'; crashTimeUtc = '2026-10-01T00:00:00Z' }
                signature      = $script:Sig; signatureFamily = $script:Sig
                module         = [ordered]@{ fileVersion = '1.113.0.32898' }
                build          = [ordered]@{ productLine = 'inmation (v1.x)'; channel = 'dev' }
                exception      = [ordered]@{ code = '0xC0000005'; name = 'access violation' }
                classification = [ordered]@{ category = 'null-pointer'; title = 'Access violation in BSONObjIterator::{ctor}'; text = 'null pointer read' }
                signatureInfo  = [ordered]@{ firstOwnFrame = 3 }
                crashStack     = @(
                    [ordered]@{ index = 0; module = 'inmation'; function = 'mongo::BSONObjIterator::{ctor}'; callSite = 'inmation!mongo::BSONObjIterator::BSONObjIterator+0x1a' },
                    [ordered]@{ index = 1; module = 'inmation'; function = 'mongo::BSONObj::getField'; callSite = 'inmation!mongo::BSONObj::getField+0x2c' },
                    [ordered]@{ index = 2; module = 'inmation'; function = 'mongo::BSONObj::getObjectField'; callSite = 'inmation!mongo::BSONObj::getObjectField+0x10' },
                    [ordered]@{ index = 3; module = 'inmation'; function = 'inmation::server::cache::get'; callSite = 'inmation!inmation::server::cache::get+0x99' },
                    [ordered]@{ index = 4; module = 'inmation'; function = 'inmation::server::access::get_metaevents'; callSite = 'inmation!inmation::server::access::get_metaevents+0x5' })
            })
    }
    ConvertTo-Json -InputObject $summary -Depth 8 | Set-Content -LiteralPath (Join-Path $run 'summary.json') -Encoding UTF8
    $md = @"
# Crash analysis: Access violation in BSONObjIterator::{ctor}

| | |
|---|---|
| Binary | inmation.exe file version v1.113.0.32898 (inmation (v1.x), dev build) |
| Stages done | 1 crash summary |
| Existing work item | not searched yet (stage 2) |
| Verdict | not analyzed |

## 1. Crashing call stack

## 2. Existing TFS work items

_Not done yet - stage 2._

## 3. Does the problem still exist?

## 4. Fixing commit

## 5. Root cause

## Artifacts

- Run folder: $run (``summary.json``)
"@
    [IO.File]::WriteAllText($report, $md)
    return [pscustomobject]@{ Run = $run; Summary = (Join-Path $run 'summary.json'); Report = $report }
}

function New-AdoItemJson([int]$Id, [string]$Title, [string]$Repro, [int]$Comments = 0, [string]$Relations = '[]', [string]$Area = 'AspenTech SAFe\EOP ART\Inmation') {
    $reproJson = ConvertTo-Json -InputObject $Repro
    $areaJson = ConvertTo-Json -InputObject $Area
    return "{ `"id`": $Id, `"rev`": 3, `"fields`": { `"System.Title`": `"$Title`", `"System.State`": `"Active`", `"System.Reason`": `"New`", `"System.WorkItemType`": `"Bug`", `"System.AreaPath`": $areaJson, `"System.CreatedDate`": `"2026-09-01T10:00:00Z`", `"System.CreatedBy`": { `"displayName`": `"Dev One`" }, `"System.CommentCount`": $Comments, `"Microsoft.VSTS.TCM.ReproSteps`": $reproJson }, `"relations`": $Relations }"
}

function Invoke-AdoScript([hashtable]$ScriptArgs) {
    $script = Join-Path $script:ScriptRoot 'Search-AdoCrashBugs.ps1'
    return @(& $script @ScriptArgs 6>&1 | ForEach-Object { "$_" })
}

function Get-KeyValues([string[]]$Lines, [string]$Key) { return @($Lines | Where-Object { $_ -like "$Key=*" } | ForEach-Object { $_.Substring($Key.Length + 1) }) }
function Get-KeyValue([string[]]$Lines, [string]$Key) { return (Get-KeyValues $Lines $Key | Select-Object -First 1) }

Describe 'Search-AdoCrashBugs' {
    $root = Join-Path ([IO.Path]::GetTempPath()) "cda-ado-tests-$PID"
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $root | Out-Null
    $config = Get-Content -LiteralPath (Join-Path $script:ScriptRoot 'crash-dump-analyzer.config.json') -Raw | ConvertFrom-Json
    $config.ado.userMcpConfig = $false
    $configPath = Join-Path $root 'config.json'
    ConvertTo-Json -InputObject $config -Depth 10 | Set-Content -LiteralPath $configPath -Encoding UTF8
    $ws = Join-Path $root 'workspace'
    New-Item -ItemType Directory -Force -Path (Join-Path $ws '.vscode'), (Join-Path $ws '.github\agents') | Out-Null
    [IO.File]::WriteAllText((Join-Path $ws '.vscode\mcp.json'), '{ "servers": { "azure-devops": { "type": "stdio", "command": "npx", "args": ["--no-install", "@azure-devops/mcp", "aspentechnology", "-a", "interactive", "-d", "core", "work", "work-items"], "env": { "AZURE_DEVOPS_PROJECT": "AspenTech SAFe" } } } }')
    [IO.File]::WriteAllText((Join-Path $ws '.github\agents\nexus-bug-dev.agent.md'), '---')
    Push-Location $root
    try {
        $t = New-AdoTestRun (Join-Path $root 'flow')
        $base = @{ SummaryJson = $t.Summary; WorkspacePath = $ws; ConfigPath = $configPath }

        $out1 = Invoke-AdoScript $base
        $queries = @(Get-KeyValues $out1 'ADO_QUERY')
        It 'prints one WIQL query per crash term and a results file' {
            Assert-Match '^available \| server azure-devops \| https://dev\.azure\.com/aspentechnology \| project AspenTech SAFe' (Get-KeyValue $out1 'NEXUS_ADO')
            Assert-Equal 5 $queries.Count
            Assert-Match "^Q1 \| SELECT .*\[System\.WorkItemType\] IN \('Bug', 'Post Development Bug'\) AND \(\[System\.AreaPath\] UNDER 'AspenTech SAFe\\EOP ART'\) AND .*'BSONObjIterator'" $queries[0]
            Assert-NotMatch 'Product Family' $queries[0]
            Assert-Equal '51' (Get-KeyValue $out1 'ADO_QUERY_TOP')
            Assert-True (Test-Path -LiteralPath (Get-KeyValue $out1 'ADO_RESULTS_FILE'))
            Assert-Match 'Search-AdoCrashBugs\.ps1' (Get-KeyValue $out1 'NEXT_STEP')
        }
        It 'marks the new ADO search as pending in the report' {
            $text = [IO.File]::ReadAllText($t.Report)
            Assert-Match '_New ADO search pending:' $text
            Assert-Match 'old TFS: not searched' $text
            $lint = @(& (Join-Path $script:ScriptRoot 'Test-CrashReport.ps1') -ReportPath $t.Report 6>&1 | ForEach-Object { "$_" })
            Assert-True (@($lint | Where-Object { $_ -like 'REPORT_ISSUE=Section 2: the new ADO search*' }).Count -eq 1)
        }

        $results = (Get-KeyValue $out1 'ADO_RESULTS_FILE')
        $answers = [IO.File]::ReadAllText($results) -replace '(?m)^TODO: .*Q1 .*$', '900001, 900002' -replace '(?m)^TODO: .*Q2 .*$', '900001' -replace '(?m)^TODO: .*Q3 .*$', 'none' -replace '(?m)^TODO: .*Q4 .*$', 'too many'
        [IO.File]::WriteAllText($results, $answers)
        $out2 = Invoke-AdoScript $base
        It 'keeps asking for the queries that are still open' {
            Assert-Equal @('Q5') @(Get-KeyValues $out2 'ADO_QUERY' | ForEach-Object { ($_ -split ' \| ')[0] })
        }

        [IO.File]::WriteAllText($results, ([IO.File]::ReadAllText($results) -replace '(?m)^TODO: .*Q5 .*$', '900003'))
        $out3 = Invoke-AdoScript $base
        $fetch = @(Get-KeyValues $out3 'ADO_FETCH')
        It 'asks to fetch only the strongest candidate' {
            Assert-Equal 1 $fetch.Count
            Assert-Match '^900001 \| .*\\ado\\ado-900001\.json$' $fetch[0]
        }

        $repro = 'Access violation reading location<br>inmation.exe!mongo::BSONObjIterator::BSONObjIterator() Line 42<br>inmation.exe!mongo::BSONObj::getField(...)<br>inmation.exe!inmation::server::cache::get(...)'
        $relations = '[ { "rel": "System.LinkTypes.Related", "url": "https://dev.azure.com/aspentechnology/x/_apis/wit/workItems/900004", "attributes": { "name": "Related" } }, { "rel": "ArtifactLink", "url": "vstfs:///GitHub/PullRequest/0c1d%2f92", "attributes": { "name": "GitHub Pull Request" } } ]'
        [IO.File]::WriteAllText(($fetch[0] -split ' \| ')[1], (New-AdoItemJson 900001 'Crash in BSON iterator' $repro 1 $relations))
        $out4 = Invoke-AdoScript $base
        $comments = @(Get-KeyValues $out4 'ADO_FETCH_COMMENTS')
        It 'asks for the comments of a work item that has some' {
            Assert-Equal 1 $comments.Count
            Assert-Match '^900001 \| .*ado-900001\.comments\.json$' $comments[0]
        }

        [IO.File]::WriteAllText(($comments[0] -split ' \| ')[1], '{ "totalCount": 1, "comments": [ { "text": "<p>Seen again on v1.113</p>", "createdBy": { "displayName": "QA" }, "createdDate": "2026-09-05T00:00:00Z" } ] }')
        $out5 = Invoke-AdoScript $base
        $fetch5 = @(Get-KeyValues $out5 'ADO_FETCH')
        It 'follows the related link of a strong match' {
            Assert-Equal 1 $fetch5.Count
            Assert-Match '^900004 \| ' $fetch5[0]
        }

        [IO.File]::WriteAllText(($fetch5[0] -split ' \| ')[1], "Tool result:`n``````json`n$(New-AdoItemJson 900004 'Tree view slow' 'Nothing to see' 0)`n``````")
        $out6 = Invoke-AdoScript $base
        $text = [IO.File]::ReadAllText($t.Report)
        It 'computes pre-verdicts, writes ado-<id>.md and points to the confirmation' {
            Assert-Equal @("AB#900001 | same (to confirm) | $script:Sig") (Get-KeyValues $out6 'PRE_VERDICT' | Select-Object -First 1)
            Assert-Match '\\ado-900001\.md$' (Get-KeyValue $out6 'CONFIRM_ITEM')
            Assert-Match 'Complete-CrashReport\.ps1' (Get-KeyValue $out6 'NEXT_STEP')
            Assert-Match 'Seen again on v1\.113' ([IO.File]::ReadAllText((Join-Path $t.Run 'ado-900001.md')))
        }
        It 'renders section 2 and the header from the new ADO' {
            Assert-Match '\| \[AB#900001\]\(https://dev\.azure\.com/aspentechnology/AspenTech%20SAFe/_workitems/edit/900001\) Crash in BSON iterator \| Active \(New\) \| same \(to confirm\) \|' $text
            Assert-Match '\[AB#900004\]\([^)]*\) Tree view slow \(linked from AB#900001\)' $text
            Assert-Match '\*\*Result:\*\* \[AB#900001\]' $text
            Assert-Match '\| Existing work item \| A: AB#900001 Crash in BSON iterator \(same \(to confirm\), Active/New\) \|' $text
            Assert-Match '\| Stages done \| 1 crash summary, 2 TFS search \(pre-verdicts to confirm\) \|' $text
            Assert-NotMatch '_New ADO search pending' $text
        }
        It 'records linked GitHub pull requests for stage 3' {
            $v = @(Get-Content -LiteralPath (Join-Path $t.Run 'ado-verification.json') -Raw | ConvertFrom-Json | ForEach-Object { $_ })
            $item = @($v[0].items | Where-Object { $_.id -eq 900001 })[0]
            Assert-Equal 'AB#900001' $item.ref
            Assert-Equal @('92') @($item.githubPullRequests)
        }
        It 'lists the new ADO item for confirmation and applies the answer' {
            $listing = @(& (Join-Path $script:ScriptRoot 'Complete-CrashReport.ps1') -ReportPath $t.Report 6>&1 | ForEach-Object { "$_" })
            Assert-Match '^2A AB#900001 \| .*ado-900001\.md' (Get-KeyValue $listing 'OPEN_ITEM')
            $answersPath = (Get-KeyValue $listing 'ANSWERS_FILE')
            [IO.File]::WriteAllText($answersPath, ([IO.File]::ReadAllText($answersPath) -replace '(?m)^TODO: .*$', 'same - same frames and access violation'))
            $applied = @(& (Join-Path $script:ScriptRoot 'Complete-CrashReport.ps1') -ReportPath $t.Report -AnswersFile $answersPath 6>&1 | ForEach-Object { "$_" })
            $after = [IO.File]::ReadAllText($t.Report)
            Assert-True (@($applied | Where-Object { $_ -eq 'ANSWER_APPLIED=2A AB#900001' }).Count -eq 1)
            Assert-Match '\| Existing work item \| A: AB#900001 Crash in BSON iterator \(same, Active/New\) \|' $after
            Assert-True (@($applied | Where-Object { $_ -eq 'REPORT_OK' }).Count -eq 1) ($applied -join ' / ')
        }

        $t2 = New-AdoTestRun (Join-Path $root 'skip')
        $outSkip = Invoke-AdoScript @{ SummaryJson = $t2.Summary; WorkspacePath = $ws; ConfigPath = $configPath; Skip = 'MCP sign-in failed' }
        It 'records a skipped search and continues with the confirmation' {
            Assert-Match 'new ADO: not searched - MCP sign-in failed' ([IO.File]::ReadAllText($t2.Report))
            Assert-Match 'Complete-CrashReport\.ps1' (Get-KeyValue $outSkip 'NEXT_STEP')
            Assert-Equal 0 @(Get-KeyValues $outSkip 'NO_BUGS_FOUND').Count
        }

        $t4 = New-AdoTestRun (Join-Path $root 'scope')
        $scopeArgs = @{ SummaryJson = $t4.Summary; WorkspacePath = $ws; ConfigPath = $configPath }
        $scopeResults = Get-KeyValue (Invoke-AdoScript $scopeArgs) 'ADO_RESULTS_FILE'
        [IO.File]::WriteAllText($scopeResults, ([IO.File]::ReadAllText($scopeResults) -replace '(?m)^TODO: .*Q1 .*$', '900010' -replace '(?m)^TODO: .*$', 'none'))
        $scopeFetch = @(Get-KeyValues (Invoke-AdoScript $scopeArgs) 'ADO_FETCH')
        [IO.File]::WriteAllText(($scopeFetch[0] -split ' \| ')[1], (New-AdoItemJson 900010 'Server crash in BSON iterator' $repro 2 '[]' 'AspenTech SAFe\Shared Service ART\Nexus'))
        $outScope = Invoke-AdoScript $scopeArgs
        $scopeText = [IO.File]::ReadAllText($t4.Report)
        It 'drops a work item outside EOP ART and reports that no bugs were found' {
            Assert-Equal 0 @(Get-KeyValues $outScope 'ADO_FETCH_COMMENTS').Count
            Assert-Equal "AB#900010 | area 'AspenTech SAFe\Shared Service ART\Nexus' is not under AspenTech SAFe\EOP ART" (Get-KeyValue $outScope 'ADO_OUT_OF_SCOPE')
            Assert-Equal 0 @(Get-KeyValues $outScope 'PRE_VERDICT').Count
            Assert-Match '^A \| Access violation in BSONObjIterator::\{ctor\} \| searched: new ADO \(.*types Bug / Post Development Bug, areas AspenTech SAFe\\EOP ART\)$' (Get-KeyValue $outScope 'NO_BUGS_FOUND')
            Assert-Match '\*\*Result:\*\* no bugs found for this crash\.' $scopeText
            Assert-Match '\| Existing work item \| A: no bugs found \|' $scopeText
            Assert-NotMatch 'AB#900010' $scopeText
            Assert-Match 'Complete-CrashReport\.ps1' (Get-KeyValue $outScope 'NEXT_STEP')
        }

        $t3 = New-AdoTestRun (Join-Path $root 'none')
        $outNone = Invoke-AdoScript @{ SummaryJson = $t3.Summary; ConfigPath = $configPath }
        It 'skips the new ADO without a Nexus installation' {
            Assert-Match '^not installed \(' (Get-KeyValue $outNone 'NEXUS_ADO')
            Assert-Match 'new ADO: not searched - Nexus \(azure-devops MCP\) not found' ([IO.File]::ReadAllText($t3.Report))
            Assert-Match 'Complete-CrashReport\.ps1' (Get-KeyValue $outNone 'NEXT_STEP')
        }
    }
    finally {
        Pop-Location
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'section 2 with both sources' {
    $summary = [pscustomobject]@{
        groups = @([pscustomobject]@{ signature = 'S'; dumps = @('d') })
        dumps  = @([pscustomobject]@{ dump = [pscustomobject]@{ path = 'd' }; signature = 'S'; signatureFamily = 'S'; module = [pscustomobject]@{ fileVersion = '1.2.3.4' }; classification = [pscustomobject]@{ title = 'AV in f' } })
    }
    $terms = @([pscustomobject]@{ term = 'f'; hits = 2; tooGeneric = $false })
    $old = [pscustomobject]@{ Key = 'tfs'; Label = 'old TFS'; Order = 1; Status = 'ok'; Note = ''; Info = 'tfs3'; Updated = 'now'
        Search = @([pscustomobject]@{ signature = 'S'; blocked = $false; terms = $terms })
        Verification = @([pscustomobject]@{ signature = 'S'; items = @([pscustomobject]@{ id = 40551; ref = '#40551'; url = 'u1'; title = 'Old'; state = 'Resolved'; reason = 'Fixed'; meaning = 'fixed'; verdict = 'same (to confirm)'; why = 'w'; via = $null; commits = @('abcdef1234567'); pullRequests = @() }) }) }
    $new = [pscustomobject]@{ Key = 'ado'; Label = 'new ADO'; Order = 0; Status = 'ok'; Note = ''; Info = 'safe'; Updated = 'now'
        Search = @([pscustomobject]@{ signature = 'S'; blocked = $false; terms = $terms })
        Verification = @([pscustomobject]@{ signature = 'S'; items = @([pscustomobject]@{ id = 900001; ref = 'AB#900001'; url = 'u2'; title = 'New'; state = 'Active'; reason = 'New'; meaning = 'open'; verdict = 'same (to confirm)'; why = 'w'; via = $null }) }) }
    It 'lists both, prefers the new ADO item for the result and names the other' {
        $s = New-Stage2Section $summary @($old, $new) @{ S = 'A' }
        Assert-Match '- Search terms, old TFS: `f` \(2\)' $s.Body
        Assert-Match '- Search terms, new ADO: `f` \(2\)' $s.Body
        Assert-Match '(?s)\| \[AB#900001\]\(u2\) New .*\| \[#40551\]\(u1\) Old ' $s.Body
        Assert-Match '\*\*Result:\*\* \[AB#900001\]\(u2\) New - \*\*same \(to confirm\)\*\*\. Known open bug.* Also matching \(see the table\): #40551 \(old TFS\)\.' $s.Body
        Assert-Equal 'A: AB#900001 New (same (to confirm), Active/New)' $s.Header
        Assert-Equal 0 @($s.ConfirmFiles).Count
    }
    It 'shows a failed source and keeps the results of the other' {
        $failed = [pscustomobject]@{ Key = 'tfs'; Label = 'old TFS'; Order = 1; Status = 'error'; Note = 'TFS not reachable'; Info = ''; Updated = ''; Search = @(); Verification = @() }
        $s = New-Stage2Section $summary @($failed, $new) @{ S = 'A' }
        Assert-Match 'old TFS: not searched - TFS not reachable' $s.Body
        Assert-NotMatch '#40551' $s.Body
        Assert-Match '\*\*Result:\*\* \[AB#900001\]' $s.Body
    }
}

Describe 'Complete-CrashReport with both sources' {
    $dir = Join-Path ([IO.Path]::GetTempPath()) "cda-complete-ado-$PID"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $report = Join-Path $dir 'crash-report.md'
    [IO.File]::WriteAllText($report, @'
# Crash analysis: AV

| | |
|---|---|
| Stages done | 1 crash summary, 2 TFS search (pre-verdicts to confirm) |
| Existing work item | A: AB#900001 New (same (to confirm), Active/New) |
| Verdict | not analyzed |

## 1. Crashing call stack

## 2. Existing TFS work items

### Signature A - AV in f

| Work item | State | Pre-verdict | Why |
|---|---|---|---|
| [AB#900001](u2) New | Active (New) | same (to confirm) | w |
| [#40551](u1) Old | Resolved (Fixed) | likely same | w |

**Result:** [AB#900001](u2) New - **same (to confirm)**. Known open bug. Also matching (see the table): #40551 (old TFS).

## 3. Does the problem still exist?

## 4. Fixing commit

## 5. Root cause
'@)
    try {
        $script = Join-Path $script:ScriptRoot 'Complete-CrashReport.ps1'
        $answers = Join-Path $dir 'answers.md'
        [IO.File]::WriteAllText($answers, "## 2A AB#900001`ndifferent - other caller`n`n## 2A #40551`nsame - same stack and exception")
        $applied = @(& $script -ReportPath $report -AnswersFile $answers 6>&1 | ForEach-Object { "$_" })
        $text = [IO.File]::ReadAllText($report)
        It 'names the confirmed item of the other source when the result item is rejected' {
            Assert-Match '\| \[AB#900001\]\(u2\) New \| Active \(New\) \| different \| w; confirmed: other caller \|' $text
            Assert-Match '\| \[#40551\]\(u1\) Old \| Resolved \(Fixed\) \| same \| w; confirmed: same stack and exception \|' $text
            Assert-Match '\*\*Result:\*\* \[AB#900001\]\(u2\) New - \*\*different\*\*.* Confirmed instead: #40551 \(same\)\.' $text
            Assert-Match '\| Existing work item \| A: AB#900001 New \(different, Active/New\) \|' $text
            Assert-True (@($applied | Where-Object { $_ -like 'ANSWER_ISSUE=*' }).Count -eq 0) ($applied -join ' / ')
        }
    }
    finally { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
}
