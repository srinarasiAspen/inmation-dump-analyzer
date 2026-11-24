# Report section 2 (existing work items) from the stage 2 files in the run folder, for both sources:
#   old TFS (Search-TfsCrashBugs.ps1): tfs-status.json, tfs-search.json, tfs-verification.json - work items '#<id>'
#   new ADO (Search-AdoCrashBugs.ps1): ado-status.json, ado-search.json, ado-verification.json - work items 'AB#<id>'
# Either script re-renders the whole section, so the order in which they run does not matter. Needs Common, Frames,
# Report and WorkItems.

$script:Stage2Sources = @(
    [pscustomobject]@{ Key = 'tfs'; Label = 'old TFS'; Order = 1 },
    [pscustomobject]@{ Key = 'ado'; Label = 'new ADO'; Order = 0 }
)
$script:Stage2PendingMarker = '_New ADO search pending:'

function Read-JsonArray([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return , @() }
    $json = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    return , @($json | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
}

function Write-JsonFile([string]$Path, $Value) {
    ConvertTo-Json -InputObject $Value -Depth 8 | Set-Content -LiteralPath $Path -Encoding UTF8
}

# Status file of a source: status = ok | pending | error | not installed | skipped; note; info (server, project, filter).
function Write-Stage2Status([string]$RunDir, [string]$Key, [string]$Status, [string]$Note, [string]$Info) {
    Write-JsonFile (Join-Path $RunDir "$Key-status.json") ([ordered]@{ status = $Status; note = $Note; info = $Info; updatedUtc = [DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm') })
}

function Read-Stage2Source([string]$RunDir, [string]$Key) {
    $def = $script:Stage2Sources | Where-Object { $_.Key -eq $Key } | Select-Object -First 1
    $search = Read-JsonArray (Join-Path $RunDir "$Key-search.json")
    $verification = Read-JsonArray (Join-Path $RunDir "$Key-verification.json")
    $statusPath = Join-Path $RunDir "$Key-status.json"
    $status = if (Test-Path -LiteralPath $statusPath) { Get-Content -LiteralPath $statusPath -Raw -Encoding UTF8 | ConvertFrom-Json } else { $null }
    $state = [string](Get-Prop $status 'status')
    if (-not $state) { $state = if ($search.Count -or $verification.Count) { 'ok' } else { 'not run' } }
    # Results of an earlier run are not shown while a source is pending or failed.
    if ($state -ne 'ok') { $search = @(); $verification = @() }
    return [pscustomobject]@{
        Key = $Key; Label = $def.Label; Order = $def.Order; Status = $state; Note = [string](Get-Prop $status 'note'); Info = [string](Get-Prop $status 'info')
        Updated = [string](Get-Prop $status 'updatedUtc'); Search = $search; Verification = $verification
    }
}

function Get-Stage2StatusText($Source) {
    switch ($Source.Status) {
        'ok' { return "$($Source.Label)$(if ($Source.Info) { " ($($Source.Info))" }), searched $($Source.Updated)Z" }
        'pending' { return "$($Source.Label): search pending" }
        default { return "$($Source.Label): not searched$(if ($Source.Note) { " - $($Source.Note)" })" }
    }
}

function Format-DraftBugText($Dump, [string]$Family) {
    $lines = @()
    $lines += "Title: Crash: $(Get-Prop $Dump 'classification.title') (inmation.exe v$(Get-Prop $Dump 'module.fileVersion'))"
    $lines += "Found in: v$(Get-Prop $Dump 'module.fileVersion') ($(Get-Prop $Dump 'build.productLine'), $(Get-Prop $Dump 'build.channel') build$(if (Get-Prop $Dump 'build.brand') { ", brand $(Get-Prop $Dump 'build.brand')" }))"
    $lines += "Exception: $(Get-Prop $Dump 'exception.code') $(Get-Prop $Dump 'exception.name')$(if (Get-Prop $Dump 'exception.access') { ", $(Get-Prop $Dump 'exception.access')" })"
    $lines += "Classification: $(Get-Prop $Dump 'classification.text')"
    $lines += "Signature: $Family"
    $lines += 'First stack lines:'
    $stackLines = if ((Get-Prop $Dump 'signatureInfo.noApplicationFrame') -and (Get-Prop $Dump 'cppException')) { @(Get-RecoveredThrowLines (Get-Prop $Dump 'cppException') 8) } else { @((Get-ReportStack $Dump 8).Lines) }
    foreach ($l in $stackLines) { $lines += "    $l" }
    foreach ($lf in @(Get-Prop $Dump 'luaStack' | Where-Object { (Get-Prop $_ 'kind') -eq 'Lua' } | Select-Object -First 3)) { $lines += "Lua: $(Get-Prop $lf 'source') line $(Get-Prop $lf 'line')" }
    foreach ($sc in @(Get-Prop $Dump 'scriptContext' | Where-Object { Get-Prop $_ 'request.endpoint' } | Select-Object -First 1)) { $lines += "Request: $(Get-Prop $sc 'request.method') $(Get-Prop $sc 'request.endpoint')" }
    return $lines
}

# What the state of a matching work item means. $Item: an entry of tfs-/ado-verification.json.
function Get-MeaningText($Item, $Dump, [string]$Family) {
    $state = [string](Get-Prop $Item 'state'); $reason = [string](Get-Prop $Item 'reason'); $integrated = [string](Get-Prop $Item 'integratedIn')
    switch ([string](Get-Prop $Item 'meaning')) {
        'fixed' {
            $commits = @(Get-Prop $Item 'commits' | Where-Object { $_ } | ForEach-Object { ([string]$_).Substring(0, [Math]::Min(10, ([string]$_).Length)) })
            $prs = @(@(Get-Prop $Item 'pullRequests' | Where-Object { $_ }) + @(Get-Prop $Item 'githubPullRequests' | Where-Object { $_ } | ForEach-Object { "GitHub #$_" }))
            if ($commits.Count -or $prs.Count) { return "Resolved as fixed ($state, $reason). Linked fix: $(if ($commits.Count) { "commits $($commits -join ', ')" })$(if ($commits.Count -and $prs.Count) { '; ' })$(if ($prs.Count) { "pull requests $($prs -join ', ')" }). Stage 3 checks whether the crashed version contains the fix$(if ($integrated) { " (integrated in: $integrated)" })." }
            return "Resolved as fixed ($state, $reason) but no commit or pull request is linked$(if ($integrated) { "; integrated in: $integrated" }). Stage 3 searches the history for the fix."
        }
        'open' { return "Known open bug ($state, $reason). This dump is additional evidence. Suggested comment (for the user to post; never post it automatically): ``New crash with the same stack: inmation.exe v$(Get-Prop $Dump 'module.fileVersion') ($(Get-Prop $Dump 'build.channel') build), crash time $(Get-Prop $Dump 'dump.crashTimeUtc'), signature $Family.``" }
        'duplicate' { return "Closed as duplicate ($state, $reason); follow its links: $(@(Get-Prop $Item 'linkedWorkItems' | Where-Object { $_ } | ForEach-Object { "$(Get-Prop $_ 'ref') ($(Get-Prop $_ 'name'))" }) -join ', ')." }
        'closed without fix' { return "Closed without a fix ($state, $reason)." }
        default { return "State $state ($reason)." }
    }
}

function Format-SearchTerms($Entry) {
    return (@(Get-Prop $Entry 'terms' | Where-Object { $_ } | ForEach-Object { "``$(Get-Prop $_ 'term')`` ($(Get-Prop $_ 'hits')$(if (Get-Prop $_ 'tooGeneric') { ', too generic' }))" }) -join ', ')
}

# Section 2 body and the 'Existing work item' header value. $Sources: Read-Stage2Source results.
function New-Stage2Section($Summary, $Sources, $Letters) {
    $sb = New-Object Text.StringBuilder
    $add = { param([string]$Line = '') [void]$sb.AppendLine($Line) }
    $headerParts = @()
    $noneFound = @()
    $confirm = New-Object Collections.Generic.List[string]
    $searched = @($Sources | Where-Object { $_.Status -eq 'ok' })
    $searchedScope = @($searched | Sort-Object Order -Descending | ForEach-Object { "$($_.Label)$(if ($_.Info) { " ($($_.Info))" })" }) -join '; '
    & $add "_Searched: $(@($Sources | Sort-Object Order -Descending | ForEach-Object { Get-Stage2StatusText $_ }) -join '; '). ``#<id>`` = old TFS, ``AB#<id>`` = new ADO; the same bug can be listed from both. Pre-verdicts come from text matches of the crash facts; each ``same`` / ``likely same`` is confirmed by reading its tfs-<id>.md / ado-<id>.md._"
    if (@($Sources | Where-Object { $_.Status -eq 'pending' }).Count) {
        & $add ''
        & $add "$script:Stage2PendingMarker run Search-AdoCrashBugs.ps1 -SummaryJson <summary.json> until it prints the Complete-CrashReport step, or record why it cannot run with -Skip '<reason>'._"
    }
    $groups = Get-SignatureGroups $Summary
    $signatures = @()
    foreach ($sig in $groups.Keys) {
        foreach ($s in $Sources) { if (@($s.Search | Where-Object { (Get-Prop $_ 'signature') -eq $sig }).Count) { $signatures += $sig; break } }
    }
    $order = @{ 'same (to confirm)' = 0; 'likely same' = 1; 'related' = 2; 'different' = 3 }
    foreach ($sig in $signatures) {
        $letter = if ($Letters.ContainsKey($sig)) { $Letters[$sig] } else { '?' }
        $rep = Get-SignatureRepresentative $groups[$sig].ToArray()
        $entries = @(foreach ($s in $Sources) { $e = $s.Search | Where-Object { (Get-Prop $_ 'signature') -eq $sig } | Select-Object -First 1; if ($e) { [pscustomobject]@{ Source = $s; Entry = $e } } })
        & $add ''
        & $add "### Signature $letter - $(if ($rep) { Get-Prop $rep 'classification.title' } else { $sig })"
        & $add ''
        if (@($entries | Where-Object { Get-Prop $_.Entry 'blocked' }).Count) { & $add 'Not searched: symbols not verified (BLOCKED).'; $headerParts += "${letter}: not searched (blocked)"; continue }
        if (-not @($entries | Where-Object { @(Get-Prop $_.Entry 'terms' | Where-Object { $_ }).Count }).Count) { & $add 'Not searched: no distinctive frame or identifier in the signature.'; $headerParts += "${letter}: not searched (no distinctive term)"; continue }
        foreach ($x in @($entries | Sort-Object { $_.Source.Order } -Descending)) { & $add "- Search terms, $($x.Source.Label): $(Format-SearchTerms $x.Entry)" }
        & $add ''
        $rows = @()
        foreach ($s in $Sources) {
            $v = $s.Verification | Where-Object { (Get-Prop $_ 'signature') -eq $sig } | Select-Object -First 1
            foreach ($it in @(Get-Prop $v 'items' | Where-Object { $_ })) { $rows += [pscustomobject]@{ Item = $it; Source = $s } }
        }
        $rows = @($rows | Sort-Object { $order[[string](Get-Prop $_.Item 'verdict')] }, { if (Get-Prop $_.Item 'via') { 1 } else { 0 } }, { $_.Source.Order }, { -[int](Get-Prop $_.Item 'id') })
        if ($rows.Count -gt 0) {
            & $add '| Work item | State | Pre-verdict | Why |'
            & $add '|---|---|---|---|'
            foreach ($r in $rows) {
                $it = $r.Item
                $ref = [string](Get-Prop $it 'ref'); if (-not $ref) { $ref = "#$(Get-Prop $it 'id')" }
                $via = [string](Get-Prop $it 'viaRef'); if (-not $via -and (Get-Prop $it 'via')) { $via = "#$(Get-Prop $it 'via')" }
                & $add "| [$ref]($(Get-Prop $it 'url')) $(Format-MdCell ([string](Get-Prop $it 'title')))$(if ($via) { " (linked from $via)" }) | $(Get-Prop $it 'state') ($(Get-Prop $it 'reason')) | $(Get-Prop $it 'verdict') | $(Format-MdCell ([string](Get-Prop $it 'why'))) |"
                if ([string](Get-Prop $it 'verdict') -match '^(same|likely same)' -and (Get-Prop $it 'file')) { $confirm.Add([string](Get-Prop $it 'file')) }
            }
            & $add ''
        }
        $matching = @($rows | Where-Object { [string](Get-Prop $_.Item 'verdict') -match '^(same \(to confirm\)|likely same)$' })
        if ($matching.Count -gt 0) {
            $it = $matching[0].Item
            $ref = [string](Get-Prop $it 'ref'); if (-not $ref) { $ref = "#$(Get-Prop $it 'id')" }
            $others = @($matching | Select-Object -Skip 1 | ForEach-Object { $o = [string](Get-Prop $_.Item 'ref'); if (-not $o) { $o = "#$(Get-Prop $_.Item 'id')" }; "$o ($($_.Source.Label))" })
            & $add "**Result:** [$ref]($(Get-Prop $it 'url')) $(Format-MdCell ([string](Get-Prop $it 'title'))) - **$(Get-Prop $it 'verdict')**. $(Get-MeaningText $it $rep $sig)$(if ($others.Count) { " Also matching (see the table): $($others -join ', ')." })"
            $headerParts += "${letter}: $ref $(Get-Prop $it 'title') ($(Get-Prop $it 'verdict'), $(Get-Prop $it 'state')/$(Get-Prop $it 'reason'))"
        }
        elseif ($searched.Count -eq 0) {
            & $add '**Result:** not searched yet.'
            $headerParts += "${letter}: not searched yet"
        }
        else {
            $closest = @($rows | Where-Object { (Get-Prop $_.Item 'verdict') -eq 'related' } | ForEach-Object { $o = [string](Get-Prop $_.Item 'ref'); if (-not $o) { $o = "#$(Get-Prop $_.Item 'id')" }; $o })
            & $add "**Result:** no bugs found for this crash.$(if ($closest.Count) { " Related (different crash, same component or callers): $($closest -join ', ')." })"
            if ($rep) {
                & $add ''
                & $add 'Draft bug text (for the user to file; never create work items automatically):'
                & $add ''
                & $add '```text'
                foreach ($l in (Format-DraftBugText $rep $sig)) { & $add $l }
                & $add '```'
            }
            $headerParts += "${letter}: no bugs found"
            $noneFound += [pscustomobject]@{ Letter = $letter; Signature = $sig; Title = $(if ($rep) { [string](Get-Prop $rep 'classification.title') } else { $sig }); Searched = $searchedScope }
        }
    }
    if ($signatures.Count -eq 0) { $headerParts += "not searched ($(@($Sources | Sort-Object Order -Descending | ForEach-Object { Get-Stage2StatusText $_ }) -join '; '))" }
    return [pscustomobject]@{ Body = $sb.ToString(); Header = ($headerParts -join "`n"); ConfirmFiles = @($confirm | Select-Object -Unique); NoneFound = $noneFound }
}

# Final stage 2 lines of both search scripts: NO_BUGS_FOUND=<letter> | <title> | searched: <sources and scope> for each
# signature without a matching work item in any searched source. $Result: Update-Stage2Report.
function Write-Stage2Result($Result) {
    foreach ($n in @($Result.NoneFound)) { Write-Host "NO_BUGS_FOUND=$($n.Letter) | $($n.Title) | searched: $($n.Searched)" }
}

# Renders section 2 from both sources, writes it to stage2-section.md, and updates the report (section 2, the
# 'Existing work item' and 'Stages done' header rows) when the report exists.
function Update-Stage2Report($Summary, [string]$RunDir) {
    $sources = @(foreach ($s in $script:Stage2Sources) { Read-Stage2Source $RunDir $s.Key })
    $section = New-Stage2Section $Summary $sources (Get-ReportGroupLetters $Summary)
    $sectionPath = Join-Path $RunDir 'stage2-section.md'
    Set-Content -LiteralPath $sectionPath -Value $section.Body -Encoding UTF8
    $reportPath = [string](Get-Prop $Summary 'reportPath')
    $updated = $false
    if ($reportPath -and (Test-Path -LiteralPath $reportPath)) {
        $stages = [string](Get-ReportHeaderValue $reportPath 'Stages done')
        if ($stages -notmatch '\b2\b') { $stages = "$stages, 2 TFS search" }
        $marker = if ($section.Body -match 'same \(to confirm\)') { ' (pre-verdicts to confirm)' } else { '' }
        $stages = $stages -replace '(\b2 TFS search)( \(pre-verdicts to confirm\))?', ('$1' + $marker)
        Set-ReportSection $reportPath 2 $section.Body @{ 'Existing work item' = $section.Header; 'Stages done' = $stages }
        $updated = $true
    }
    return [pscustomobject]@{ Body = $section.Body; Header = $section.Header; SectionPath = $sectionPath; ReportPath = $reportPath; Updated = $updated; ConfirmFiles = $section.ConfirmFiles; NoneFound = $section.NoneFound; Sources = $sources }
}
