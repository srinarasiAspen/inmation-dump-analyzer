<#
.SYNOPSIS
Searches the new ADO (Azure DevOps Services) for existing work items that match a crash analyzed by
Invoke-CrashDumpAnalysis.ps1, through the azure-devops MCP server that Nexus installs. Stage 2, after
Search-TfsCrashBugs.ps1 -Auto (old TFS).

.DESCRIPTION
Scripts cannot call an MCP server: the agent does, and this script tells it exactly what to call and reads back what
the agent saved. Run it again after each step until NEXT_STEP is the confirmation with Complete-CrashReport.ps1:
  1. Queries: ADO_QUERY=<key> | <WIQL> per search term (the crash terms of the old TFS search, restricted to the
     configured work item types and area paths, config 'ado': Bug and Post Development Bug under AspenTech SAFe\EOP ART).
     The agent runs each exactly as printed with the MCP tool wit_query
     (action wiql, top ADO_QUERY_TOP) and writes the returned IDs into ADO_RESULTS_FILE under '## <key>'.
  2. Fetch: candidates are ranked and selected as in the old TFS search; ADO_FETCH=<id> | <file> per work item (also
     items linked to strong matches as duplicate / related) and ADO_FETCH_COMMENTS=<id> | <file> for items with
     comments. The agent saves the MCP result (wit_work_item, action get / list_comments) unchanged into the file.
     A fetched item outside the configured types / area paths (a linked item, a wrong ID) is dropped:
     ADO_OUT_OF_SCOPE=AB#<id> | <reason>.
  3. Result: pre-verdicts, ado-<id>.md with match evidence, ado-search.json, ado-verification.json, report section 2
     re-rendered with the old TFS and the new ADO results, NO_BUGS_FOUND=<letter> | ... per signature without a
     matching work item, CONFIRM_ITEM=<file>, NEXT_STEP=Complete-CrashReport.ps1.

Without a Nexus installation (no @azure-devops/mcp server in .vscode/mcp.json of the workspace) it records
'not installed' and continues with the confirmation. -Skip '<reason>' records why the new ADO could not be searched
(for example: the MCP sign-in failed). The same work item can be listed from the old TFS and the new ADO (migrated
items); both are kept.

Read-only: nothing is written to ADO or TFS; files are written only into the run folder.

.EXAMPLE
.\Search-AdoCrashBugs.ps1 -SummaryJson C:\Users\me\AppData\Local\inmation-crash-analysis\runs\20261029-155120\summary.json

.EXAMPLE
.\Search-AdoCrashBugs.ps1 -SummaryJson <summary.json> -Skip 'azure-devops MCP sign-in failed'
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory = $true)][string]$SummaryJson,
    [string]$WorkspacePath,
    [string]$Skip,
    [string]$Signature,
    [string]$ConfigPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
foreach ($lib in 'Common', 'Frames', 'SearchTerms', 'TfsMatch', 'Report', 'WorkItems', 'Stage2Report', 'NexusAdo') { . (Join-Path $PSScriptRoot "lib\$lib.ps1") }

$config = (Read-AnalyzerConfig $ConfigPath $PSScriptRoot).Config
$adoCfg = Get-Cfg $config 'ado' $null
$maxFrameTerms = [int](Get-Cfg $adoCfg 'maxFrameTerms' 6)
$maxHitsPerTerm = [int](Get-Cfg $adoCfg 'maxHitsPerTerm' 50)
$top = [int](Get-Cfg $adoCfg 'top' 15)
$SummaryJson = (Resolve-Path -LiteralPath $SummaryJson).Path
$summary = Get-Content -LiteralPath $SummaryJson -Raw -Encoding UTF8 | ConvertFrom-Json
$runDir = Split-Path $SummaryJson -Parent
$adoDir = Join-Path $runDir 'ado'
$resultsPath = Join-Path $adoDir 'query-results.md'
$queriesPath = Join-Path $adoDir 'queries.json'

$nexus = Find-NexusAdo (Get-WorkspaceRoots $WorkspacePath $summary) $adoCfg
$selfCommand = Format-AdoSearchCommand $PSScriptRoot $SummaryJson $nexus $(if ($Signature) { '-Signature "' + $Signature + '"' } else { '' })
$info = if ($nexus.Available) { "$($nexus.OrgUrl), project $($nexus.Project), $(Get-AdoScopeText $adoCfg)" } else { $null }
Write-Host "NEXUS_ADO=$(Format-NexusAdoLine $nexus)"

# Renders section 2 with both sources; on a final state also the work items to confirm and the confirmation step.
function Complete-AdoStep([string]$Status, [string]$Note, [switch]$Final) {
    Write-Stage2Status $runDir 'ado' $Status $Note $info
    $r = Update-Stage2Report $summary $runDir
    if ($r.Updated) { Write-Host "REPORT_UPDATED=$($r.ReportPath)" } else { Write-Host "REPORT_NOT_FOUND=$($r.ReportPath) (copy $($r.SectionPath) into section 2 of the report)" }
    if (-not $Final) { return }
    Write-Stage2Result $r
    foreach ($f in $r.ConfirmFiles) { Write-Host "CONFIRM_ITEM=$f" }
    if ($r.Updated) { Write-Host "NEXT_STEP=Confirm the pre-verdicts: powershell -NoProfile -ExecutionPolicy Bypass -File `"$(Join-Path $PSScriptRoot 'Complete-CrashReport.ps1')`" -ReportPath `"$($r.ReportPath)`"" }
    exit 0
}

if ($Skip) { Write-Host "ADO_SKIPPED=$Skip"; Complete-AdoStep 'skipped' $Skip -Final }
if (-not $nexus.Available) { Complete-AdoStep 'not installed' "Nexus (azure-devops MCP) not found: $($nexus.Problem)" -Final }
New-Item -ItemType Directory -Force -Path $adoDir | Out-Null

#region step 1: queries

$groups = Get-SignatureGroups $summary
$searches = @()
foreach ($sig in $groups.Keys) {
    $dumps = $groups[$sig].ToArray()
    if (-not (Test-SignatureSelected $sig $dumps $Signature)) { continue }
    $rep = Get-SignatureRepresentative $dumps
    $terms = if ($rep) { @(Get-CrashTerms $rep $maxFrameTerms) } else { @() }
    $searches += [pscustomobject]@{ Signature = $sig; Dumps = $dumps.Count; Blocked = (-not $rep); Terms = $terms }
}
$queries = @()
$termKeys = @{}
foreach ($s in @($searches | Where-Object { -not $_.Blocked })) {
    foreach ($t in $s.Terms) {
        $lower = $t.Text.ToLowerInvariant()
        if ($termKeys.ContainsKey($lower)) { continue }
        $key = "Q$($queries.Count + 1)"
        $termKeys[$lower] = $key
        $queries += [pscustomobject][ordered]@{ key = $key; term = $t.Text; wiql = (New-AdoTermWiql $t.Text $adoCfg) }
    }
}

# A new results template when there is none or the queries changed (other config or summary); the old one is kept.
$stored = Read-JsonArray $queriesPath
$unchanged = ($stored.Count -eq $queries.Count) -and -not @(for ($i = 0; $i -lt $queries.Count; $i++) { if ([string](Get-Prop $stored[$i] 'wiql') -cne $queries[$i].wiql) { $i } }).Count
if (-not $unchanged -or -not (Test-Path -LiteralPath $resultsPath)) {
    if (Test-Path -LiteralPath $resultsPath) { Move-Item -LiteralPath $resultsPath -Destination (Join-Path $adoDir "query-results.$([DateTime]::UtcNow.ToString('yyyyMMddHHmmss')).old.md") -Force }
    Write-JsonFile $queriesPath @($queries)
    $sb = New-Object Text.StringBuilder
    [void]$sb.AppendLine("<!-- New ADO query results. Run each ADO_QUERY of Search-AdoCrashBugs.ps1 with the azure-devops MCP tool wit_query (action wiql, project '$($nexus.Project)', top $($maxHitsPerTerm + 1)) and replace the TODO line under its key with the IDs of the returned work items, comma-separated (e.g. 123456, 123789), or 'none'. Keep the '## ' headings. -->")
    foreach ($q in $queries) { [void]$sb.AppendLine(''); [void]$sb.AppendLine("## $($q.key)"); [void]$sb.AppendLine("TODO: work item IDs returned by query $($q.key) (term '$($q.term)'), or none") }
    [IO.File]::WriteAllText($resultsPath, $sb.ToString(), [Text.UTF8Encoding]::new($false))
}

$answers = Read-KeyedAnswers $resultsPath
$termHits = @{}
$hitCounts = @{}
$open = @()
foreach ($q in $queries) {
    $a = if ($answers.Contains($q.key)) { ConvertFrom-AdoQueryAnswer ([string]$answers[$q.key]) } else { $null }
    if (-not $a) { $open += $q; continue }
    $lower = $q.term.ToLowerInvariant()
    $termHits[$lower] = @($a.Ids)
    if ($a.TooMany -and @($a.Ids).Count -le $maxHitsPerTerm) { $hitCounts[$lower] = $maxHitsPerTerm + 1 }
}
if ($open.Count -gt 0) {
    Write-Host "ADO_PROJECT=$($nexus.Project)"
    Write-Host "ADO_QUERY_TOP=$($maxHitsPerTerm + 1)"
    foreach ($q in $open) { Write-Host "ADO_QUERY=$($q.key) | $($q.wiql)" }
    Write-Host "ADO_RESULTS_FILE=$resultsPath"
    Complete-AdoStep 'pending' $null
    Write-Host "NEXT_STEP=Run each ADO_QUERY with the azure-devops MCP tool wit_query (action wiql, project '$($nexus.Project)', top $($maxHitsPerTerm + 1)); in $resultsPath replace the TODO line under '## <key>' with the returned work item IDs (comma-separated) or 'none'. Then run: $selfCommand"
    exit 0
}

#endregion

#region step 2: fetch the candidates

$entries = @(foreach ($s in $searches) {
        if ($s.Blocked) { [pscustomobject][ordered]@{ signature = $s.Signature; dumps = $s.Dumps; blocked = $true; terms = @(); candidates = @() }; continue }
        $e = Get-SearchEntry $s.Signature $s.Dumps $s.Terms $termHits $maxHitsPerTerm $top $hitCounts
        foreach ($c in $e.candidates) { $c | Add-Member -NotePropertyName 'url' -NotePropertyValue (Get-AdoWorkItemUrl $nexus.OrgUrl $nexus.Project $c.id) }
        $e
    })

$itemCache = @{}
# The saved work item (and its comments) or why it is not usable yet: Status ok / missing / invalid / comments.
# OutOfScope: why an ok item is outside the configured types / area paths (it is dropped), else $null.
function Read-AdoItemFile([int]$ItemId) {
    if ($itemCache.ContainsKey($ItemId)) { return $itemCache[$ItemId] }
    $path = Join-Path $adoDir "ado-$ItemId.json"
    $commentsPath = Join-Path $adoDir "ado-$ItemId.comments.json"
    $result = [pscustomobject]@{ Id = $ItemId; Status = 'ok'; Item = $null; Comments = $null; Problem = $null; Path = $path; CommentsPath = $commentsPath; OutOfScope = $null }
    if (-not (Test-Path -LiteralPath $path)) { $result.Status = 'missing' }
    else {
        try {
            $result.Item = Get-AdoWorkItemFromJson (ConvertFrom-McpJsonText ([IO.File]::ReadAllText($path))) $ItemId
            if (-not $result.Item) { throw "no work item $ItemId with fields in the file" }
        }
        catch { $result.Status = 'invalid'; $result.Problem = $_.Exception.Message }
    }
    if ($result.Status -eq 'ok') { $result.OutOfScope = Get-AdoOutOfScopeReason $result.Item.fields $adoCfg }
    if ($result.Status -eq 'ok' -and -not $result.OutOfScope) {
        if (Test-Path -LiteralPath $commentsPath) {
            try { $result.Comments = ConvertFrom-McpJsonText ([IO.File]::ReadAllText($commentsPath)) }
            catch { $result.Status = 'invalid'; $result.Path = $commentsPath; $result.Problem = $_.Exception.Message }
        }
        elseif ([int](Get-Field $result.Item.fields 'System.CommentCount') -gt 0) { $result.Status = 'comments' }
    }
    $itemCache[$ItemId] = $result
    return $result
}

$selected = @{}
$waiting = New-Object Collections.Generic.List[object]
foreach ($e in @($entries | Where-Object { -not $_.blocked })) {
    $selected[$e.signature] = @{}
    $rep = Get-SignatureRepresentative $groups[$e.signature].ToArray()
    $queue = @(Select-CandidatesToVerify $e | ForEach-Object { [pscustomobject]@{ Id = [int]$_; Via = $null } })
    while ($queue.Count -gt 0) {
        $next = $queue[0]; $queue = @($queue | Select-Object -Skip 1)
        if ($selected[$e.signature].ContainsKey($next.Id)) { continue }
        $selected[$e.signature][$next.Id] = $next.Via
        $file = Read-AdoItemFile $next.Id
        if ($file.Status -ne 'ok') { if (-not $waiting.Contains($file)) { $waiting.Add($file) }; continue }
        if ($file.OutOfScope -or $next.Via) { continue }
        $pre = Get-WorkItemPreVerdict $rep (Get-WorkItemText $file.Item.fields (Get-AdoDiscussion $file.Comments $file.Item)) $maxFrameTerms
        if ($pre.Verdict -match '^(same|likely same)') {
            foreach ($l in @((Get-WorkItemLinks $file.Item).WorkItems | Where-Object { $_.Name -match 'Duplicate|Related' } | Select-Object -First 3)) { $queue += [pscustomobject]@{ Id = [int]$l.Id; Via = $next.Id } }
        }
    }
}
if ($waiting.Count -gt 0) {
    Write-Host "ADO_PROJECT=$($nexus.Project)"
    foreach ($w in $waiting) {
        switch ($w.Status) {
            'missing' { Write-Host "ADO_FETCH=$($w.Id) | $($w.Path)" }
            'comments' { Write-Host "ADO_FETCH_COMMENTS=$($w.Id) | $($w.CommentsPath)" }
            default { Write-Host "ADO_FETCH_INVALID=$($w.Id) | $($w.Path) | $($w.Problem)" }
        }
    }
    Complete-AdoStep 'pending' $null
    Write-Host "NEXT_STEP=For each ADO_FETCH: call the azure-devops MCP tool wit_work_item (action get, id <id>, project '$($nexus.Project)', expand Relations) and save the tool result unchanged as the named file. For each ADO_FETCH_COMMENTS: wit_work_item (action list_comments, workItemId <id>, project '$($nexus.Project)'), saved the same way. ADO_FETCH_INVALID: fetch and save that file again. Then run: $selfCommand"
    exit 0
}

#endregion

#region step 3: pre-verdicts and report

$fetched = @{}
$linkTemplate = (Get-AdoWorkItemUrl $nexus.OrgUrl $nexus.Project 0) -replace '0$', '{id}'
foreach ($itemId in @($selected.Values | ForEach-Object { $_.Keys } | Select-Object -Unique)) {
    $file = Read-AdoItemFile ([int]$itemId)
    if ($file.OutOfScope) { Write-Host "ADO_OUT_OF_SCOPE=AB#$itemId | $($file.OutOfScope)"; continue }
    $links = Get-Cfg $file.Item '_links' $null
    $url = [string](Get-Cfg (Get-Cfg $links 'html' $null) 'href' '')
    if (-not $url) { $url = Get-AdoWorkItemUrl $nexus.OrgUrl $nexus.Project ([int]$itemId) }
    $item = [pscustomobject]@{
        Id = [int]$itemId; Ref = "AB#$itemId"; RefPrefix = 'AB#'; Url = $url; LinkUrlTemplate = $linkTemplate; SourceLabel = 'ADO'
        Fields = $file.Item.fields; Links = (Get-WorkItemLinks $file.Item); Discussion = (Get-AdoDiscussion $file.Comments $file.Item)
    }
    $wi = Export-WorkItemMarkdown $item $groups $Signature $maxFrameTerms (Join-Path $runDir "ado-$itemId.md")
    $fetched[[int]$itemId] = $wi
    Write-Host "AB#$itemId [$($wi.State)] $($wi.Title)"
    Write-Host "ADO_ITEM_MD=$($wi.Path)"
}
$letters = Get-ReportGroupLetters $summary
$verifyData = @(foreach ($e in @($entries | Where-Object { -not $_.blocked })) {
        $rows = @(Get-VerifiedRows $e.signature $fetched $selected[$e.signature])
        foreach ($r in $rows) { Write-Host "PRE_VERDICT=AB#$($r.Id) | $($r.Verdict) | $($e.signature)" }
        [ordered]@{ signature = $e.signature; letter = $(if ($letters.ContainsKey($e.signature)) { $letters[$e.signature] } else { $null }); items = @($rows | ForEach-Object { ConvertTo-VerificationItem $fetched[[int]$_.Id] $_ 'ado' }) }
    })
Write-JsonFile (Join-Path $runDir 'ado-search.json') @($entries)
Write-JsonFile (Join-Path $runDir 'ado-verification.json') $verifyData
Write-Host "ADO_SEARCH_JSON=$(Join-Path $runDir 'ado-search.json')"
Complete-AdoStep 'ok' $null -Final

#endregion
