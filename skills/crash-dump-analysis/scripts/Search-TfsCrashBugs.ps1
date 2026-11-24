<#
.SYNOPSIS
Searches TFS / Azure DevOps Server for existing work items that match a crash analyzed by Invoke-CrashDumpAnalysis.ps1.

.DESCRIPTION
Read-only. The only POST is the WIQL query endpoint (_apis/wit/wiql), which runs a query and changes nothing; all other
calls are GET. Work items are never created, updated or commented on.

Search mode (-SummaryJson and/or -Term):
  Derives search terms per crash signature from summary.json - identifiers of the asserted expression and the function
  names of the first meaningful frames (frames that only report the failure, C++ exception dispatch, the Lua VM and OS
  frames are skipped) -
  and runs one full-text query per term over title, repro steps, description, system info and discussion. Candidates
  are ranked by the matched terms (earlier frames and rarer terms weigh more). Terms with too many hits are reported
  as too generic and not scored. BLOCKED dumps (unverified symbols) are skipped: their function names are not reliable.
  Writes tfs-search.md / tfs-search.json and prints TFS_SEARCH_MD=<path>.

Detail mode (-Id):
  Fetches each work item with its repro steps, description, system info, discussion, links (related work items,
  commits, pull requests, attachments) and writes tfs-<id>.md (TFS_ITEM_MD=<path>). With -SummaryJson it adds a
  "Match evidence" table: which crash facts (frame functions, asserted identifiers, exception code, file version)
  occur in the work item text.

Auto mode (-SummaryJson -Auto):
  Search, then fetch the candidates worth verifying (and the items linked to strong matches as duplicate / related),
  compute a pre-verdict per signature, write tfs-verification.json and render report section 2 together with the new
  ADO results of Search-AdoCrashBugs.ps1 (lib/Stage2Report.ps1). Then it looks for the azure-devops MCP server of a
  Nexus installation in the workspace (.vscode/mcp.json): NEXUS_ADO=available | ... makes NEXT_STEP the new ADO search
  (Search-AdoCrashBugs.ps1); otherwise NEXT_STEP is the confirmation with Complete-CrashReport.ps1.

Authentication: a PAT from SOURCE_ADO_PAT / TFS_PAT or the per-user file ~/.config/inmation-ado/.env (same as the
inmation-ado-* skills); otherwise Windows integrated authentication of the current user. Credentials are never printed.
On failure the script prints TFS_ERROR=<message> and exits with code 2; with -Auto it still writes tfs-status.json,
renders section 2 and prints the new ADO step (NEXUS_ADO=, NEXT_STEP=), so the new ADO is searched anyway.

.EXAMPLE
.\Search-TfsCrashBugs.ps1 -SummaryJson C:\Users\me\AppData\Local\inmation-crash-analysis\runs\20261029-155120\summary.json

.EXAMPLE
.\Search-TfsCrashBugs.ps1 -Id 13023,12750 -SummaryJson <summary.json>

.EXAMPLE
.\Search-TfsCrashBugs.ps1 -SummaryJson <summary.json> -Signature 'process_vqt_writes'

.PARAMETER Signature
Restricts search and match evidence to crash signatures containing this text (summary.json can hold several).

.PARAMETER WorkspacePath
Workspace with the Nexus installation (.vscode/mcp.json) for the new ADO step; default: the current directory, its git
root and the source repository of the run.

.EXAMPLE
.\Search-TfsCrashBugs.ps1 -Term '_mongoc_cursor_collection', 'collection_len'

.NOTES
-Id and -Term also accept one comma-separated string, so lists work the same with 'powershell -File' (which passes
'-Id 1,2' as the single string "1,2") as in-process. Commas inside <...> (template arguments) do not split a term.
#>
[CmdletBinding()]
param(
    [string]$SummaryJson,
    [string[]]$Term,
    [string[]]$Id,
    [string]$Signature,
    [string[]]$WorkItemType,
    [int]$Top = 0,
    [string]$ConfigPath,
    [string]$OutDir,
    [string]$WorkspacePath,
    [switch]$Auto
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

foreach ($lib in 'Common', 'Frames', 'SearchTerms', 'TfsMatch', 'Report', 'TfsAuth', 'WorkItems', 'Stage2Report', 'NexusAdo') { . (Join-Path $PSScriptRoot "lib\$lib.ps1") }

# 'powershell -File' passes '-Id 1,2' / '-Term a,b' as one string; split on commas outside <...> template arguments.
function Split-ListArgument([string[]]$Values) {
    $out = New-Object Collections.Generic.List[string]
    foreach ($v in @($Values)) {
        if (-not $v) { continue }
        $depth = 0
        $current = New-Object Text.StringBuilder
        foreach ($ch in $v.ToCharArray()) {
            if ($ch -eq '<') { $depth++ } elseif ($ch -eq '>' -and $depth -gt 0) { $depth-- }
            if ($ch -eq ',' -and $depth -eq 0) { $out.Add($current.ToString().Trim()); [void]$current.Clear(); continue }
            [void]$current.Append($ch)
        }
        $out.Add($current.ToString().Trim())
    }
    return @($out | Where-Object { $_ })
}

$config = (Read-AnalyzerConfig $ConfigPath $PSScriptRoot).Config
$tfsCfg = Get-Cfg $config 'tfs' $null
$baseUrl = ([string](Get-Cfg $tfsCfg 'url' 'https://tfs3.inmationdev.com/tfs/inmation')).TrimEnd('/')
$project = [string](Get-Cfg $tfsCfg 'project' 'system_inmation')
$apiVersion = [string](Get-Cfg $tfsCfg 'apiVersion' '4.1')
if (-not $WorkItemType) { $WorkItemType = @(Get-Cfg $tfsCfg 'workItemTypes' @('Bug')) }
if ($Top -le 0) { $Top = [int](Get-Cfg $tfsCfg 'top' 15) }
$maxFrameTerms = [int](Get-Cfg $tfsCfg 'maxFrameTerms' 6)
$maxHitsPerTerm = [int](Get-Cfg $tfsCfg 'maxHitsPerTerm' 200)
$titleFields = @(Get-Cfg $tfsCfg 'titleFields' @('System.Title'))
$textFields = @(Get-Cfg $tfsCfg 'textFields' @('Microsoft.VSTS.TCM.ReproSteps', 'System.Description', 'Microsoft.VSTS.TCM.SystemInfo', 'System.History'))
$ownModules = @((Get-Cfg $config 'binaries' $null).PSObject.Properties | ForEach-Object { [IO.Path]::GetFileNameWithoutExtension($_.Name) })

#region TFS access

$script:auth = Get-TfsAuth

function Invoke-Tfs([string]$Method, [string]$Uri, $Body) {
    $params = @{ Uri = $Uri; Method = $Method; Headers = $script:auth.Headers; TimeoutSec = 90; UseBasicParsing = $true }
    if ($script:auth.UseDefaultCredentials) { $params.UseDefaultCredentials = $true }
    if ($null -ne $Body) { $params.Body = [Text.Encoding]::UTF8.GetBytes(($Body | ConvertTo-Json -Depth 5)); $params.ContentType = 'application/json; charset=utf-8' }
    try { return Invoke-RestMethod @params }
    catch {
        $status = $null
        if ($_.Exception.PSObject.Properties['Response'] -and $_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
        $detail = if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
        $detail = ($detail -replace 'Authorization:\s*\S+', 'Authorization: [redacted]')
        if ($detail.Length -gt 400) { $detail = $detail.Substring(0, 400) + ' ...' }
        $message = switch ($status) {
            401 { "TFS authentication failed (401, $($script:auth.Mode)). Sign in with a domain account that has access to $baseUrl, or set TFS_PAT (or ~/.config/inmation-ado/.env)." }
            403 { "TFS access denied (403, $($script:auth.Mode)): the account lacks permission for project $project." }
            404 { "TFS resource not found (404): $Uri" }
            $null { "TFS not reachable ($baseUrl): $detail" }
            default { "TFS request failed ($status): $detail" }
        }
        throw [InvalidOperationException]::new($message)
    }
}

function Get-WebUrl([int]$WorkItemId) { return "$baseUrl/$([Uri]::EscapeDataString($project))/_workitems/edit/$WorkItemId" }

function Invoke-Wiql([string]$Where) {
    $types = ($WorkItemType | ForEach-Object { "'" + ($_ -replace "'", "''") + "'" }) -join ', '
    $query = "SELECT [System.Id] FROM WorkItems WHERE [System.TeamProject] = @project AND [System.WorkItemType] IN ($types) AND ($Where)"
    $result = Invoke-Tfs 'Post' "$baseUrl/$([Uri]::EscapeDataString($project))/_apis/wit/wiql?api-version=$apiVersion" @{ query = $query }
    return @($result.workItems | ForEach-Object { [int]$_.id })
}

function Get-WorkItems([int[]]$Ids) {
    $items = @()
    for ($i = 0; $i -lt $Ids.Count; $i += 100) {
        $chunk = $Ids[$i..([Math]::Min($i + 99, $Ids.Count - 1))]
        $items += @((Invoke-Tfs 'Get' "$baseUrl/_apis/wit/workitems?ids=$($chunk -join ',')&api-version=$apiVersion" $null).value)
    }
    return $items
}

#endregion

#region detail mode helpers

function Get-WorkItemDetail([int]$WorkItemId) {
    $item = Invoke-Tfs 'Get' "$baseUrl/_apis/wit/workitems/$WorkItemId`?`$expand=relations&api-version=$apiVersion" $null
    $updates = @((Invoke-Tfs 'Get' "$baseUrl/_apis/wit/workItems/$WorkItemId/updates?api-version=$apiVersion" $null).value)
    $discussion = @()
    foreach ($u in $updates) {
        $f = Get-Cfg $u 'fields' $null
        $h = Get-Field $f 'System.History'
        if ($h -and (Get-Cfg $h 'newValue' $null)) {
            $date = Get-Field $f 'System.ChangedDate'
            $discussion += [pscustomobject]@{ Date = $(if ($date) { Get-Cfg $date 'newValue' $null } else { Get-Cfg $u 'revisedDate' $null }); By = Get-DisplayName (Get-Cfg $u 'revisedBy' $null); Text = ConvertFrom-Html (Get-Cfg $h 'newValue' '') }
        }
    }
    return [pscustomobject]@{ Item = $item; Discussion = $discussion }
}

# Fetches one work item, writes tfs-<id>.md (fields, text, discussion, links, match evidence) and returns its facts.
function Export-WorkItem([int]$WorkItemId, $Groups) {
    $detail = Get-WorkItemDetail $WorkItemId
    $item = [pscustomobject]@{
        Id = $WorkItemId; Ref = "#$WorkItemId"; RefPrefix = '#'; Url = (Get-WebUrl $WorkItemId); LinkUrlTemplate = (Get-WebUrl 0) -replace '0$', '{id}'
        SourceLabel = 'TFS'; Fields = $detail.Item.fields; Links = (Get-WorkItemLinks $detail.Item); Discussion = $detail.Discussion
    }
    $wi = Export-WorkItemMarkdown $item $Groups $Signature $maxFrameTerms (Join-Path $OutDir "tfs-$WorkItemId.md")
    Write-Host "#$WorkItemId [$($wi.State)] $($wi.Title)"
    Write-Host "TFS_ITEM_MD=$($wi.Path)"
    return $wi
}

# After the old TFS search (or its failure): the new ADO step if Nexus is installed, report section 2 from both sources,
# and the next step. The work items to confirm are printed once both searches are done.
function Complete-Stage2Step {
    $adoCfg = Get-Cfg $config 'ado' $null
    $nexus = Find-NexusAdo (Get-WorkspaceRoots $WorkspacePath $summary) $adoCfg
    Write-Host "NEXUS_ADO=$(Format-NexusAdoLine $nexus)"
    $adoStatusPath = Join-Path $OutDir 'ado-status.json'
    $adoStatus = if (Test-Path -LiteralPath $adoStatusPath) { [string](Get-Prop (Get-Content -LiteralPath $adoStatusPath -Raw -Encoding UTF8 | ConvertFrom-Json) 'status') } else { '' }
    $adoPending = $false
    if ($adoStatus -notin 'ok', 'skipped') {
        if ($nexus.Available) { Write-Stage2Status $OutDir 'ado' 'pending' $null "$($nexus.OrgUrl), project $($nexus.Project)"; $adoPending = $true }
        else { Write-Stage2Status $OutDir 'ado' 'not installed' "Nexus (azure-devops MCP) not found: $($nexus.Problem)" $null }
    }
    $r = Update-Stage2Report $summary $OutDir
    Write-Host "TFS_VERIFY_MD=$($r.SectionPath)"
    if ($r.Updated) { Write-Host "REPORT_UPDATED=$($r.ReportPath)" } else { Write-Host "REPORT_NOT_FOUND=$($r.ReportPath) (copy $($r.SectionPath) into section 2 of the report)" }
    $summaryPath = (Resolve-Path -LiteralPath $SummaryJson).Path
    if ($adoPending) {
        $extra = if ($Signature) { '-Signature "' + $Signature + '"' } else { '' }
        Write-Host "NEXT_STEP=Search the new ADO: $(Format-AdoSearchCommand $PSScriptRoot $summaryPath $nexus $extra)"
        return
    }
    Write-Stage2Result $r
    foreach ($f in $r.ConfirmFiles) { Write-Host "CONFIRM_ITEM=$f" }
    if ($r.Updated) { Write-Host "NEXT_STEP=Confirm the pre-verdicts: powershell -NoProfile -ExecutionPolicy Bypass -File `"$(Join-Path $PSScriptRoot 'Complete-CrashReport.ps1')`" -ReportPath `"$($r.ReportPath)`"" }
}

#endregion

#region main

$Term = @(Split-ListArgument $Term)
$workItemIds = @(foreach ($v in (Split-ListArgument $Id)) {
        $n = 0
        if (-not [int]::TryParse($v.TrimStart('#'), [ref]$n) -or $n -le 0) { throw "Invalid work item ID '$v'." }
        $n
    })
if (-not $SummaryJson -and -not $Term -and -not $workItemIds) { throw 'Pass -SummaryJson (search terms from a collector run), -Term, or -Id (work item details).' }
if ($Auto -and -not $SummaryJson) { throw '-Auto needs -SummaryJson.' }
$summary = $null
if ($SummaryJson) { $summary = Get-Content -LiteralPath $SummaryJson -Raw -Encoding UTF8 | ConvertFrom-Json }
if (-not $OutDir) { $OutDir = if ($SummaryJson) { Split-Path (Resolve-Path -LiteralPath $SummaryJson).Path -Parent } else { Join-Path $env:LOCALAPPDATA 'inmation-crash-analysis\tfs' } }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Write-Host "TFS: $baseUrl, project $project, work item types $($WorkItemType -join ', '), auth: $($script:auth.Mode)"

try {
    $groups = if ($summary) { Get-SignatureGroups $summary } else { [ordered]@{} }
    if ($workItemIds) {
        foreach ($wid in $workItemIds) {
            $wi = Export-WorkItem $wid $groups
            foreach ($sig in $wi.Evidence.Keys) { Write-Host "PRE_VERDICT=#$wid | $($wi.Evidence[$sig].Verdict) | $sig" }
        }
        exit 0
    }

    # Search mode: one term list per crash signature (plus -Term for all of them).
    $searches = @()
    if ($summary) {
        foreach ($sig in $groups.Keys) {
            $dumps = $groups[$sig].ToArray()
            if (-not (Test-SignatureSelected $sig $dumps $Signature)) { continue }
            $rep = Get-SignatureRepresentative $dumps
            if (-not $rep) { Write-Host "Skipping signature without verified symbols: $sig"; $searches += [pscustomobject]@{ Signature = $sig; Dumps = $dumps.Count; Blocked = $true; Terms = @() }; continue }
            $terms = @(Get-CrashTerms $rep $maxFrameTerms)
            if ($terms.Count -eq 0 -and -not $Term) { Write-Host "NO_DISTINCTIVE_TERMS=$sig" }
            foreach ($t in @($Term)) { if ($t) { $terms += [pscustomobject]@{ Text = $t; Kind = 'user term'; Weight = 2.0; Frame = $null } } }
            $searches += [pscustomobject]@{ Signature = $sig; Dumps = $dumps.Count; Blocked = $false; Terms = $terms }
        }
    }
    else {
        $searches += [pscustomobject]@{ Signature = '(user terms)'; Dumps = 0; Blocked = $false; Terms = @($Term | Where-Object { $_ } | ForEach-Object { [pscustomobject]@{ Text = $_; Kind = 'user term'; Weight = 2.0; Frame = $null } }) }
    }

    $termHits = @{}
    $out = @()
    foreach ($s in $searches) {
        if ($s.Blocked) { $out += [pscustomobject][ordered]@{ signature = $s.Signature; dumps = $s.Dumps; blocked = $true; terms = @(); candidates = @() }; continue }
        foreach ($t in $s.Terms) {
            $key = $t.Text.ToLowerInvariant()
            if ($termHits.ContainsKey($key)) { continue }
            $literal = $t.Text -replace "'", "''"
            $clauses = @($titleFields | ForEach-Object { "[$_] CONTAINS '$literal'" }) + @($textFields | ForEach-Object { "[$_] CONTAINS WORDS '$literal'" })
            Write-Host "Searching '$($t.Text)' ($($t.Kind)) ..."
            $termHits[$key] = @(Invoke-Wiql ($clauses -join ' OR '))
        }
        $entry = Get-SearchEntry $s.Signature $s.Dumps $s.Terms $termHits $maxHitsPerTerm $Top
        if (@($entry.candidates).Count -gt 0) {
            $byId = @{}
            foreach ($wi in @(Get-WorkItems @($entry.candidates | ForEach-Object { [int]$_.id }))) { $byId[[int]$wi.id] = $wi }
            foreach ($c in $entry.candidates) {
                $wi = $byId[[int]$c.id]
                $f = if ($wi) { $wi.fields } else { $null }
                foreach ($pair in @(@('type', 'System.WorkItemType'), @('title', 'System.Title'), @('state', 'System.State'), @('reason', 'System.Reason'), @('created', 'System.CreatedDate'), @('changed', 'System.ChangedDate'), @('iteration', 'System.IterationPath'), @('foundIn', 'Microsoft.VSTS.Build.FoundIn'), @('integratedIn', 'Microsoft.VSTS.Build.IntegrationBuild'), @('tags', 'System.Tags'))) {
                    $c | Add-Member -NotePropertyName $pair[0] -NotePropertyValue (Get-Field $f $pair[1])
                }
                $c | Add-Member -NotePropertyName 'url' -NotePropertyValue (Get-WebUrl ([int]$c.id))
            }
        }
        $out += $entry
    }

    $md = New-Object Text.StringBuilder
    [void]$md.AppendLine("# TFS search for existing work items")
    [void]$md.AppendLine("")
    [void]$md.AppendLine("- Server: $baseUrl, project $project; types: $($WorkItemType -join ', '); fields: $((@($titleFields) + @($textFields)) -join ', ')")
    [void]$md.AppendLine("- Candidates are ranked by matched terms only. Verify each with ``-Id <id> -SummaryJson <summary.json>`` before calling it the same bug.")
    foreach ($e in $out) {
        [void]$md.AppendLine("")
        [void]$md.AppendLine("## Signature: ``$($e.signature)`` ($($e.dumps) dump(s))")
        if ($e.blocked) { [void]$md.AppendLine(""); [void]$md.AppendLine("Not searched: symbols not verified (BLOCKED)."); continue }
        if (@($e.terms).Count -eq 0) {
            [void]$md.AppendLine("")
            [void]$md.AppendLine("Not searched: no distinctive term (only reporting / C++ exception-dispatch frames, and no thrown C++ exception decoded). Rerun with ``-Signature`` and ``-Term`` set to a distinctive function from the stack.")
            continue
        }
        [void]$md.AppendLine("")
        [void]$md.AppendLine("| Term | Source | Hits |"); [void]$md.AppendLine("|---|---|---|")
        foreach ($t in $e.terms) { [void]$md.AppendLine("| ``$($t.term)`` | $($t.kind) | $($t.hits)$(if ($t.tooGeneric) { ' (too generic, not scored)' }) |") }
        [void]$md.AppendLine("")
        if (@($e.candidates).Count -eq 0) { [void]$md.AppendLine("No work item matches any scored term."); continue }
        [void]$md.AppendLine("| Id | State | Title | Matched terms | Score | Created | Tags |"); [void]$md.AppendLine("|---|---|---|---|---|---|---|")
        foreach ($c in $e.candidates) {
            $titleText = ([string]$c.title) -replace '\|', '\|'
            $created = if ($c.created) { ([string]$c.created).Substring(0, [Math]::Min(10, ([string]$c.created).Length)) } else { '' }
            $matched = @($c.matchedTerms | ForEach-Object { '`' + $_ + '`' }) -join ', '
            $tags = ([string]$c.tags) -replace '\|', '\|'
            [void]$md.AppendLine("| [#$($c.id)]($($c.url)) | $($c.state) ($($c.reason)) | $titleText | $matched | $($c.score) | $created | $tags |")
        }
    }
    $mdPath = Join-Path $OutDir 'tfs-search.md'
    $jsonPath = Join-Path $OutDir 'tfs-search.json'
    Set-Content -LiteralPath $mdPath -Value $md.ToString() -Encoding UTF8
    ConvertTo-Json -InputObject @($out) -Depth 6 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
    if (-not $Auto) { Write-Host $md.ToString() }
    Write-Host "TFS_SEARCH_MD=$mdPath"
    Write-Host "TFS_SEARCH_JSON=$jsonPath"

    if ($Auto) {
        # Fetch the candidates worth verifying, compute pre-verdicts, follow duplicate/related links of matches once.
        $fetched = @{}
        $selected = @{}
        foreach ($e in @($out | Where-Object { -not $_.blocked })) {
            $selected[$e.signature] = @{}
            $queue = @(Select-CandidatesToVerify $e | ForEach-Object { [pscustomobject]@{ Id = [int]$_; Via = $null } })
            while ($queue.Count -gt 0) {
                $next = $queue[0]; $queue = @($queue | Select-Object -Skip 1)
                if ($selected[$e.signature].ContainsKey($next.Id)) { continue }
                $selected[$e.signature][$next.Id] = $next.Via
                if (-not $fetched.ContainsKey($next.Id)) { $fetched[$next.Id] = Export-WorkItem $next.Id $groups }
                $wi = $fetched[$next.Id]
                $pre = if ($wi.Evidence.ContainsKey($e.signature)) { $wi.Evidence[$e.signature] } else { $null }
                if (-not $next.Via -and $pre -and $pre.Verdict -match '^(same|likely same)') {
                    foreach ($l in @($wi.Links.WorkItems | Where-Object { $_.Name -match 'Duplicate|Related' } | Select-Object -First 3)) { $queue += [pscustomobject]@{ Id = [int]$l.Id; Via = $next.Id } }
                }
            }
        }
        $letters = Get-ReportGroupLetters $summary
        $verifyData = @(foreach ($e in @($out | Where-Object { -not $_.blocked })) {
                $rows = @(Get-VerifiedRows $e.signature $fetched $selected[$e.signature])
                foreach ($r in $rows) { Write-Host "PRE_VERDICT=#$($r.Id) | $($r.Verdict) | $($e.signature)" }
                [ordered]@{ signature = $e.signature; letter = $(if ($letters.ContainsKey($e.signature)) { $letters[$e.signature] } else { $null }); items = @($rows | ForEach-Object { ConvertTo-VerificationItem $fetched[[int]$_.Id] $_ 'tfs' }) }
            })
        Write-JsonFile (Join-Path $OutDir 'tfs-verification.json') $verifyData
        Write-Stage2Status $OutDir 'tfs' 'ok' $null "$baseUrl, project $project, types $($WorkItemType -join ', ')"
        Complete-Stage2Step
    }
}
catch [InvalidOperationException] {
    Write-Host "TFS_ERROR=$($_.Exception.Message)"
    if ($Auto -and $summary) {
        Write-Stage2Status $OutDir 'tfs' 'error' $_.Exception.Message "$baseUrl, project $project"
        Complete-Stage2Step
    }
    exit 2
}

#endregion
