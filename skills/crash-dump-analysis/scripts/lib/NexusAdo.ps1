# New ADO (Azure DevOps Services) through the azure-devops MCP server that Nexus installs into a workspace
# (.vscode/mcp.json, package @azure-devops/mcp). The scripts cannot call the MCP server: they detect it, build the WIQL
# queries and the fetch list, and read back what the agent saved (query results file, work item JSON files).

# JSON with comments and trailing commas (VS Code mcp.json) -> object.
function ConvertFrom-JsoncText([string]$Text) {
    $sb = New-Object Text.StringBuilder
    $inString = $false; $escape = $false; $i = 0
    while ($i -lt $Text.Length) {
        $c = $Text[$i]
        if ($inString) {
            [void]$sb.Append($c)
            if ($escape) { $escape = $false } elseif ($c -eq '\') { $escape = $true } elseif ($c -eq '"') { $inString = $false }
            $i++; continue
        }
        if ($c -eq '"') { $inString = $true; [void]$sb.Append($c); $i++; continue }
        if ($c -eq '/' -and $i + 1 -lt $Text.Length -and $Text[$i + 1] -eq '/') { while ($i -lt $Text.Length -and $Text[$i] -ne "`n") { $i++ }; continue }
        if ($c -eq '/' -and $i + 1 -lt $Text.Length -and $Text[$i + 1] -eq '*') { $end = $Text.IndexOf('*/', $i + 2); $i = if ($end -lt 0) { $Text.Length } else { $end + 2 }; continue }
        if ($c -eq ',') {
            $j = $i + 1
            while ($j -lt $Text.Length -and [char]::IsWhiteSpace($Text[$j])) { $j++ }
            if ($j -lt $Text.Length -and ($Text[$j] -eq '}' -or $Text[$j] -eq ']')) { $i++; continue }
        }
        [void]$sb.Append($c); $i++
    }
    return ($sb.ToString() | ConvertFrom-Json)
}

# The azure-devops MCP server of a mcp.json, or $null: server name, organization URL, project, enabled domains.
function Get-AdoMcpServer([string]$McpJsonPath, $AdoConfig) {
    $package = [string](Get-Cfg $AdoConfig 'mcpPackage' '@azure-devops/mcp')
    $json = ConvertFrom-JsoncText ([IO.File]::ReadAllText($McpJsonPath))
    $servers = Get-Cfg $json 'servers' $null
    if (-not $servers) { $servers = Get-Cfg $json 'mcpServers' $null }
    if (-not $servers) { return $null }
    foreach ($p in $servers.PSObject.Properties) {
        $mcpArgs = @(Get-Cfg $p.Value 'args' @() | ForEach-Object { [string]$_ })
        $command = [string](Get-Cfg $p.Value 'command' '')
        $index = -1
        for ($i = 0; $i -lt $mcpArgs.Count; $i++) { if ($mcpArgs[$i] -match "^$([regex]::Escape($package))(@[^\s]*)?$") { $index = $i; break } }
        if ($index -lt 0 -and $command -notmatch [regex]::Escape($package)) { continue }
        $org = $null
        for ($i = $index + 1; $i -lt $mcpArgs.Count; $i++) { if (-not $mcpArgs[$i].StartsWith('-')) { $org = $mcpArgs[$i]; break } }
        if ($org -match '^\$\{') { $org = $null }
        $domains = @()
        for ($i = 0; $i -lt $mcpArgs.Count; $i++) {
            if ($mcpArgs[$i] -in '-d', '--domains') { for ($k = $i + 1; $k -lt $mcpArgs.Count -and -not $mcpArgs[$k].StartsWith('-'); $k++) { $domains += $mcpArgs[$k] } }
        }
        $serverEnv = Get-Cfg $p.Value 'env' $null
        $orgUrl = [string](Get-Cfg $serverEnv 'AZURE_DEVOPS_ORG_URL' '')
        if (-not $orgUrl -and $org) { $orgUrl = if ($org -match '^https?://') { $org } else { "https://dev.azure.com/$org" } }
        $project = [string](Get-Cfg $serverEnv 'AZURE_DEVOPS_PROJECT' '')
        if (-not $project) { $project = [string](Get-Cfg $serverEnv 'ado_mcp_project' '') }
        if ($project -match '^\$\{') { $project = '' }
        if ($orgUrl -match '\$\{') { $orgUrl = '' }
        return [pscustomobject]@{ Server = $p.Name; OrgUrl = $orgUrl.TrimEnd('/'); Project = $project; Domains = $domains; McpJson = $McpJsonPath }
    }
    return $null
}

# Finds the azure-devops MCP server of a Nexus installation. $Roots: workspace folders (their .vscode/mcp.json, and
# .github/agents/nexus-*.agent.md for the Nexus marker); then the user-level mcp.json of VS Code. Config ado.organizationUrl
# and ado.project override the values from mcp.json.
function Find-NexusAdo([string[]]$Roots, $AdoConfig, [string[]]$UserMcpFiles) {
    if ($null -eq $UserMcpFiles) {
        $UserMcpFiles = @(if ($env:APPDATA -and (Get-Cfg $AdoConfig 'userMcpConfig' $true)) { Join-Path $env:APPDATA 'Code\User\mcp.json'; Join-Path $env:APPDATA 'Code - Insiders\User\mcp.json' })
    }
    $candidates = @()
    foreach ($r in @($Roots | Where-Object { $_ } | Select-Object -Unique)) { $candidates += [pscustomobject]@{ Root = $r; Path = (Join-Path $r '.vscode\mcp.json') } }
    foreach ($f in @($UserMcpFiles | Where-Object { $_ })) { $candidates += [pscustomobject]@{ Root = $null; Path = $f } }
    $notes = @()
    foreach ($c in $candidates) {
        if (-not (Test-Path -LiteralPath $c.Path)) { continue }
        $server = $null
        try { $server = Get-AdoMcpServer $c.Path $AdoConfig } catch { $notes += "$($c.Path): $($_.Exception.Message)"; continue }
        if (-not $server) { continue }
        $nexus = [bool]($c.Root -and (@(Get-ChildItem -LiteralPath (Join-Path $c.Root '.github\agents') -Filter 'nexus-*.agent.md' -ErrorAction SilentlyContinue).Count -or (Test-Path -LiteralPath (Join-Path $c.Root '.nexus'))))
        $orgUrl = [string](Get-Cfg $AdoConfig 'organizationUrl' ''); if (-not $orgUrl) { $orgUrl = $server.OrgUrl }
        $project = [string](Get-Cfg $AdoConfig 'project' ''); if (-not $project) { $project = $server.Project }
        $usable = (@($server.Domains).Count -eq 0) -or (@($server.Domains | Where-Object { $_ -in 'all', 'work-items' }).Count -gt 0)
        $problem = if (-not $usable) { "the server enables only the domains $($server.Domains -join ', ') (needs work-items)" } elseif (-not $orgUrl) { 'no organization in mcp.json (set ado.organizationUrl)' } elseif (-not $project) { 'no project in mcp.json (set ado.project)' } else { $null }
        return [pscustomobject]@{ Available = (-not $problem); Problem = $problem; Server = $server.Server; OrgUrl = $orgUrl.TrimEnd('/'); Project = $project; Domains = $server.Domains; McpJson = $c.Path; Root = $c.Root; Nexus = $nexus }
    }
    $where = @($candidates | ForEach-Object { $_.Path }) -join ', '
    return [pscustomobject]@{ Available = $false; Problem = "no @azure-devops/mcp server in $where$(if ($notes.Count) { " ($($notes -join '; '))" })"; Server = $null; OrgUrl = $null; Project = $null; Domains = @(); McpJson = $null; Root = $null; Nexus = $false }
}

function Get-AdoWorkItemUrl([string]$OrgUrl, [string]$Project, [int]$Id) {
    return "$($OrgUrl.TrimEnd('/'))/$([Uri]::EscapeDataString($Project))/_workitems/edit/$Id"
}

# Folders that may hold the Nexus installation: -WorkspacePath, the current directory and its git root, the source
# repository of the run (summary.json 'repo').
function Get-WorkspaceRoots([string]$WorkspacePath, $Summary) {
    $roots = @()
    if ($WorkspacePath) { $roots += (Resolve-Path -LiteralPath $WorkspacePath).Path }
    $cwd = (Get-Location).ProviderPath
    $roots += $cwd
    if (Get-Command git -ErrorAction SilentlyContinue) {
        $top = Invoke-Git $cwd @('rev-parse', '--show-toplevel')
        if ($top.ExitCode -eq 0 -and $top.Lines) { $roots += ($top.Lines[0] -replace '/', '\') }
    }
    $repo = [string](Get-Cfg $Summary 'repo' '')
    if ($repo) { $roots += $repo }
    return , @($roots | Where-Object { $_ } | Select-Object -Unique)
}

function Format-AdoSearchCommand([string]$ScriptsDir, [string]$SummaryJson, $Nexus, [string]$Extra = '') {
    $cmd = "powershell -NoProfile -ExecutionPolicy Bypass -File `"$(Join-Path $ScriptsDir 'Search-AdoCrashBugs.ps1')`" -SummaryJson `"$SummaryJson`""
    if ($Nexus -and $Nexus.Root) { $cmd += " -WorkspacePath `"$($Nexus.Root)`"" }
    if ($Extra) { $cmd += " $Extra" }
    return $cmd
}

function Format-NexusAdoLine($Nexus) {
    if ($Nexus.Available) { return "available | server $($Nexus.Server) | $($Nexus.OrgUrl) | project $($Nexus.Project) | $($Nexus.McpJson)$(if (-not $Nexus.Nexus) { ' (azure-devops MCP without Nexus agents)' })" }
    return "not installed ($($Nexus.Problem))"
}

function ConvertTo-WiqlString([string]$Value) { return "'" + ($Value -replace "'", "''") + "'" }

# Restriction of the new ADO search: work item types, product families and area paths from the config.
function Get-AdoScopeClause($AdoConfig) {
    $clauses = @()
    $types = @(Get-Cfg $AdoConfig 'workItemTypes' @('Bug') | Where-Object { $_ })
    if ($types.Count) { $clauses += "[System.WorkItemType] IN ($(@($types | ForEach-Object { ConvertTo-WiqlString $_ }) -join ', '))" }
    $families = @(Get-Cfg $AdoConfig 'productFamilies' @() | Where-Object { $_ })
    $field = [string](Get-Cfg $AdoConfig 'productFamilyField' 'Product Family')
    if ($families.Count -and $field) { $clauses += "[$field] IN ($(@($families | ForEach-Object { ConvertTo-WiqlString $_ }) -join ', '))" }
    $areas = @(Get-Cfg $AdoConfig 'areaPaths' @() | Where-Object { $_ })
    if ($areas.Count) { $clauses += '(' + (@($areas | ForEach-Object { "[System.AreaPath] UNDER $(ConvertTo-WiqlString $_)" }) -join ' OR ') + ')' }
    return ($clauses -join ' AND ')
}

function Get-AdoScopeText($AdoConfig) {
    $parts = @("types $(@(Get-Cfg $AdoConfig 'workItemTypes' @('Bug')) -join ' / ')")
    $families = @(Get-Cfg $AdoConfig 'productFamilies' @() | Where-Object { $_ })
    if ($families.Count) { $parts += "$(Get-Cfg $AdoConfig 'productFamilyField' 'Product Family') $($families -join ' / ')" }
    $areas = @(Get-Cfg $AdoConfig 'areaPaths' @() | Where-Object { $_ })
    if ($areas.Count) { $parts += "areas $($areas -join ' / ')" }
    return ($parts -join ', ')
}

# Why a fetched work item is outside the configured scope (type not in ado.workItemTypes, area not under one of
# ado.areaPaths), or $null. The queries are scoped, but linked items and IDs the agent wrote may not be. A field that
# is missing in the saved result is not held against the item.
function Get-AdoOutOfScopeReason($Fields, $AdoConfig) {
    $types = @(Get-Cfg $AdoConfig 'workItemTypes' @('Bug') | Where-Object { $_ } | ForEach-Object { [string]$_ })
    $type = [string](Get-Field $Fields 'System.WorkItemType')
    if ($type -and $types.Count -and -not @($types | Where-Object { $_ -ieq $type }).Count) { return "type '$type' is not $($types -join ' / ')" }
    $areas = @(Get-Cfg $AdoConfig 'areaPaths' @() | Where-Object { $_ } | ForEach-Object { ([string]$_).TrimEnd('\') })
    $area = [string](Get-Field $Fields 'System.AreaPath')
    if ($area -and $areas.Count -and -not @($areas | Where-Object { $area -ieq $_ -or $area.StartsWith("$_\", [StringComparison]::OrdinalIgnoreCase) }).Count) { return "area '$area' is not under $($areas -join ' / ')" }
    return $null
}

# One query per search term: title substring or full-text match of the text fields, within the configured scope.
function New-AdoTermWiql([string]$Term, $AdoConfig) {
    $literal = $Term -replace "'", "''"
    $titleFields = @(Get-Cfg $AdoConfig 'titleFields' @('System.Title'))
    $textFields = @(Get-Cfg $AdoConfig 'textFields' @('Microsoft.VSTS.TCM.ReproSteps', 'System.Description', 'Microsoft.VSTS.TCM.SystemInfo', 'System.History'))
    $match = @($titleFields | ForEach-Object { "[$_] CONTAINS '$literal'" }) + @($textFields | ForEach-Object { "[$_] CONTAINS WORDS '$literal'" })
    $scope = Get-AdoScopeClause $AdoConfig
    return "SELECT [System.Id] FROM WorkItems WHERE [System.TeamProject] = @project$(if ($scope) { " AND $scope" }) AND ($($match -join ' OR ')) ORDER BY [System.Id] DESC"
}

# '## <key>' headings and their text (the answers-file format of Complete-CrashReport.ps1).
function Read-KeyedAnswers([string]$Path) {
    $answers = [ordered]@{}
    if (-not (Test-Path -LiteralPath $Path)) { return $answers }
    $key = $null; $buffer = New-Object Collections.Generic.List[string]
    foreach ($line in [IO.File]::ReadAllLines((Resolve-Path -LiteralPath $Path).Path)) {
        if ($line -match '^##\s+(\S+)') {
            if ($key) { $answers[$key] = ($buffer -join "`n").Trim() }
            $key = $Matches[1]; $buffer = New-Object Collections.Generic.List[string]
            continue
        }
        if ($key -and $line -notmatch '^\s*<!--') { $buffer.Add($line) }
    }
    if ($key) { $answers[$key] = ($buffer -join "`n").Trim() }
    return $answers
}

# Answer of one query: $null (open), or Ids plus TooMany. Accepts '123, 456', 'AB#123', 'none', 'too many'.
function ConvertFrom-AdoQueryAnswer([string]$Text) {
    if (-not $Text -or $Text -match '(?m)^\s*TODO\b') { return $null }
    $ids = @([regex]::Matches($Text, '(?<![\w.-])(?:AB)?#?(\d{1,9})(?![\w.-])') | ForEach-Object { [int]$_.Groups[1].Value } | Select-Object -Unique)
    $tooMany = $Text -match '(?i)too many|more than'
    if ($ids.Count -eq 0 -and -not $tooMany -and $Text -notmatch '(?i)\b(none|no (work )?items?|0 (work )?items?|empty)\b') { return $null }
    return [pscustomobject]@{ Ids = $ids; TooMany = [bool]$tooMany }
}

# A work item (or the comments of one) as saved by the agent from an MCP tool result: the JSON text, optionally wrapped
# in the MCP's spotlight delimiters ('<<nonce>> [UNTRUSTED ... CONTENT ...] <<nonce>>' ... '<</nonce>>'), other text or a
# code fence. Returns the parsed object or throws with a short reason.
function ConvertFrom-McpJsonText([string]$Text) {
    if (-not $Text -or -not $Text.Trim()) { throw 'the file is empty' }
    $clean = [regex]::Replace($Text, '(?m)^\s*<</?[0-9a-fA-F]{8,}>>.*$', '')
    $starts = @([regex]::Matches($clean, '(?m)^\s*[\[{]') | ForEach-Object { $_.Index + $_.Length - 1 })
    if ($starts.Count -eq 0) { $starts = @([regex]::Matches($clean, '[\[{]') | Select-Object -First 5 | ForEach-Object { $_.Index }) }
    if ($starts.Count -eq 0) { throw 'no JSON object in the file' }
    $problem = $null
    foreach ($start in @($starts | Select-Object -First 5)) {
        $close = if ($clean[$start] -eq '{') { '}' } else { ']' }
        $end = $clean.LastIndexOf($close)
        if ($end -le $start) { $problem = 'the JSON is cut off (no closing bracket)'; continue }
        try { return ($clean.Substring($start, $end - $start + 1) | ConvertFrom-Json) }
        catch { $problem = "invalid JSON: $($_.Exception.Message -replace '\s+', ' ')" }
    }
    throw $problem
}

# The work item from a saved 'get' result ({id, fields, relations}); also accepts a batch ({value: [...]}, [...]).
function Get-AdoWorkItemFromJson($Json, [int]$Id) {
    $list = @(if ($Json -is [array]) { $Json } elseif (Get-Cfg $Json 'value' $null) { @(Get-Cfg $Json 'value' @()) } else { $Json })
    foreach ($w in $list) { if ($w -and [int](Get-Cfg $w 'id' 0) -eq $Id -and (Get-Cfg $w 'fields' $null)) { return $w } }
    return $null
}

# Discussion entries from a saved 'list_comments' result ({comments: [...]}) or the System.History of the item.
function Get-AdoDiscussion($CommentsJson, $WorkItem) {
    $entries = @()
    $comments = @(if ($CommentsJson -is [array]) { $CommentsJson } else { Get-Cfg $CommentsJson 'comments' @() })
    foreach ($c in $comments) {
        if (-not $c) { continue }
        $text = ConvertFrom-Html ([string](Get-Cfg $c 'text' ''))
        if (-not $text) { continue }
        $entries += [pscustomobject]@{ Date = [string](Get-Cfg $c 'createdDate' ''); By = Get-DisplayName (Get-Cfg $c 'createdBy' $null); Text = $text }
    }
    if ($entries.Count -eq 0 -and $WorkItem) {
        $history = ConvertFrom-Html ([string](Get-Field (Get-Cfg $WorkItem 'fields' $null) 'System.History'))
        if ($history) { $entries += [pscustomobject]@{ Date = [string](Get-Field (Get-Cfg $WorkItem 'fields' $null) 'System.ChangedDate'); By = Get-DisplayName (Get-Field (Get-Cfg $WorkItem 'fields' $null) 'System.ChangedBy'); Text = $history } }
    }
    return , @($entries | Sort-Object { $_.Date })
}
