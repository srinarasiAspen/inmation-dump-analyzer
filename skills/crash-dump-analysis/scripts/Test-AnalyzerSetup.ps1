<#
.SYNOPSIS
Checks whether this machine can run the crash dump analysis: debugger, configuration, build shares, local folders, source
repository, TFS access and (optional) Linux core dump tools.

.DESCRIPTION
Read-only except for creating the local work folders. Prints one line per check:
  CHECK=<name> | OK|WARN|FAIL | <detail>
and SETUP_OK or SETUP_FAIL=<count> at the end. FAIL means a stage cannot run; WARN limits it (e.g. no source = no stage 3).

.EXAMPLE
.\Test-AnalyzerSetup.ps1
.\Test-AnalyzerSetup.ps1 -RepoPath C:\git\inmation-services -SkipNetwork
#>
[CmdletBinding()]
param(
    [string]$RepoPath,
    [string]$ConfigPath,
    [switch]$SkipNetwork
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
foreach ($lib in 'Common', 'Cdb', 'BuildLookup', 'TfsAuth', 'Frames', 'LinuxCore', 'NexusAdo') { . (Join-Path $PSScriptRoot "lib\$lib.ps1") }

$script:failures = 0
function Write-Check([string]$Name, [string]$State, [string]$Detail) {
    if ($State -eq 'FAIL') { $script:failures++ }
    $color = switch ($State) { 'OK' { 'Green' } 'WARN' { 'Yellow' } default { 'Red' } }
    Write-Host "CHECK=$Name | $State | $Detail" -ForegroundColor $color
}

Write-Check 'powershell' $(if ($PSVersionTable.PSVersion.Major -ge 5) { 'OK' } else { 'FAIL' }) "version $($PSVersionTable.PSVersion)"

$config = $null
try {
    $info = Read-AnalyzerConfig $ConfigPath $PSScriptRoot
    $config = $info.Config
    Write-Check 'config' 'OK' ($info.Sources -join ' + ')
}
catch { Write-Check 'config' 'FAIL' $_.Exception.Message }
if (-not $config) { Write-Host "SETUP_FAIL=$script:failures"; exit 1 }

try {
    $cdb = Find-Cdb $config
    $ver = (Get-Item -LiteralPath $cdb).VersionInfo.ProductVersion
    Write-Check 'cdb' 'OK' "$cdb ($ver)"
    # Performance counters (perf-counter-analysis) are read with a cdb JavaScript extension.
    $jsProvider = Join-Path (Split-Path $cdb -Parent) 'winext\JsProvider.dll'
    if (Test-Path -LiteralPath $jsProvider) { Write-Check 'cdb-javascript' 'OK' $jsProvider }
    else { Write-Check 'cdb-javascript' 'WARN' "$jsProvider not found: performance counter analysis needs the JavaScript provider of a current Debugging Tools for Windows." }
}
catch { Write-Check 'cdb' 'FAIL' "$($_.Exception.Message) Install the Windows SDK 'Debugging Tools for Windows' (winget install Microsoft.WindowsSDK.10.0.26100, select Debugging Tools)." }

foreach ($key in 'workRoot', 'localSymbolCache', 'extractRoot') {
    $default = "$env:LOCALAPPDATA\inmation-crash-analysis\$key"
    $path = Expand-PathValue (Get-Cfg $config $key $default)
    try {
        New-Item -ItemType Directory -Force -Path $path | Out-Null
        $probe = Join-Path $path ".probe-$([Guid]::NewGuid().ToString('N'))"
        [IO.File]::WriteAllText($probe, ''); Remove-Item -LiteralPath $probe -Force
        $free = (New-Object IO.DriveInfo([IO.Path]::GetPathRoot((Resolve-Path -LiteralPath $path).Path))).AvailableFreeSpace / 1GB
        $state = if ($key -eq 'extractRoot' -and $free -lt 10) { 'WARN' } else { 'OK' }
        Write-Check $key $state ("{0} (free {1:N1} GB{2})" -f $path, $free, $(if ($state -eq 'WARN') { '; full dumps need about 1 GB each when extracted' } else { '' }))
    }
    catch { Write-Check $key 'FAIL' "$path not writable: $($_.Exception.Message)" }
}

if (-not $SkipNetwork) {
    foreach ($line in @(Get-Cfg $config 'productLines' @())) {
        $name = Get-Cfg $line 'name' 'line'
        foreach ($kind in 'releaseRoots', 'devRoots') {
            foreach ($root in @(Get-Cfg $line $kind @())) {
                $path = Expand-PathValue $root
                $ok = $false
                try { $ok = Test-Path -LiteralPath $path } catch { $ok = $false }
                Write-Check "share:$kind" $(if ($ok) { 'OK' } else { 'WARN' }) "$path ($name)$(if (-not $ok) { ' - not reachable: symbols for these builds must be passed with -PdbPath or lie next to the dump' })"
            }
        }
    }
}

try {
    $src = Resolve-SourceRepo $RepoPath $false $config
    if ($src.Repo) {
        $refs = @()
        foreach ($line in @(Get-Cfg $config 'productLines' @())) { $refs += Get-Cfg $line 'compareRef' $null }
        $refs = @($refs | Where-Object { $_ } | Select-Object -Unique)
        $missing = @($refs | Where-Object { (Invoke-Git $src.Repo @('rev-parse', '--verify', '--quiet', "$_^{commit}")).ExitCode -ne 0 })
        $fetchHead = Join-Path $src.Repo '.git\FETCH_HEAD'
        $age = if (Test-Path -LiteralPath $fetchHead) { [int]((Get-Date) - (Get-Item -LiteralPath $fetchHead).LastWriteTime).TotalDays } else { $null }
        $state = if ($missing.Count) { 'WARN' } else { 'OK' }
        Write-Check 'source' $state "$($src.Repo); compare refs $(if ($missing.Count) { "missing: $($missing -join ', ') (git fetch origin)" } else { "present: $($refs -join ', ')" }); last fetch $(if ($null -ne $age) { "$age day(s) ago" } else { 'unknown' })"
    }
    else { Write-Check 'source' 'WARN' "no source repository ($($src.Note)): stages 1 and 2 work, stage 3 needs a clone" }
}
catch { Write-Check 'source' 'WARN' $_.Exception.Message }

if (-not $SkipNetwork) {
    $tfs = Get-Cfg $config 'tfs' $null
    $url = ([string](Get-Cfg $tfs 'url' '')).TrimEnd('/')
    $project = [string](Get-Cfg $tfs 'project' '')
    $auth = Get-TfsAuth
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    try {
        $params = @{ Uri = "$url/_apis/projects/$([Uri]::EscapeDataString($project))?api-version=$(Get-Cfg $tfs 'apiVersion' '4.1')"; Method = 'Get'; Headers = $auth.Headers; TimeoutSec = 30; UseBasicParsing = $true }
        if ($auth.UseDefaultCredentials) { $params.UseDefaultCredentials = $true }
        $p = Invoke-RestMethod @params
        Write-Check 'tfs' 'OK' "$url project $($p.name) ($($auth.Mode))"
    }
    catch {
        $status = $null
        if ($_.Exception.PSObject.Properties['Response'] -and $_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
        $hint = switch ($status) { 401 { 'authentication failed: sign in with a domain account, or set TFS_PAT / ~/.config/inmation-ado/.env' } 403 { 'access denied to the project' } default { "not reachable: $($_.Exception.Message)" } }
        Write-Check 'tfs' 'WARN' "$url ($($auth.Mode)) - $hint. The old TFS search of stage 2 will not work."
    }
}

# The new ADO is searched by the agent through the azure-devops MCP server of a Nexus installation in the workspace.
try {
    $nexus = Find-NexusAdo (Get-WorkspaceRoots $RepoPath $null) (Get-Cfg $config 'ado' $null)
    if ($nexus.Available) { Write-Check 'nexus-ado' 'OK' "$($nexus.OrgUrl) project $($nexus.Project) via MCP server '$($nexus.Server)' ($($nexus.McpJson)$(if (-not $nexus.Nexus) { '; no Nexus agents found' }))" }
    else { Write-Check 'nexus-ado' 'WARN' "$($nexus.Problem) - stage 2 searches only the old TFS. Install Nexus in the workspace (setup-vscode-nexus-agents.js) to search the new ADO too." }
}
catch { Write-Check 'nexus-ado' 'WARN' $_.Exception.Message }

$gdbProblem = Test-WslGdb $config
if ($gdbProblem) { Write-Check 'linux-gdb' 'WARN' "$gdbProblem - only needed for Linux core dumps" }
else { Write-Check 'linux-gdb' 'OK' "WSL $(if (Get-WslDistroArgs $config) { "distribution $((Get-WslDistroArgs $config)[1])" } else { 'default distribution' }) with gdb" }
$docker = Get-Command docker -ErrorAction SilentlyContinue
if (-not $docker) { Write-Check 'linux-sysroot' 'WARN' 'docker not found - Linux cores then need -SysrootPath (executable and libraries of the image) to unwind' }
else {
    $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { & docker version --format '{{.Server.Version}}' *> $null; $dockerOk = $LASTEXITCODE -eq 0 } finally { $ErrorActionPreference = $eap }
    Write-Check 'linux-sysroot' $(if ($dockerOk) { 'OK' } else { 'WARN' }) $(if ($dockerOk) { "docker available; images: $(@(Get-Cfg (Get-Cfg $config 'linux' $null) 'images' @()) -join ', ')" } else { 'docker found but the engine is not running (start Docker Desktop) - only needed for Linux core dumps' })
}

if ($script:failures -eq 0) { Write-Host 'SETUP_OK' } else { Write-Host "SETUP_FAIL=$script:failures"; exit 1 }
