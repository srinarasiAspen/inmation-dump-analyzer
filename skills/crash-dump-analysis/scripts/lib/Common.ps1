# Shared helpers: configuration access, path/template expansion, git, hashing, masking.

function Get-Cfg($Object, [string]$Name, $Default) {
    if ($null -ne $Object -and $Object.PSObject.Properties[$Name]) { return $Object.PSObject.Properties[$Name].Value }
    return $Default
}

function Expand-PathValue([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }
    return [Environment]::ExpandEnvironmentVariables($Value)
}

function Expand-Template([string]$Template, [hashtable]$Vars) {
    $result = $Template
    foreach ($key in $Vars.Keys) { $result = $result.Replace('{' + $key + '}', [string]$Vars[$key]) }
    return $result
}

function Invoke-Git([string]$Repo, [string[]]$GitArgs) {
    # No-source mode: never fall back to the current directory (git -C '' would use it).
    if (-not $Repo) { return [pscustomobject]@{ ExitCode = 128; Lines = @() } }
    $eap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = & git -C $Repo @GitArgs 2>$null
        $code = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $eap }
    return [pscustomobject]@{ ExitCode = $code; Lines = @($out | ForEach-Object { "$_" }) }
}

# Objects merge recursively, everything else (values, arrays) is replaced by the override.
function Merge-ConfigObject($Base, $Override) {
    if ($null -eq $Base) { return $Override }
    if ($null -eq $Override) { return $Base }
    if ($Base -isnot [Management.Automation.PSCustomObject] -or $Override -isnot [Management.Automation.PSCustomObject]) { return $Override }
    $result = [pscustomobject]@{}
    foreach ($p in $Base.PSObject.Properties) { $result | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value }
    foreach ($p in $Override.PSObject.Properties) {
        if ($p.Name.StartsWith('_')) { continue }
        $merged = if ($result.PSObject.Properties[$p.Name]) { Merge-ConfigObject $result.PSObject.Properties[$p.Name].Value $p.Value } else { $p.Value }
        $result | Add-Member -NotePropertyName $p.Name -NotePropertyValue $merged -Force
    }
    return $result
}

# Settings: the explicit -ConfigPath, else CRASH_DUMP_ANALYZER_CONFIG, else the default next to the scripts. A user override
# file (%LOCALAPPDATA%\inmation-crash-analysis\config.json) is merged on top, so local changes survive plugin updates.
function Read-AnalyzerConfig([string]$ConfigPath, [string]$ScriptRoot) {
    $base = if ($ConfigPath) { $ConfigPath } elseif ($env:CRASH_DUMP_ANALYZER_CONFIG) { $env:CRASH_DUMP_ANALYZER_CONFIG } else { Join-Path $ScriptRoot 'crash-dump-analyzer.config.json' }
    if (-not (Test-Path -LiteralPath $base)) { throw "Configuration not found: $base" }
    $config = Get-Content -LiteralPath $base -Raw | ConvertFrom-Json
    $sources = @((Resolve-Path -LiteralPath $base).Path)
    $userFile = Join-Path (Join-Path $env:LOCALAPPDATA 'inmation-crash-analysis') 'config.json'
    if (-not $ConfigPath -and (Test-Path -LiteralPath $userFile)) {
        $config = Merge-ConfigObject $config (Get-Content -LiteralPath $userFile -Raw | ConvertFrom-Json)
        $sources += $userFile
    }
    return [pscustomobject]@{ Config = $config; Sources = $sources }
}

function Test-SourceRepoMarkers([string]$Repo, $Config) {
    $markers = @(Get-Cfg (Get-Cfg $Config 'sourceRepo' $null) 'markers' @('server/inmation'))
    foreach ($m in $markers) { if (-not (Test-Path -LiteralPath (Join-Path $Repo $m))) { return $false } }
    return $true
}

# The product source is a clone of the inmation server repository: -RepoPath, else CRASH_DUMP_ANALYZER_REPO, else the git
# repository of the current directory if it has the configured marker folders. The plugin's own repository never counts.
function Resolve-SourceRepo([string]$RepoPath, [bool]$NoSource, $Config) {
    if ($NoSource) { return [pscustomobject]@{ Repo = $null; Note = 'disabled with -NoSource' } }
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) { return [pscustomobject]@{ Repo = $null; Note = 'git is not installed' } }
    $explicit = if ($RepoPath) { $RepoPath } elseif ($env:CRASH_DUMP_ANALYZER_REPO) { $env:CRASH_DUMP_ANALYZER_REPO } else { $null }
    if ($explicit) {
        $top = Invoke-Git $explicit @('rev-parse', '--show-toplevel')
        if ($top.ExitCode -ne 0 -or -not $top.Lines) { throw "Not a git repository: $explicit" }
        $path = $top.Lines[0] -replace '/', '\'
        if (-not (Test-SourceRepoMarkers $path $Config)) { throw "$path is not a clone of the inmation server repository (missing $(@(Get-Cfg (Get-Cfg $Config 'sourceRepo' $null) 'markers' @('server/inmation')) -join ', '))." }
        return [pscustomobject]@{ Repo = $path; Note = $null }
    }
    $top = Invoke-Git (Get-Location).ProviderPath @('rev-parse', '--show-toplevel')
    if ($top.ExitCode -ne 0 -or -not $top.Lines) { return [pscustomobject]@{ Repo = $null; Note = 'the current directory is not inside a git clone of the inmation server repository; pass -RepoPath' } }
    $path = $top.Lines[0] -replace '/', '\'
    if (-not (Test-SourceRepoMarkers $path $Config)) { return [pscustomobject]@{ Repo = $null; Note = "the current repository ($path) is not the inmation server repository; pass -RepoPath" } }
    return [pscustomobject]@{ Repo = $path; Note = $null }
}

# Version of the plugin (plugin.json at the plugin root, three levels above the scripts folder).
function Get-ToolVersion([string]$ScriptRoot) {
    $manifest = Join-Path $ScriptRoot '..\..\..\plugin.json'
    if (Test-Path -LiteralPath $manifest) {
        try { return [string](Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json).version } catch { }
    }
    return 'dev'
}

function Get-ExceptionName([uint32]$Code) {
    $names = @{
        0xC0000005L = 'ACCESS_VIOLATION'; 0xC00000FDL = 'STACK_OVERFLOW'; 0xC0000374L = 'HEAP_CORRUPTION'
        0xC0000409L = 'STACK_BUFFER_OVERRUN / FAIL_FAST'; 0xE06D7363L = 'C++ EXCEPTION'; 0x80000003L = 'BREAKPOINT'
        0xC0000094L = 'INTEGER_DIVIDE_BY_ZERO'; 0xC000001DL = 'ILLEGAL_INSTRUCTION'; 0xC0000006L = 'IN_PAGE_ERROR'
        0xC0000017L = 'NO_MEMORY'; 0xC0000420L = 'ASSERTION_FAILURE'; 0x40000015L = 'FATAL_APP_EXIT (abort)'
        0xC0000008L = 'INVALID_HANDLE'; 0xC000041DL = 'FATAL_USER_CALLBACK_EXCEPTION'
    }
    $key = [long]$Code
    if ($names.ContainsKey($key)) { return $names[$key] }
    return 'UNKNOWN'
}

# Subcodes of __fastfail (winnt.h FAST_FAIL_*), passed as the first parameter of 0xC0000409.
function Get-FailFastName([uint64]$SubCode) {
    $names = @{
        0 = 'LEGACY_GS_VIOLATION'; 1 = 'VTGUARD_CHECK_FAILURE'; 2 = 'STACK_COOKIE_CHECK_FAILURE'; 3 = 'CORRUPT_LIST_ENTRY'
        4 = 'INCORRECT_STACK'; 5 = 'INVALID_ARG'; 6 = 'GS_COOKIE_INIT'; 7 = 'FATAL_APP_EXIT'; 8 = 'RANGE_CHECK_FAILURE'
        9 = 'UNSAFE_REGISTRY_ACCESS'; 10 = 'GUARD_ICALL_CHECK_FAILURE'; 11 = 'GUARD_WRITE_CHECK_FAILURE'; 12 = 'INVALID_FIBER_SWITCH'
        13 = 'INVALID_SET_OF_CONTEXT'; 14 = 'INVALID_REFERENCE_COUNT'; 18 = 'INVALID_JUMP_BUFFER'; 19 = 'MRDATA_MODIFIED'
        21 = 'INVALID_EXCEPTION_CHAIN'; 37 = 'GUARD_JUMPTABLE'; 38 = 'INVALID_LONGJUMP_TARGET'; 44 = 'GUARD_SS_FAILURE'
        50 = 'HEAP_METADATA_CORRUPTION'
    }
    if ($SubCode -le [int]::MaxValue -and $names.ContainsKey([int]$SubCode)) { return 'FAST_FAIL_' + $names[[int]$SubCode] }
    return "FAST_FAIL subcode $SubCode"
}

function Get-FailFastLabel([uint64]$SubCode) {
    switch ($SubCode) {
        0 { return 'STACK_BUFFER_OVERRUN (/GS cookie, FAST_FAIL_LEGACY_GS_VIOLATION)' }
        2 { return 'STACK_BUFFER_OVERRUN (/GS cookie, FAST_FAIL_STACK_COOKIE_CHECK_FAILURE)' }
        7 { return 'ABORT (FAST_FAIL_FATAL_APP_EXIT: abort()/assert/terminate - not a buffer overrun)' }
        5 { return 'FAIL_FAST INVALID_ARG (CRT invalid parameter handler)' }
        default { return "FAIL_FAST ($(Get-FailFastName $SubCode))" }
    }
}

$script:sha256Cache = @{}

function Get-StreamSha256([IO.Stream]$Stream) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Stream)) -replace '-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-FileSha256([string]$Path) {
    $key = $Path.ToLowerInvariant()
    if (-not $script:sha256Cache.ContainsKey($key)) {
        $fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        try { $script:sha256Cache[$key] = Get-StreamSha256 $fs } finally { $fs.Dispose() }
    }
    return $script:sha256Cache[$key]
}

# Masks values of credential-like assignments in script text recovered from memory.
function Protect-ScriptText([string]$Text) {
    return [regex]::Replace($Text, '(?i)((?:password|passwd|pwd|secret|token|api_?key|credential)\w*\s*["'']?\]?\s*[=:]\s*)(["''])((?:(?!\2)[^\r\n])*)\2', '$1$2***masked***$2')
}

function Format-Duration([TimeSpan]$Span) {
    if ($Span.TotalDays -ge 1) { return '{0}d {1:hh\:mm\:ss}' -f [int][Math]::Floor($Span.TotalDays), $Span }
    return '{0:hh\:mm\:ss}' -f $Span
}
