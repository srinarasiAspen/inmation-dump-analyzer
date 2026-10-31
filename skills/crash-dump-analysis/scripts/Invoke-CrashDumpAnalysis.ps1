<#
.SYNOPSIS
Collects deterministic crash facts from Windows minidumps of inmation binaries.

.DESCRIPTION
For every dump (zip archives containing dumps are extracted first; byte-identical dumps - same SHA-256 - are
analyzed once and their other copies are listed as provenance; PDBs bundled in the input zips are used when their
GUID matches) the script:
  1. Reads the crashing binary's file version, PDB identity (GUID/age) and the process uptime directly
     from the dump.
  2. Finds the build folder that holds this exact binary - unbranded or branded (aspen, plantweb, ...) -
     by comparing the CodeView GUID of the binary on the share, then fetches the matching PDB
     (symbols.zip) into a local cache and verifies its GUID, so mismatched symbols are never used.
     A dump without verified private symbols is marked BLOCKED: it gets only raw facts (exception,
     module+RVA addresses), no function-based signature, build commit or source mapping. Other dumps
     of the same run are not affected.
  3. Runs cdb (!analyze, exception record/context, crashing stack with source lines, disassembly,
     locals, all thread stacks) and labels fail-fast subcodes and assertion/abort frames.
  4. Determines the source commit the binary was built from and maps the crashing frames to repository
     files (or to vcpkg ports for third-party frames), including the source lines at that commit and the
     later history of those files on the comparison ref.
  5. If Lua or a configured script entry frame is on the stack, runs a second cdb pass that walks the Lua
     call chain and extracts the script and request (credentials masked). For frames in libraries stored
     in the model ('@<path>#<library>'), it reads the function prototypes (upvalue, local and constant
     names) and recovers the library text from process memory, validated against the prototypes' lines.

Results are written to <workRoot>\<timestamp>\summary.json (plus raw cdb logs) and the path is
printed as SUMMARY_JSON=<path>. Settings come from crash-dump-analyzer.config.json.

.EXAMPLE
.\Invoke-CrashDumpAnalysis.ps1 -DumpPath C:\dumps\inmation.exe.11664.dmp

.EXAMPLE
.\Invoke-CrashDumpAnalysis.ps1 -DumpPath \\server\crashes\customerX -PdbPath C:\sym\inmation.pdb -SkipFetch

.PARAMETER NoSource
Skips everything that needs the git repository (build commit estimation, source lines, file history, vcpkg ports).
This mode is also used automatically when the script does not run from a git clone or git is not installed.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$DumpPath,
    [string]$ConfigPath,
    [string]$PdbPath,
    [string]$RepoPath,
    [string]$OutDir,
    [switch]$Recurse,
    [switch]$SkipFetch,
    [switch]$NoSource
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem

#region helpers

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

#endregion

#region minidump / pdb parsing

function Read-MinidumpInfo([string]$Path) {
    $fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
        $br = New-Object IO.BinaryReader($fs)
        if ($br.ReadUInt32() -ne 0x504D444D) { throw "Not a minidump (MDMP signature missing): $Path" }
        $null = $br.ReadUInt32()
        $streamCount = $br.ReadUInt32()
        $dirRva = $br.ReadUInt32()
        $null = $br.ReadUInt32()
        $dumpTime = $br.ReadUInt32()

        $streams = @{}
        for ($i = 0; $i -lt $streamCount; $i++) {
            $fs.Position = [int64]$dirRva + 12 * $i
            $type = [int]$br.ReadUInt32(); $size = $br.ReadUInt32(); $rva = $br.ReadUInt32()
            if ($type -ne 0 -and -not $streams.ContainsKey($type)) { $streams[$type] = @{ Size = $size; Rva = $rva } }
        }

        $arch = $null
        if ($streams.ContainsKey(7)) {
            $fs.Position = $streams[7].Rva
            $archId = $br.ReadUInt16()
            $arch = switch ($archId) { 0 { 'x86' } 5 { 'arm' } 9 { 'x64' } 12 { 'arm64' } default { "unknown($archId)" } }
        }

        $processId = $null
        $processCreateTime = $null
        if ($streams.ContainsKey(15)) {
            # MINIDUMP_MISC_INFO: SizeOfInfo, Flags1, ProcessId, ProcessCreateTime, ...
            $fs.Position = $streams[15].Rva + 4
            $miscFlags = $br.ReadUInt32()
            $pidValue = $br.ReadUInt32()
            $createValue = $br.ReadUInt32()
            if ($miscFlags -band 1) { $processId = $pidValue }
            if (($miscFlags -band 2) -and $createValue -gt 0) { $processCreateTime = $createValue }
        }

        $exception = $null
        if ($streams.ContainsKey(6)) {
            $fs.Position = $streams[6].Rva
            $threadId = $br.ReadUInt32(); $null = $br.ReadUInt32()
            $code = $br.ReadUInt32(); $flags = $br.ReadUInt32(); $null = $br.ReadUInt64()
            $address = $br.ReadUInt64(); $paramCount = $br.ReadUInt32(); $null = $br.ReadUInt32()
            $params = @()
            $rawParams = @()
            for ($j = 0; $j -lt 15; $j++) {
                $value = $br.ReadUInt64()
                if ($j -lt $paramCount) { $params += ('0x{0:X}' -f $value); $rawParams += $value }
            }
            $access = $null
            if (($code -eq 3221225477 -or $code -eq 3221225478) -and $rawParams.Count -ge 2) {
                $kind = switch ([int]$rawParams[0]) { 0 { 'read from' } 1 { 'write to' } 8 { 'execute (DEP) at' } default { "access type $($rawParams[0]) at" } }
                $access = '{0} 0x{1:X}' -f $kind, $rawParams[1]
            }
            $name = Get-ExceptionName $code
            $failFastCode = $null
            $failFastName = $null
            if ($code -eq 3221226505 -and $rawParams.Count -ge 1) {
                $failFastCode = $rawParams[0]
                $failFastName = Get-FailFastName $rawParams[0]
                $name = Get-FailFastLabel $rawParams[0]
            }
            $exception = [ordered]@{
                threadId     = $threadId
                code         = ('0x{0:X8}' -f $code)
                name         = $name
                failFastCode = $failFastCode
                failFastName = $failFastName
                flags        = ('0x{0:X}' -f $flags)
                address      = ('0x{0:X16}' -f $address)
                access       = $access
                parameters   = $params
            }
        }

        $modules = @()
        if ($streams.ContainsKey(4)) {
            $fs.Position = $streams[4].Rva
            $moduleCount = $br.ReadUInt32()
            for ($i = 0; $i -lt $moduleCount; $i++) {
                $offset = [int64]$streams[4].Rva + 4 + 108 * $i
                $fs.Position = $offset
                $base = $br.ReadUInt64(); $imageSize = $br.ReadUInt32(); $null = $br.ReadUInt32()
                $timeStamp = $br.ReadUInt32(); $nameRva = $br.ReadUInt32()
                $vsSignature = $br.ReadUInt32(); $null = $br.ReadUInt32()
                $fileVersionMS = $br.ReadUInt32(); $fileVersionLS = $br.ReadUInt32()
                $productVersionMS = $br.ReadUInt32(); $productVersionLS = $br.ReadUInt32()
                $fs.Position = $offset + 76
                $cvSize = $br.ReadUInt32(); $cvRva = $br.ReadUInt32()

                $fs.Position = $nameRva
                $nameLength = $br.ReadUInt32()
                $modulePath = [Text.Encoding]::Unicode.GetString($br.ReadBytes([int]$nameLength))

                # File version drives all routing; the product version (e.g. 1.3 for OT Data Fabric 26.x) is informational only.
                $version = $null
                $productVersion = $null
                if ($vsSignature -eq 4277077181) {
                    $version = '{0}.{1}.{2}.{3}' -f ($fileVersionMS -shr 16), ($fileVersionMS -band 0xFFFF), ($fileVersionLS -shr 16), ($fileVersionLS -band 0xFFFF)
                    $productVersion = '{0}.{1}.{2}.{3}' -f ($productVersionMS -shr 16), ($productVersionMS -band 0xFFFF), ($productVersionLS -shr 16), ($productVersionLS -band 0xFFFF)
                }

                $pdbGuid = $null; $pdbAge = $null; $pdbPath = $null
                if ($cvSize -ge 24 -and $cvRva -gt 0) {
                    $fs.Position = $cvRva
                    $cv = $br.ReadBytes([int]$cvSize)
                    if ([Text.Encoding]::ASCII.GetString($cv, 0, 4) -eq 'RSDS') {
                        $guidBytes = New-Object byte[] 16
                        [Array]::Copy($cv, 4, $guidBytes, 0, 16)
                        $pdbGuid = ([Guid]::new($guidBytes)).ToString()
                        $pdbAge = [BitConverter]::ToUInt32($cv, 20)
                        $pdbPath = [Text.Encoding]::UTF8.GetString($cv, 24, $cv.Length - 24).TrimEnd([char]0)
                    }
                }

                $modules += [pscustomobject]@{
                    Name        = [IO.Path]::GetFileName($modulePath)
                    Path        = $modulePath
                    Base        = ('0x{0:X16}' -f $base)
                    Size        = $imageSize
                    TimeStamp   = $timeStamp
                    FileVersion = $version
                    ProductVersion = $productVersion
                    PdbGuid     = $pdbGuid
                    PdbAge      = $pdbAge
                    PdbPath     = $pdbPath
                }
            }
        }

        $uptime = $null
        $processStart = $null
        if ($processCreateTime -and $dumpTime -ge $processCreateTime) {
            $processStart = ([DateTimeOffset]::FromUnixTimeSeconds($processCreateTime)).UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
            $uptime = [TimeSpan]::FromSeconds($dumpTime - $processCreateTime)
        }

        return [pscustomobject]@{
            Path         = $Path
            SizeBytes    = $fs.Length
            ProcessStartUtc = $processStart
            UptimeSeconds = if ($uptime) { [int64]$uptime.TotalSeconds } else { $null }
            Uptime       = if ($uptime) { Format-Duration $uptime } else { $null }
            CrashTimeUtc = ([DateTimeOffset]::FromUnixTimeSeconds($dumpTime)).UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
            Architecture = $arch
            ProcessId    = $processId
            Exception    = $exception
            Modules      = $modules
        }
    }
    finally { $fs.Dispose() }
}

function Read-PdbIdentity([string]$Path) {
    $fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $br = New-Object IO.BinaryReader($fs)
        $magic = [Text.Encoding]::ASCII.GetString($br.ReadBytes(32))
        if (-not $magic.StartsWith('Microsoft C/C++ MSF 7.00')) { throw "Unsupported or corrupt PDB (not MSF 7.00): $Path" }
        $blockSize = [int64]$br.ReadUInt32()
        $null = $br.ReadUInt32(); $null = $br.ReadUInt32()
        $directoryBytes = [int64]$br.ReadUInt32()
        $null = $br.ReadUInt32()
        $blockMapAddress = [int64]$br.ReadUInt32()

        $directoryBlockCount = [int][Math]::Ceiling($directoryBytes / $blockSize)
        $fs.Position = $blockMapAddress * $blockSize
        $directoryBlocks = @(for ($i = 0; $i -lt $directoryBlockCount; $i++) { $br.ReadUInt32() })
        $ms = New-Object IO.MemoryStream
        foreach ($block in $directoryBlocks) {
            $fs.Position = [int64]$block * $blockSize
            $buffer = $br.ReadBytes([int]$blockSize)
            $ms.Write($buffer, 0, $buffer.Length)
        }
        $directory = $ms.ToArray()

        $streamCount = [BitConverter]::ToUInt32($directory, 0)
        if ($streamCount -lt 2) { throw "PDB has no info stream: $Path" }
        $stream0Size = [BitConverter]::ToUInt32($directory, 4)
        $stream0Blocks = if ($stream0Size -eq 4294967295) { 0 } else { [int][Math]::Ceiling($stream0Size / $blockSize) }
        $infoStreamFirstBlock = [BitConverter]::ToUInt32($directory, [int](4 + 4 * $streamCount + 4 * $stream0Blocks))

        $fs.Position = [int64]$infoStreamFirstBlock * $blockSize
        $null = $br.ReadUInt32(); $null = $br.ReadUInt32()
        $age = $br.ReadUInt32()
        $guid = ([Guid]::new($br.ReadBytes(16))).ToString()
        return [pscustomobject]@{ Guid = $guid; Age = $age }
    }
    finally { $fs.Dispose() }
}

# Reads the linker timestamp and the CodeView (RSDS) PDB identity of a PE file by seeking, so a binary on a
# share can be matched against the dump without copying it.
function Read-PeIdentity([string]$Path) {
    $fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
        $br = New-Object IO.BinaryReader($fs)
        $fs.Position = 0x3C
        $peOffset = [int64]$br.ReadUInt32()
        $fs.Position = $peOffset
        if ($br.ReadUInt32() -ne 0x00004550) { throw "Not a PE file: $Path" }
        $null = $br.ReadUInt16()
        $sectionCount = $br.ReadUInt16()
        $timeStamp = $br.ReadUInt32()
        $null = $br.ReadUInt32(); $null = $br.ReadUInt32()
        $optionalSize = $br.ReadUInt16()
        $null = $br.ReadUInt16()
        $optionalStart = $fs.Position
        $magic = $br.ReadUInt16()
        $dataDirOffset = if ($magic -eq 0x20B) { 112 } else { 96 }
        $fs.Position = $optionalStart + $dataDirOffset + 6 * 8
        $debugRva = $br.ReadUInt32(); $debugSize = $br.ReadUInt32()
        $result = [pscustomobject]@{ TimeStamp = $timeStamp; Guid = $null; Age = $null }
        if ($debugRva -eq 0 -or $debugSize -eq 0) { return $result }

        $debugOffset = $null
        $fs.Position = $optionalStart + $optionalSize
        for ($i = 0; $i -lt $sectionCount; $i++) {
            $null = $br.ReadBytes(8)
            $virtualSize = $br.ReadUInt32(); $virtualAddress = $br.ReadUInt32()
            $null = $br.ReadUInt32(); $rawPointer = $br.ReadUInt32()
            $null = $br.ReadBytes(16)
            if ($debugRva -ge $virtualAddress -and $debugRva -lt ($virtualAddress + $virtualSize)) { $debugOffset = [int64]$rawPointer + ($debugRva - $virtualAddress) }
        }
        if ($null -eq $debugOffset) { return $result }
        for ($i = 0; $i -lt [Math]::Floor($debugSize / 28); $i++) {
            $fs.Position = $debugOffset + 28 * $i + 12
            $type = $br.ReadUInt32(); $null = $br.ReadUInt32(); $null = $br.ReadUInt32(); $dataPointer = $br.ReadUInt32()
            if ($type -ne 2) { continue }
            $fs.Position = $dataPointer
            if ([Text.Encoding]::ASCII.GetString($br.ReadBytes(4)) -ne 'RSDS') { continue }
            $result.Guid = ([Guid]::new($br.ReadBytes(16))).ToString()
            $result.Age = $br.ReadUInt32()
            break
        }
        return $result
    }
    finally { $fs.Dispose() }
}

#endregion

#region symbols / build lookup

function Get-BuildChannel($Config, [hashtable]$Vars) {
    if (-not $Vars.minor) { return 'release' }
    $rule = Get-Cfg $Config 'devBuildRule' 'oddMinor'
    if ($rule -eq 'oddMinor' -and ([int]$Vars.minor % 2) -eq 1) { return 'dev' }
    return 'release'
}

function Get-ProductLine($Config, [hashtable]$Vars) {
    $gitCfg = Get-Cfg $Config 'git' $null
    $defaultRef = Get-Cfg $gitCfg 'compareRef' 'origin/main-legacy'
    $major = 0
    $hasMajor = $Vars.major -and [int]::TryParse([string]$Vars.major, [ref]$major)
    $lines = @(Get-Cfg $Config 'productLines' @())
    if ($lines.Count -eq 0) {
        # Legacy flat configuration
        $lines = @([pscustomobject]@{ name = 'default'; releaseRoots = @(Get-Cfg $Config 'releaseRoots' @()); devRoots = @(Get-Cfg $Config 'devRoots' @()); compareRef = $defaultRef })
    }
    $chosen = $null
    foreach ($line in $lines) {
        $min = [int](Get-Cfg $line 'minMajor' 0)
        $max = [int](Get-Cfg $line 'maxMajor' ([int]::MaxValue))
        if (($hasMajor -and $major -ge $min -and $major -le $max) -or (-not $hasMajor -and $min -eq 0)) { $chosen = $line; break }
    }
    if (-not $chosen) { $chosen = $lines[-1] }
    return [pscustomobject]@{
        Name         = Get-Cfg $chosen 'name' 'default'
        ReleaseRoots = @(Get-Cfg $chosen 'releaseRoots' @() | ForEach-Object { Expand-PathValue $_ })
        DevRoots     = @(Get-Cfg $chosen 'devRoots' @() | ForEach-Object { Expand-PathValue $_ })
        BrandedReleaseRoots = @(Get-Cfg $chosen 'brandedReleaseRoots' @() | ForEach-Object { Expand-PathValue $_ })
        BrandedDevRoots     = @(Get-Cfg $chosen 'brandedDevRoots' @() | ForEach-Object { Expand-PathValue $_ })
        CompareRef   = Get-Cfg $chosen 'compareRef' $defaultRef
    }
}

# Roots of the expected channel come first; the other channel is a fallback because a few builds do not follow the rule.
function Get-SearchRoots($Line, [string]$Channel) {
    $release = @($Line.ReleaseRoots | ForEach-Object { [pscustomobject]@{ Channel = 'release'; Root = $_ } })
    $dev = @($Line.DevRoots | ForEach-Object { [pscustomobject]@{ Channel = 'dev'; Root = $_ } })
    if ($Channel -eq 'dev') { return @($dev + $release) }
    return @($release + $dev)
}

function Find-VersionDirectory($Config, $Line, [hashtable]$Vars, [string]$Channel) {
    return Find-VersionFolderInRoots $Config $Vars (Get-SearchRoots $Line $Channel)
}

function Find-VersionFolderInRoots($Config, [hashtable]$Vars, $Roots) {
    $folder = Expand-Template (Get-Cfg $Config 'versionFolderPattern' 'v{version}') $Vars
    $roots = @($Roots)
    foreach ($entry in $roots) {
        $candidate = Join-Path $entry.Root $folder
        if (Test-Path -LiteralPath $candidate) { return [pscustomobject]@{ Path = $candidate; Channel = $entry.Channel } }
    }
    # Folders can carry a suffix, e.g. v2.0.0.3061_keep_for_qa
    foreach ($entry in $roots) {
        if (-not (Test-Path -LiteralPath $entry.Root)) { continue }
        $match = Get-ChildItem -LiteralPath $entry.Root -Directory -Filter "$folder*" -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq $folder -or $_.Name.StartsWith("${folder}_") } | Select-Object -First 1
        if ($match) { return [pscustomobject]@{ Path = $match.FullName; Channel = $entry.Channel } }
    }
    return $null
}

# Brands whose path hints occur in the binary's install path come first (e.g. D:\AspenTech\inmation.root -> aspen).
function Get-OrderedBrands($Config, [string]$ModulePath) {
    $hinted = @(); $others = @()
    foreach ($brand in @(Get-Cfg $Config 'brands' @())) {
        $name = Get-Cfg $brand 'name' $null
        if (-not $name) { continue }
        $hit = @(Get-Cfg $brand 'pathHints' @()) | Where-Object { $_ -and $ModulePath -and $ModulePath.IndexOf($_, [StringComparison]::OrdinalIgnoreCase) -ge 0 } | Select-Object -First 1
        if ($hit) { $hinted += [pscustomobject]@{ Name = $name; Hint = $hit } } else { $others += [pscustomobject]@{ Name = $name; Hint = $null } }
    }
    return @($hinted + $others)
}

# All build folders that may hold the crashed binary: the unbranded folder of the product line and the same version in
# every branded root. Each candidate carries the PDB identity of its binary, so the matching folder is known before any
# symbol archive is extracted.
function Get-BuildFolderCandidates($Config, $Line, [hashtable]$Vars, [string]$Channel, $Module) {
    $list = New-Object Collections.Generic.List[object]
    $seen = @{}
    $binaryFolder = Get-Cfg $Config 'binaryFolder' 'inmation.root\bin'
    $add = {
        param($Hit, $Brand, $Hint)
        if (-not $Hit -or $seen.ContainsKey($Hit.Path.ToLowerInvariant())) { return }
        $seen[$Hit.Path.ToLowerInvariant()] = $true
        $exe = Join-Path (Join-Path $Hit.Path $binaryFolder) $Module.Name
        $state = 'unknown'; $exeGuid = $null; $exeTime = $null
        if (Test-Path -LiteralPath $exe) {
            try {
                $pe = Read-PeIdentity $exe
                $exeGuid = $pe.Guid
                $exeTime = ([DateTimeOffset]::FromUnixTimeSeconds($pe.TimeStamp)).UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
                if ($pe.Guid) { $state = if ($pe.Guid -eq $Module.PdbGuid) { 'match' } else { 'mismatch' } }
                elseif ($pe.TimeStamp -eq $Module.TimeStamp) { $state = 'match' }
            }
            catch { $state = 'unknown' }
        }
        $list.Add([pscustomobject]@{ Path = $Hit.Path; Channel = $Hit.Channel; Brand = $Brand; BrandHint = $Hint; ExePath = $exe; ExeGuid = $exeGuid; ExeTimeUtc = $exeTime; State = $state })
    }
    $brands = Get-OrderedBrands $Config $Module.Path
    $brandedHits = @()
    foreach ($brand in $brands) {
        $roots = @()
        $release = @($Line.BrandedReleaseRoots | ForEach-Object { [pscustomobject]@{ Channel = 'release'; Root = $_.Replace('{brand}', $brand.Name) } })
        $dev = @($Line.BrandedDevRoots | ForEach-Object { [pscustomobject]@{ Channel = 'dev'; Root = $_.Replace('{brand}', $brand.Name) } })
        $roots = if ($Channel -eq 'dev') { @($dev + $release) } else { @($release + $dev) }
        $hit = Find-VersionFolderInRoots $Config $Vars $roots
        if ($hit) { $brandedHits += [pscustomobject]@{ Hit = $hit; Brand = $brand } }
    }
    $primary = Find-VersionDirectory $Config $Line $Vars $Channel
    foreach ($b in @($brandedHits | Where-Object { $_.Brand.Hint })) { & $add $b.Hit $b.Brand.Name $b.Brand.Hint }
    if ($primary) { & $add $primary $null $null }
    foreach ($b in @($brandedHits | Where-Object { -not $_.Brand.Hint })) { & $add $b.Hit $b.Brand.Name $null }
    $candidates = $list.ToArray()
    # Folders whose binary matches the dump first, then folders without a readable binary; mismatches last.
    return @(@($candidates | Where-Object { $_.State -eq 'match' }) + @($candidates | Where-Object { $_.State -eq 'unknown' }) + @($candidates | Where-Object { $_.State -eq 'mismatch' }))
}

function Format-CandidateList($Candidates, $Module) {
    $dumpTime = ([DateTimeOffset]::FromUnixTimeSeconds($Module.TimeStamp)).UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $items = @($Candidates | ForEach-Object {
            $brandText = if ($_.Brand) { "brand $($_.Brand)" } else { 'unbranded' }
            "$($_.Path) [$brandText, $($_.Channel)]: binary GUID $($_.ExeGuid), linked $($_.ExeTimeUtc) -> $($_.State)"
        })
    return "dump binary GUID $($Module.PdbGuid), linked $dumpTime, path $($Module.Path). Build folders checked: $(if ($items) { $items -join '; ' } else { 'none' })"
}

function Get-NearbyVersions($Line, [hashtable]$Vars, [string]$Channel) {
    $found = @()
    foreach ($entry in (Get-SearchRoots $Line $Channel)) {
        if (Test-Path -LiteralPath $entry.Root) {
            $found += @(Get-ChildItem -LiteralPath $entry.Root -Directory -Filter ('v{0}.{1}.*' -f $Vars.major, $Vars.minor) -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 10 | ForEach-Object { $_.FullName })
        }
    }
    return $found
}

function Read-BuildInfo($Config, [string]$VersionDir) {
    if (-not $VersionDir) { return $null }
    $path = Join-Path $VersionDir (Get-Cfg $Config 'buildInfoFile' 'build_info.txt')
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    $info = [ordered]@{ path = $path; sourceBranch = $null; commit = $null }
    foreach ($line in (Get-Content -LiteralPath $path)) {
        if ($line -match '^\s*Source Branch:\s*(\S+)') { $info.sourceBranch = $Matches[1] }
        elseif ($line -match '^\s*Commit ID:\s*([0-9a-fA-F]{7,40})') { $info.commit = $Matches[1].ToLowerInvariant() }
    }
    return [pscustomobject]$info
}

function Resolve-Pdb($Config, $Module, [string]$PdbName, $Candidates, [string]$PdbOverride, [string[]]$DumpDirs, $BundledPdbs) {
    $cacheRoot = Expand-PathValue (Get-Cfg $Config 'localSymbolCache' "$env:LOCALAPPDATA\inmation-crash-analysis\symbols")
    $key = ($Module.PdbGuid -replace '-', '').ToUpperInvariant() + $Module.PdbAge
    $targetDir = Join-Path (Join-Path $cacheRoot $PdbName) $key
    $target = Join-Path $targetDir $PdbName

    if (Test-Path -LiteralPath $target) {
        $cached = Read-PdbIdentity $target
        if ($cached.Guid -eq $Module.PdbGuid) {
            return [pscustomobject]@{ PdbPath = $target; SymbolDir = $targetDir; Source = 'local cache'; Guid = $cached.Guid; Age = $cached.Age; Candidate = $null }
        }
        Remove-Item -LiteralPath $target -Force
    }

    New-Item -ItemType Directory -Force -Path $targetDir | Out-Null
    $partial = "$target.partial"

    if ($PdbOverride) {
        $identity = Read-PdbIdentity $PdbOverride
        if ($identity.Guid -ne $Module.PdbGuid) {
            throw "PDB mismatch: dump expects $PdbName GUID $($Module.PdbGuid) age $($Module.PdbAge), but '$PdbOverride' has GUID $($identity.Guid)."
        }
        Copy-Item -LiteralPath $PdbOverride -Destination $target -Force
        return [pscustomobject]@{ PdbPath = $target; SymbolDir = $targetDir; Source = $PdbOverride; Guid = $identity.Guid; Age = $identity.Age; Candidate = $null }
    }

    foreach ($dumpDir in @($DumpDirs | Where-Object { $_ } | Select-Object -Unique)) {
        $adjacent = Join-Path $dumpDir $PdbName
        if (Test-Path -LiteralPath $adjacent) {
            $identity = Read-PdbIdentity $adjacent
            if ($identity.Guid -eq $Module.PdbGuid) {
                return [pscustomobject]@{ PdbPath = $adjacent; SymbolDir = $dumpDir; Source = "$adjacent (next to dump)"; Guid = $identity.Guid; Age = $identity.Age; Candidate = $null }
            }
        }
    }

    # Symbols shipped inside the dump's zip (or another zip of the input) take precedence over the build shares.
    $mismatches = @()
    foreach ($bundled in @($BundledPdbs | Where-Object { $_ -and $_.Name -ieq $PdbName })) {
        $zip = [IO.Compression.ZipFile]::OpenRead($bundled.Archive)
        try {
            $entry = $zip.GetEntry($bundled.Entry)
            if (-not $entry) { continue }
            Write-Host "  Extracting $($bundled.Entry) from $($bundled.Archive) ($([Math]::Round($entry.Length / 1MB)) MB, bundled with the dump) ..."
            [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $partial, $true)
        }
        finally { $zip.Dispose() }
        try { $identity = Read-PdbIdentity $partial }
        catch { $mismatches += "$($bundled.Archive)!$($bundled.Entry) is not a readable PDB ($($_.Exception.Message))"; Remove-Item -LiteralPath $partial -Force; continue }
        if ($identity.Guid -eq $Module.PdbGuid) {
            Move-Item -LiteralPath $partial -Destination $target -Force
            return [pscustomobject]@{ PdbPath = $target; SymbolDir = $targetDir; Source = "$($bundled.Archive)!$($bundled.Entry) (bundled with dump)"; Guid = $identity.Guid; Age = $identity.Age; Candidate = $null }
        }
        $mismatches += "$($bundled.Archive)!$($bundled.Entry) (bundled) has GUID $($identity.Guid)"
        Remove-Item -LiteralPath $partial -Force
    }

    $candidates = @($Candidates | Where-Object { $_ })
    if ($candidates.Count -eq 0) {
        $bundledNote = if ($mismatches.Count -gt 0) { " Bundled symbols do not match: $($mismatches -join '; ')." } else { '' }
        if (-not (Get-ChildItem -LiteralPath $targetDir -Force -ErrorAction SilentlyContinue)) { Remove-Item -LiteralPath $targetDir -Force -ErrorAction SilentlyContinue }
        throw "No build folder found for this version on the release, dev or branded shares; pass -PdbPath with the matching $PdbName.$bundledNote"
    }

    $searched = @()
    foreach ($candidate in $candidates) {
        if ($candidate.State -eq 'mismatch') {
            $mismatches += "$($candidate.ExePath) is a different build (binary GUID $($candidate.ExeGuid), linked $($candidate.ExeTimeUtc)); its symbols were not extracted"
            continue
        }
        $archive = Join-Path $candidate.Path (Get-Cfg $Config 'symbolArchive' 'symbols\symbols.zip')
        $searched += $archive
        $found = { param($Identity, $Source) [pscustomobject]@{ PdbPath = $target; SymbolDir = $targetDir; Source = $Source; Guid = $Identity.Guid; Age = $Identity.Age; Candidate = $candidate } }
        if (Test-Path -LiteralPath $archive) {
            $zip = [IO.Compression.ZipFile]::OpenRead($archive)
            try {
                foreach ($entry in @($zip.Entries | Where-Object { $_.Name -ieq $PdbName })) {
                    $entryName = $entry.FullName
                    Write-Host "  Extracting $entryName from $archive ($([Math]::Round($entry.Length / 1MB)) MB) ..."
                    [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $partial, $true)
                    $identity = Read-PdbIdentity $partial
                    if ($identity.Guid -eq $Module.PdbGuid) {
                        Move-Item -LiteralPath $partial -Destination $target -Force
                        return (& $found $identity "$archive!$entryName")
                    }
                    $mismatches += "$archive!$entryName has GUID $($identity.Guid)"
                    Remove-Item -LiteralPath $partial -Force
                }
            }
            finally { $zip.Dispose() }
        }
        else {
            $loose = Join-Path (Split-Path $archive -Parent) $PdbName
            if (Test-Path -LiteralPath $loose) {
                $identity = Read-PdbIdentity $loose
                if ($identity.Guid -eq $Module.PdbGuid) {
                    Copy-Item -LiteralPath $loose -Destination $target -Force
                    return (& $found $identity $loose)
                }
                $mismatches += "$loose has GUID $($identity.Guid)"
            }
        }
    }

    $context = Format-CandidateList $candidates $Module
    if (-not (Get-ChildItem -LiteralPath $targetDir -Force -ErrorAction SilentlyContinue)) { Remove-Item -LiteralPath $targetDir -Force -ErrorAction SilentlyContinue }
    if ($mismatches.Count -gt 0) {
        throw "PDB mismatch: dump expects $PdbName GUID $($Module.PdbGuid) age $($Module.PdbAge). Candidates: $($mismatches -join '; '). $context. No build folder holds this binary (private/hotfix build, or a brand or share not in the config); pass -PdbPath."
    }
    throw "$PdbName not found in $($searched -join ', ') (or next to it). $context. Pass -PdbPath."
}

function Get-BuildTime($Config, [string]$VersionDir, $Module) {
    if ($VersionDir) {
        $manifest = Get-ChildItem -LiteralPath $VersionDir -Filter (Get-Cfg $Config 'manifestPattern' 'manifest_*.txt') -File -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($manifest) {
            $match = Select-String -LiteralPath $manifest.FullName -Pattern 'Build time \(UTC\):\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})' | Select-Object -First 1
            if ($match) {
                $time = [DateTime]::ParseExact($match.Matches[0].Groups[1].Value, 'yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AssumeUniversal,AdjustToUniversal')
                return [pscustomobject]@{ TimeUtc = $time; Source = $manifest.FullName }
            }
        }
    }
    $peTime = ([DateTimeOffset]::FromUnixTimeSeconds($Module.TimeStamp)).UtcDateTime
    if ($peTime.Year -ge 2015 -and $peTime -le [DateTime]::UtcNow.AddDays(1)) {
        return [pscustomobject]@{ TimeUtc = $peTime; Source = 'PE header timestamp' }
    }
    return $null
}

function Find-BuildCommit($Config, [string]$Repo, [hashtable]$Vars, $BuildTime, $BuildInfo, [string]$CompareRef) {
    $gitCfg = Get-Cfg $Config 'git' $null
    $compareRef = if ($CompareRef) { $CompareRef } else { Get-Cfg $gitCfg 'compareRef' 'origin/main-legacy' }
    $result = [ordered]@{ branch = $null; sourceBranch = $null; commit = $null; commitDateUtc = $null; subject = $null; method = $null; confidence = 'none'; notes = @() }

    if (-not $Repo) {
        if ($BuildInfo -and $BuildInfo.commit) {
            $result.sourceBranch = $BuildInfo.sourceBranch
            $result.commit = $BuildInfo.commit; $result.method = "build_info.txt ($($BuildInfo.path)); not verified - no source repository"; $result.confidence = 'exact'
        }
        else { $result.notes += 'No source repository available; the build commit is only known when the build folder has build_info.txt.' }
        return $result
    }

    foreach ($pattern in @(Get-Cfg $gitCfg 'branchPatterns' @('origin/release/v{major}.{minor}'))) {
        $ref = Expand-Template $pattern $Vars
        if ((Invoke-Git $Repo @('rev-parse', '--verify', '--quiet', "$ref^{commit}")).ExitCode -eq 0) { $result.branch = $ref; break }
    }

    $buildIso = if ($BuildTime) { $BuildTime.TimeUtc.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null }
    $commit = $null

    if ($BuildInfo -and $BuildInfo.commit) {
        $result.sourceBranch = $BuildInfo.sourceBranch
        $known = Invoke-Git $Repo @('rev-parse', '--verify', '--quiet', "$($BuildInfo.commit)^{commit}")
        if ($known.ExitCode -eq 0 -and $known.Lines.Count -gt 0) {
            $commit = $known.Lines[0]; $result.method = "build_info.txt ($($BuildInfo.path))"; $result.confidence = 'exact'
        }
        else {
            $result.notes += "build_info.txt names commit $($BuildInfo.commit) (source $($BuildInfo.sourceBranch)), but it is not in this repository. Fetch the source branch or use a clone that has it; falling back to estimation."
        }
    }

    foreach ($tagPattern in @(Get-Cfg $gitCfg 'tagPatterns' @('v{version}'))) {
        if ($commit) { break }
        $tag = Expand-Template $tagPattern $Vars
        $tagCommit = Invoke-Git $Repo @('rev-parse', '--verify', '--quiet', "refs/tags/$tag^{commit}")
        if ($tagCommit.ExitCode -eq 0 -and $tagCommit.Lines.Count -gt 0) {
            $commit = $tagCommit.Lines[0]; $result.method = "release tag $tag"; $result.confidence = 'high'
            break
        }
    }

    if (-not $commit -and $result.branch) {
        $messageTemplate = Get-Cfg $gitCfg 'versionCommitMessage' 'make v{major}.{minor}.{revision}'
        $messageRegex = ((Expand-Template $messageTemplate $Vars) -replace '([.\[\]()*+?{}|^$\\])', '\$1') + '([^0-9]|$)'
        $bump = Invoke-Git $Repo @('log', $result.branch, '-1', '--format=%H', '-E', "--grep=$messageRegex")
        if ($bump.ExitCode -eq 0 -and $bump.Lines.Count -gt 0 -and $bump.Lines[0]) {
            $commit = $bump.Lines[0]; $result.method = 'version bump commit on version branch'; $result.confidence = 'high'
        }
        elseif ($buildIso) {
            $atTime = Invoke-Git $Repo @('rev-list', '-1', "--before=$buildIso", $result.branch)
            if ($atTime.Lines.Count -gt 0 -and $atTime.Lines[0]) {
                $commit = $atTime.Lines[0]; $result.method = 'last commit on version branch before build time'; $result.confidence = 'medium'
                $result.notes += "No '$(Expand-Template $messageTemplate $Vars)' commit exists on $($result.branch); the build may contain changes that were never pushed to this repository. Validate with the PDB source lines."
            }
        }
    }
    elseif (-not $commit) {
        $result.notes += "No version branch found (patterns: $((@(Get-Cfg $gitCfg 'branchPatterns' @())) -join ', '))."
        if ($buildIso) {
            $atTime = Invoke-Git $Repo @('rev-list', '-1', "--before=$buildIso", $compareRef)
            if ($atTime.Lines.Count -gt 0 -and $atTime.Lines[0]) {
                $commit = $atTime.Lines[0]; $result.method = "last commit on $compareRef before build time"; $result.confidence = 'low'
            }
        }
    }

    if ($commit) {
        $info = Invoke-Git $Repo @('show', '-s', '--format=%cI%x09%s', $commit)
        $parts = $info.Lines[0] -split "`t", 2
        $result.commit = $commit; $result.commitDateUtc = $parts[0]; $result.subject = $parts[1]
    }
    else {
        $result.notes += 'Could not determine the build commit.'
    }
    return $result
}

#endregion

#region cdb

function Find-Cdb($Config) {
    $candidates = @()
    $configured = Expand-PathValue (Get-Cfg $Config 'debuggerPath' '')
    if ($configured) { $candidates += $configured }
    $candidates += @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\Debuggers\x64\cdb.exe",
        "$env:ProgramFiles\Windows Kits\10\Debuggers\x64\cdb.exe"
    )
    $onPath = Get-Command cdb.exe -ErrorAction SilentlyContinue
    if ($onPath) { $candidates += $onPath.Source }
    foreach ($candidate in $candidates) { if ($candidate -and (Test-Path -LiteralPath $candidate)) { return $candidate } }
    throw 'cdb.exe not found. Install "Debugging Tools for Windows" (Windows SDK) or set debuggerPath in the config.'
}

function Invoke-Cdb([string]$Cdb, [string]$Dump, [string]$SymbolPath, [string]$ImagePath, [string]$LogPath, [string[]]$Commands, [int]$TimeoutSeconds) {
    $argList = @('-z', "`"$Dump`"", '-y', "`"$SymbolPath`"", '-lines')
    if ($ImagePath) { $argList += @('-i', "`"$ImagePath`"") }
    $argList += @('-c', "`"$($Commands -join '; ')`"")
    $process = Start-Process -FilePath $Cdb -ArgumentList ($argList -join ' ') -NoNewWindow -PassThru `
        -RedirectStandardOutput $LogPath -RedirectStandardError "$LogPath.stderr"
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        Stop-Process -Id $process.Id -Force
        throw "cdb did not finish within $TimeoutSeconds s (log: $LogPath)."
    }
    $stderrPath = "$LogPath.stderr"
    if ((Test-Path -LiteralPath $stderrPath) -and (Get-Item -LiteralPath $stderrPath).Length -eq 0) { Remove-Item -LiteralPath $stderrPath -Force }
}

# Runs a command file (-cf), which avoids command-line quoting problems for long, structured queries.
function Invoke-CdbScript([string]$Cdb, [string]$Dump, [string]$SymbolPath, [string]$ImagePath, [string]$LogPath, [string]$CommandFile, [int]$TimeoutSeconds) {
    $argList = @('-z', "`"$Dump`"", '-y', "`"$SymbolPath`"", '-lines')
    if ($ImagePath) { $argList += @('-i', "`"$ImagePath`"") }
    $argList += @('-cf', "`"$CommandFile`"")
    $process = Start-Process -FilePath $Cdb -ArgumentList ($argList -join ' ') -NoNewWindow -PassThru `
        -RedirectStandardOutput $LogPath -RedirectStandardError "$LogPath.stderr"
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        Stop-Process -Id $process.Id -Force
        throw "cdb did not finish within $TimeoutSeconds s (log: $LogPath)."
    }
    $stderrPath = "$LogPath.stderr"
    if ((Test-Path -LiteralPath $stderrPath) -and (Get-Item -LiteralPath $stderrPath).Length -eq 0) { Remove-Item -LiteralPath $stderrPath -Force }
}

function Split-CdbSections([string[]]$Lines) {
    $sections = @{}
    $current = $null
    foreach ($line in $Lines) {
        if ($line -match '^<<<SECTION:(\w+)>>>\s*$') {
            $current = $Matches[1]
            $sections[$current] = New-Object Collections.Generic.List[string]
            continue
        }
        if ($current) { $sections[$current].Add($line) }
    }
    return $sections
}

function Get-Section([hashtable]$Sections, [string]$Name) {
    if ($Sections.ContainsKey($Name)) { return @($Sections[$Name]) }
    return @()
}

function ConvertFrom-CdbStack([string[]]$Lines) {
    $regex = '^(?<num>[0-9a-f]{2,})\s+(?:(?<sp>[0-9a-f]{8}(?:`[0-9a-f]{8})?)\s+(?<ret>[0-9a-f]{8}(?:`[0-9a-f]{8})?)|\(Inline Function\)\s+[-`]+)\s+(?<site>.+?)(?:\s+\[(?<file>[^\]]+?) @ (?<line>\d+)\])?\s*$'
    $frames = @()
    foreach ($line in $Lines) {
        if ($line -notmatch $regex) { continue }
        $m = $Matches.Clone()
        $site = $m['site']
        $module = if ($site -match '^([^!+\s]+)[!+]') { $Matches[1] } else { $null }
        $function = $site -replace '^[^!]+!', '' -replace '\+0x[0-9a-f]+$', ''
        $frames += [pscustomobject][ordered]@{
            index      = [Convert]::ToInt32([string]$m['num'], 16)
            inline     = -not $m['sp']
            module     = $module
            function   = $function
            callSite   = $site
            retAddr    = if ($m['ret']) { '0x' + ($m['ret'] -replace '`', '') } else { $null }
            sourceFile = if ($m['file']) { $m['file'] } else { $null }
            sourceLine = if ($m['line']) { [int]$m['line'] } else { $null }
            repoPath   = $null
            buildSnippet = $null
            functionFoundAtBuildCommit = $null
            thirdParty = $null
        }
    }
    return $frames
}

# Symbol-independent frame addresses (module+RVA) from the exception address and the return addresses of 'kn'.
# Used instead of function names when the PDB is not verified: export-symbol names are nearest exports, not functions.
function Get-RawStack($Frames, [string]$ExceptionAddress, $Modules) {
    $ranges = @($Modules | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Base = [Convert]::ToUInt64(($_.Base -replace '^0x', ''), 16); Size = [uint64]$_.Size } })
    $nextIp = if ($ExceptionAddress) { [Convert]::ToUInt64(($ExceptionAddress -replace '^0x', ''), 16) } else { $null }
    $raw = @()
    foreach ($f in $Frames) {
        $ip = $nextIp
        if (-not $f.inline) { $nextIp = if ($f.retAddr) { [Convert]::ToUInt64(($f.retAddr -replace '^0x', ''), 16) } else { $null } }
        $text = $null
        if ($null -ne $ip) {
            $mod = $ranges | Where-Object { $ip -ge $_.Base -and $ip -lt ($_.Base + $_.Size) } | Select-Object -First 1
            $text = if ($mod) { '{0}+0x{1:x}' -f $mod.Name, ($ip - $mod.Base) } else { '0x{0:x}' -f $ip }
        }
        $raw += [pscustomobject][ordered]@{ index = $f.index; inline = $f.inline; address = $text }
    }
    return $raw
}

#endregion

#region source mapping

$script:repoPathCache = @{}
$script:fileCache = @{}

function Convert-ToRepoPath([string]$Repo, [string]$Commit, [string]$SourceFile, $Config) {
    if (-not $SourceFile -or -not $Commit) { return $null }
    $cacheKey = "$Commit|$SourceFile"
    if ($script:repoPathCache.ContainsKey($cacheKey)) { return $script:repoPathCache[$cacheKey] }
    $candidates = @()
    foreach ($root in @(Get-Cfg $Config 'buildSourceRoots' @())) {
        if ($SourceFile.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) { $candidates += $SourceFile.Substring($root.Length) }
    }
    $segments = $SourceFile -split '[\\/]' | Where-Object { $_ -and $_ -notmatch ':$' }
    for ($i = 0; $i -lt [Math]::Min($segments.Count - 1, 8); $i++) { $candidates += ($segments[$i..($segments.Count - 1)] -join '/') }
    $resolved = $null
    foreach ($candidate in $candidates) {
        $rel = $candidate -replace '\\', '/'
        if ((Invoke-Git $Repo @('cat-file', '-e', ('{0}:{1}' -f $Commit, $rel))).ExitCode -eq 0) { $resolved = $rel; break }
    }
    $script:repoPathCache[$cacheKey] = $resolved
    return $resolved
}

function Get-GitFileLines([string]$Repo, [string]$Commit, [string]$RelPath) {
    $key = "$Commit|$RelPath"
    if (-not $script:fileCache.ContainsKey($key)) {
        $show = Invoke-Git $Repo @('show', ('{0}:{1}' -f $Commit, $RelPath))
        $script:fileCache[$key] = if ($show.ExitCode -eq 0) { $show.Lines } else { $null }
    }
    return $script:fileCache[$key]
}

function Get-ShortFunctionName([string]$Function) {
    $name = $Function
    while ($name -match '<[^<>]*>') { $name = $name -replace '<[^<>]*>', '' }
    $name = ($name -split '::')[-1]
    if (-not $name -or $name -match '^operator' -or $name -match 'lambda') { return $null }
    return $name
}

#endregion

#region assertions / abort

# Frames that only report a failure (CRT abort/assert/terminate, fail-fast helpers, exception dispatch). They are
# skipped for the crash signature and searched for the assertion text.
$script:noiseFunctionRegex = '^(abort|raise|_?wassert|_assert|_bson_assert_failed_on_line|bson_abort|std::terminate|terminate|__std_terminate|_invalid_parameter(_noinfo)?(_noreturn)?|_invoke_watson|_purecall|_CxxThrowException|RaiseException|RtlRaiseException|__report_gsfailure|__report_securityfailure|__fastfail|_?_?acrt_call_reportfault|_call_reportfault|__scrt_unhandled_exception_filter|KiUserExceptionDispatcher|RtlDispatchException|RtlUserThreadStart|BaseThreadInitThunk)$'
# MSVC C++ exception dispatch/unwind frames: on the stack of every unhandled exception, never evidence of a bug.
$script:ehRuntimeRegex = '^(__CxxFrameHandler\d*|__InternalCxxFrameHandler(Wrapper)?(<.*>)?|FindHandler(<.*>)?|CatchIt(<.*>)?|__FrameHandler\d*::\w+|_CallSettingFrame\w*|_CallCatchBlock\d*|__C_specific_handler|__GSHandlerCheck\w*|__FrameUnwindFilter|__ExceptionPtrRethrow|std::_Throw_Cpp_error|std::_Throw_C_error|std::rethrow_exception|RtlpExecuteHandlerFor(Exception|Unwind)|RtlUnwindEx)$'

function Test-NoiseFrame($Frame) {
    # A bare address below frame 0 is a wrong unwind (e.g. minidump without KERNELBASE/ntdll), not a caller. Frame 0
    # as a bare address is kept: the crash executed outside known code.
    $bogusUnwind = ($Frame.index -gt 0) -and (-not $Frame.module) -and ($Frame.function -match '^0x[0-9a-f`]+$')
    return [bool](($Frame.function -match $script:noiseFunctionRegex) -or ($Frame.function -match $script:ehRuntimeRegex) -or $bogusUnwind -or (($Frame.module -match '^(ntdll|KERNELBASE|kernel32|ucrtbase|vcruntime\d*|msvcp\d*)$') -and ($Frame.function -match 'Raise|Exception|Fail|abort|terminate')))
}

# Splits 'dv /t /v' output of several '.frame N' commands into a map frame index -> local lines.
function Split-LocalsByFrame([string[]]$Lines) {
    $map = @{}
    $current = $null
    foreach ($line in $Lines) {
        if ($line -match '^(?<num>[0-9a-f]{2,})\s+(?:[0-9a-f]{8}(?:`[0-9a-f]{8})?\s+[0-9a-f]{8}(?:`[0-9a-f]{8})?|\(Inline Function\))') {
            $current = [Convert]::ToInt32($Matches['num'], 16)
            if (-not $map.ContainsKey($current)) { $map[$current] = New-Object Collections.Generic.List[string] }
            continue
        }
        if ($null -ne $current) { $map[$current].Add($line) }
    }
    return $map
}

function Get-LocalValue([string[]]$Lines, [string[]]$Names) {
    foreach ($name in $Names) {
        foreach ($line in $Lines) {
            if ($line -match ('\b' + [regex]::Escape($name) + ' = (?:0x[0-9a-f`]+ )?(?:(?<str>"(?:[^"\\]|\\.)*")|0n(?<dec>-?\d+)|(?<num>-?\d+|0x[0-9a-f`]+))')) {
                if ($Matches['str']) { return $Matches['str'].Trim('"') }
                if ($Matches['dec']) { return $Matches['dec'] }
                return $Matches['num']
            }
        }
    }
    return $null
}

function Get-AssertionInfo($Frames, [hashtable]$LocalsByFrame, $Exception) {
    $kinds = [ordered]@{
        '_bson_assert_failed_on_line' = 'BSON_ASSERT (libbson/libmongoc)'
        'bson_abort'                  = 'bson_abort'
        '_wassert'                    = 'CRT assert()'
        '_assert'                     = 'CRT assert()'
        '_invalid_parameter'          = 'CRT invalid parameter'
        '_invalid_parameter_noinfo'   = 'CRT invalid parameter'
        '_invalid_parameter_noinfo_noreturn' = 'CRT invalid parameter'
        '_purecall'                   = 'pure virtual call'
        'std::terminate'              = 'std::terminate (unhandled C++ exception or noexcept violation)'
        'terminate'                   = 'std::terminate (unhandled C++ exception or noexcept violation)'
        '__std_terminate'             = 'std::terminate (unhandled C++ exception or noexcept violation)'
        'abort'                       = 'abort()'
    }
    $hit = $null
    foreach ($key in $kinds.Keys) {
        $hit = $Frames | Where-Object { $_.index -lt 12 -and $_.function -eq $key } | Select-Object -First 1
        if ($hit) { break }
    }
    if (-not $hit) { return $null }
    $lines = if ($LocalsByFrame.ContainsKey($hit.index)) { @($LocalsByFrame[$hit.index]) } else { @() }
    $reporter = $Frames | Where-Object { $_.index -gt $hit.index -and -not (Test-NoiseFrame $_) } | Select-Object -First 1
    $info = [ordered]@{
        kind          = $kinds[$hit.function]
        frame         = $hit.index
        function      = $hit.function
        expression    = Get-LocalValue $lines @('test', 'expression', '_Message', 'message', 'expr')
        file          = Get-LocalValue $lines @('file', '_File')
        line          = Get-LocalValue $lines @('line', '_Line')
        inFunction    = Get-LocalValue $lines @('func', 'function', '_Function')
        reportedBy    = if ($reporter) { $reporter.callSite } else { $null }
        deliberate    = $true
        note          = $null
        unwindNote    = $null
    }
    if ($Exception -and $Exception.failFastCode -eq 7) { $info.note = 'Exception 0xC0000409 subcode 7 (FAST_FAIL_FATAL_APP_EXIT) is how abort() terminates the process; this is not a stack buffer overrun.' }
    if (-not $reporter -and $info.kind -like 'std::terminate*') {
        $info.unwindNote = 'No application frame on the unwound stack: the unwind stopped in the C++ exception dispatch (typical for a minidump without KERNELBASE/ntdll). The thrown exception and its throw site are still on the stack; decode them with the agent recipe "Unhandled C++ exception (std::terminate)".'
    }
    return [pscustomobject]$info
}

#endregion

#region third-party (vcpkg) frames

function ConvertFrom-VcpkgSourcePath([string]$SourceFile) {
    if (-not $SourceFile) { return $null }
    if ($SourceFile -match '[\\/]buildtrees[\\/](?<port>[^\\/]+)[\\/]src[\\/](?<dir>[^\\/]+?)\.clean[\\/](?<rel>.+)$') {
        $dir = $Matches['dir']; $port = $Matches['port']; $rel = $Matches['rel'] -replace '\\', '/'
        $version = if ($dir -match '^(?<v>.+)-(?<h>[0-9a-f]{10})$') { $Matches['v'] } else { $dir }
        return [pscustomobject]@{ port = $port; sourceDir = $dir; version = $version; relPath = $rel }
    }
    if ($SourceFile -match '[\\/]vcpkg_installed[\\/][^\\/]+[\\/](?:[^\\/]+[\\/])?include[\\/](?<rel>.+)$') {
        return [pscustomobject]@{ port = $null; sourceDir = $null; version = $null; relPath = 'include/' + ($Matches['rel'] -replace '\\', '/') }
    }
    return $null
}

function Read-PortDirectory([string]$Repo, [string]$Commit, [string]$Dir) {
    $files = Invoke-Git $Repo @('ls-tree', '--name-only', "${Commit}:$Dir")
    if ($files.ExitCode -ne 0 -or $files.Lines.Count -eq 0) { return $null }
    $version = $null; $portVersion = $null
    $manifest = Invoke-Git $Repo @('show', "${Commit}:$Dir/vcpkg.json")
    if ($manifest.ExitCode -eq 0) {
        try {
            $json = ($manifest.Lines -join "`n") | ConvertFrom-Json
            foreach ($field in 'version', 'version-string', 'version-semver', 'version-date') { if (-not $version) { $version = Get-Cfg $json $field $null } }
            $portVersion = Get-Cfg $json 'port-version' $null
        }
        catch { $version = '(vcpkg.json unreadable)' }
    }
    $portfile = (Invoke-Git $Repo @('show', "${Commit}:$Dir/portfile.cmake")).Lines
    $active = @($portfile | Where-Object { $_ -notmatch '^\s*#' } | ForEach-Object { ($_ -split '#', 2)[0] }) -join "`n"
    $patches = @($files.Lines | Where-Object { $_ -match '\.(patch|diff)$' -and $active.Contains($_) })
    return [pscustomobject]@{ dir = $Dir; version = $version; portVersion = $portVersion; patches = $patches; note = $null }
}

# Port definition used by a commit: an overlay port of this repository, else the port of the vcpkg submodule commit
# pinned by that commit (needs the submodule checked out locally).
function Get-PortInfo($Config, [string]$Repo, [string]$Commit, [string]$Port) {
    if (-not $Repo -or -not $Commit -or -not $Port) { return $null }
    foreach ($root in @(Get-Cfg $Config 'vcpkgPortRoots' @('vcpkg-ports-inmation', 'vcpkg-ports', 'vcpkg-ports-ci'))) {
        $info = Read-PortDirectory $Repo $Commit "$root/$Port"
        if ($info) { return $info }
    }
    $submodule = Get-Cfg $Config 'vcpkgSubmodule' 'vcpkg'
    $link = (Invoke-Git $Repo @('ls-tree', $Commit, '--', $submodule)).Lines | Select-Object -First 1
    if ($link -match '^160000 commit ([0-9a-f]{40})\s') {
        $subCommit = $Matches[1]
        $subRepo = Join-Path $Repo $submodule
        if ((Test-Path -LiteralPath $subRepo) -and (Invoke-Git $subRepo @('cat-file', '-e', "$subCommit^{commit}")).ExitCode -eq 0) {
            $info = Read-PortDirectory $subRepo $subCommit "ports/$Port"
            if ($info) { $info.dir = "$submodule@$($subCommit.Substring(0, 10)):ports/$Port"; return $info }
        }
        return [pscustomobject]@{ dir = $null; version = $null; portVersion = $null; patches = @(); note = "upstream port from vcpkg submodule commit $($subCommit.Substring(0, 10)) (not available locally)" }
    }
    return [pscustomobject]@{ dir = $null; version = $null; portVersion = $null; patches = @(); note = 'port not found in overlay roots or vcpkg submodule' }
}

function Find-LocalPortSource($Config, [string]$Repo, $ThirdParty) {
    if (-not $ThirdParty.port) { return $null }
    $root = Expand-PathValue (Get-Cfg $Config 'localBuildtrees' '')
    if (-not $root -and $Repo) { $root = Join-Path $Repo 'vcpkg\buildtrees' }
    if (-not $root) { return $null }
    $srcRoot = Join-Path (Join-Path $root $ThirdParty.port) 'src'
    if (-not (Test-Path -LiteralPath $srcRoot)) { return $null }
    $rel = $ThirdParty.relPath -replace '/', '\'
    $exact = Join-Path (Join-Path $srcRoot "$($ThirdParty.sourceDir).clean") $rel
    if (Test-Path -LiteralPath $exact) { return [pscustomobject]@{ path = $exact; exact = $true } }
    $same = Get-ChildItem -LiteralPath $srcRoot -Directory -Filter "$($ThirdParty.version)-*.clean" -ErrorAction SilentlyContinue |
        ForEach-Object { Join-Path $_.FullName $rel } | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if ($same) { return [pscustomobject]@{ path = $same; exact = $false } }
    return $null
}

#endregion

#region Lua / script context (second cdb pass)

function Get-LuaFlavor([string]$Version) {
    if (-not $Version) { return '5.3' }
    if ($Version -match '^5\.3') { return '5.3' }
    if ($Version -match '^5\.4\.([0-5])$') { return '5.4' }
    if ($Version -match '^5\.(4|5)') { return '5.5' }
    return '5.3'
}

# Builds a cdb command file that walks the Lua CallInfo chain and dumps the configured script strings.
# cdb pitfalls handled here: '.if' conditions must not contain @@c++(), so values go through pseudo-registers first;
# every 'r' resets the register context set by .ecxr, so each 'r' that reads a local is preceded by '.ecxr; .frame'.
function New-ContextCommands($Frames, [string]$LuaFlavor, $ScriptFrames, [int]$MaxScriptBytes, [bool]$Wow64) {
    $cmds = New-Object Collections.Generic.List[string]
    if ($Wow64) { $cmds.Add('.load wow64exts'); $cmds.Add('!sw') }
    $cmds.Add('.ecxr')
    $luaCore = '^(luaD_precall|luaD_call|luaD_callnoyield|luaV_execute|luaD_rawrunprotected|luaD_pcall|lua_pcallk|lua_callk|luaT_callTM|luaD_throw|luaG_.*|luaH_.*|luaV_.*|precallC|ccall)$'
    $firstCore = $Frames | Where-Object { $_.function -match $luaCore } | Select-Object -First 1
    if ($firstCore) {
        $tries = @($Frames | Where-Object { $_.index -le $firstCore.index + 1 -and $_.index -ge [Math]::Max(0, $firstCore.index - 4) } | Sort-Object { if ($_.index -lt $firstCore.index) { $firstCore.index - $_.index } else { 10 + $_.index } })
        $cmds.Add('.echo <<<CTX:lua>>>')
        $cmds.Add('r $t0 = 0')
        foreach ($f in $tries) { $cmds.Add(".if (@`$t0 == 0) { .ecxr; .frame 0n$($f.index); r `$t0 = @@c++(L->ci) }") }
        $cmds.Add('.echo LUA_START'); $cmds.Add('? @$t0')
        $ci = '((CallInfo*)@$t0)'
        switch ($LuaFlavor) {
            '5.3' { $tv = "(*$ci->func)" }
            '5.4' { $tv = "$ci->func->val" }
            default { $tv = "$ci->func.p->val" }
        }
        $p = "((LClosure*)$tv.value_.gc)->p"
        $pc = "(($ci->u.l.savedpc - $p->code) - 1)"
        $luaBody = @('.echo <<<LUAFRAME>>>', "r `$t2 = @@c++($tv.tt_)", '.echo LF_TT', '? @$t2')
        $luaInner = @()
        switch ($LuaFlavor) {
            '5.3' { $luaInner += '.echo LF_SRC', "dx -r0 (char*)($p->source+1)" }
            '5.4' { $luaInner += '.echo LF_SRC', "dx -r0 (char*)$p->source->contents" }
            default {
                $luaInner += "r `$t3 = @@c++($p->source->shrlen)", '.echo LF_SRC'
                $luaInner += ".if ((@`$t3 & 0x80) == 0) { dx -r0 (char*)&$p->source->contents } .else { dx -r0 $p->source->contents }"
            }
        }
        $luaInner += '.echo LF_DEF', "dx -r0 $p->linedefined", '.echo LF_LAST', "dx -r0 $p->lastlinedefined", '.echo LF_PROTO', "? @@c++($p)"
        if ($LuaFlavor -eq '5.3') {
            $luaInner += '.echo LF_LINE', "dx -r0 $p->lineinfo[$pc]"
        }
        else {
            $luaInner += '.echo LF_PC', "dx -r0 (int)$pc"
            $luaInner += "r `$t4 = @@c++($p->sizeabslineinfo)", '.if (@$t4 > 0n4096) { r $t4 = 0n4096 }', '.echo LF_ABS'
            $luaInner += ".if (@`$t4 > 0) { dd @@c++($p->abslineinfo) L?(@`$t4 * 2) }"
            $luaInner += "r `$t5 = @@c++($ci->u.l.savedpc - $p->code)", '.if (@$t5 > 0n65536) { r $t5 = 0n65536 }', '.echo LF_LI'
            $luaInner += ".if (@`$t5 > 0) { db @@c++($p->lineinfo) L?@`$t5 }"
        }
        $cInner = @('.echo LF_CFN', "dx -r0 $tv.value_.f")
        $ccInner = @('.echo LF_CFN', "dx -r0 ((CClosure*)$tv.value_.gc)->f")
        $luaBody += ".if ((@`$t2 & 0x3f) == 6) { $($luaInner -join '; ') } .else { .if (@`$t2 == 0x16) { $($cInner -join '; ') } .else { .if ((@`$t2 & 0x3f) == 0x26) { $($ccInner -join '; ') } } }"
        $luaBody += "r `$t0 = @@c++($ci->previous)"
        $cmds.Add(".for (r `$t1 = 0; (@`$t0 != 0) & (@`$t1 < 0n80); r `$t1 = @`$t1 + 1) { $($luaBody -join '; ') }")
        $cmds.Add('.echo <<<CTX:luaend>>>')
    }
    foreach ($sf in @($ScriptFrames)) {
        $v = $sf.Variable
        $cmds.Add(".echo <<<CTX:script:$($sf.Frame)>>>")
        $at = ".ecxr; .frame 0n$($sf.Frame)"
        $cmds.Add('r $t2 = 0'); $cmds.Add('r $t3 = 0'); $cmds.Add('r $t4 = 0')
        $cmds.Add("$at; r `$t3 = @@c++($v._Mypair._Myval2._Mysize)")
        $cmds.Add("$at; r `$t4 = @@c++($v._Mypair._Myval2._Myres)")
        $cmds.Add(".if (@`$t4 >= 0n16) { $at; r `$t2 = @@c++($v._Mypair._Myval2._Bx._Ptr) } .else { $at; r `$t2 = @@c++(&$v._Mypair._Myval2._Bx._Buf[0]) }")
        $cmds.Add('.echo SCRIPT_SIZE'); $cmds.Add('? @$t3')
        $cmds.Add(".if (@`$t3 > 0n$MaxScriptBytes) { r `$t3 = 0n$MaxScriptBytes }")
        $cmds.Add('.echo SCRIPT_BYTES')
        $cmds.Add('.if ((@$t2 != 0) & (@$t3 != 0)) { db @$t2 L?@$t3 }')
        $cmds.Add('.echo SCRIPT_END')
    }
    $cmds.Add('.echo <<<CTX:end>>>')
    $cmds.Add('q')
    return $cmds
}

function ConvertFrom-DbLines([string[]]$Lines) {
    $bytes = New-Object Collections.Generic.List[byte]
    foreach ($l in $Lines) {
        if ($l -match '^(?:[0-9a-f]{8}`)?[0-9a-f]{8}  ((?:[0-9a-f]{2}[ -]){1,16})') {
            foreach ($h in ($Matches[1].Trim() -split '[ -]+')) { if ($h) { $bytes.Add([Convert]::ToByte($h, 16)) } }
        }
    }
    return , $bytes.ToArray()
}

function ConvertFrom-DdLines([string[]]$Lines) {
    $values = New-Object Collections.Generic.List[int]
    foreach ($l in $Lines) {
        if ($l -match '^(?:[0-9a-f]{8}`)?[0-9a-f]{8}  ((?:[0-9a-f]{8} ?){1,4})') {
            foreach ($h in ($Matches[1].Trim() -split ' +')) { if ($h) { $values.Add([BitConverter]::ToInt32([BitConverter]::GetBytes([Convert]::ToUInt32($h, 16)), 0)) } }
        }
    }
    return , $values.ToArray()
}

# Value of the 'dx' / '?' output line that follows a marker line.
function Get-MarkedValue([string[]]$Block, [string]$Marker) {
    for ($i = 0; $i -lt $Block.Count; $i++) {
        if ($Block[$i] -ne $Marker) { continue }
        # Commands from a -cf file are echoed with the prompt (e.g. '0:087> ? @$t3'); skip those lines.
        $j = $i + 1
        while ($j -lt $Block.Count -and $Block[$j] -match '^\d+:\d+(:x86)?> ') { $j++ }
        $next = if ($j -lt $Block.Count) { $Block[$j] } else { '' }
        if ($next -match '^Error|Unable to|memory read error') { return $null }
        if ($next -match ': (?:0x[0-9a-f`]+ : )?"(?<s>.*)" \[Type:') { return $Matches['s'] }
        if ($next -match 'Evaluate expression: (?<n>-?\d+) =') { return $Matches['n'] }
        if ($next -match ': 0x[0-9a-f`]+ : (?<sym>[^\s\[]+) \[Type:') { return $Matches['sym'] }
        if ($next -match ': (?<n>-?\d+) \[Type:') { return $Matches['n'] }
        return $null
    }
    return $null
}

function Get-MarkedRange([string[]]$Block, [string]$Marker) {
    $start = [Array]::IndexOf($Block, $Marker)
    if ($start -lt 0) { return @() }
    $out = @()
    for ($i = $start + 1; $i -lt $Block.Count; $i++) {
        if ($Block[$i] -match '^LF_[A-Z]+$') { break }
        $out += $Block[$i]
    }
    return $out
}

# luaG_getfuncline of Lua 5.4/5.5: absolute base line from abslineinfo plus the relative deltas in lineinfo.
function Get-Lua54Line([int]$Pc, [int]$LineDefined, [int[]]$AbsPairs, [byte[]]$LineInfo) {
    if (-not $LineInfo -or $LineInfo.Count -eq 0) { return $null }
    $basePc = -1; $line = $LineDefined
    for ($i = 0; $i + 1 -lt $AbsPairs.Count; $i += 2) {
        if ($AbsPairs[$i] -le $Pc) { $basePc = $AbsPairs[$i]; $line = $AbsPairs[$i + 1] } else { break }
    }
    while ($basePc -lt $Pc) {
        $basePc++
        if ($basePc -ge $LineInfo.Count) { return $null }
        $delta = [int]$LineInfo[$basePc]; if ($delta -gt 127) { $delta -= 256 }
        $line += $delta
    }
    return $line
}

function ConvertFrom-LuaContext([string[]]$Lines, [string]$LuaFlavor) {
    $frames = @()
    $blocks = @()
    $current = $null
    foreach ($l in $Lines) {
        if ($l -eq '<<<LUAFRAME>>>') { if ($null -ne $current) { $blocks += , $current.ToArray() }; $current = New-Object Collections.Generic.List[string]; continue }
        if ($null -ne $current) { $current.Add($l) }
    }
    if ($null -ne $current) { $blocks += , $current.ToArray() }
    $level = 0
    foreach ($b in $blocks) {
        $level++
        $tt = Get-MarkedValue $b 'LF_TT'
        $ttValue = if ($tt) { [int64]$tt } else { -1 }
        if (($ttValue -band 0x3f) -eq 6) {
            $source = Get-MarkedValue $b 'LF_SRC'
            $def = Get-MarkedValue $b 'LF_DEF'
            $line = $null
            if ($LuaFlavor -eq '5.3') { $line = Get-MarkedValue $b 'LF_LINE' }
            else {
                $pcText = Get-MarkedValue $b 'LF_PC'
                if ($pcText -and $def) { $line = Get-Lua54Line ([int]$pcText) ([int]$def) (ConvertFrom-DdLines (Get-MarkedRange $b 'LF_ABS')) (ConvertFrom-DbLines (Get-MarkedRange $b 'LF_LI')) }
            }
            $protoText = Get-MarkedValue $b 'LF_PROTO'
            $frames += [pscustomobject][ordered]@{ level = $level; kind = 'Lua'; source = $source; lineDefined = $def; lastLineDefined = (Get-MarkedValue $b 'LF_LAST'); line = $line; cFunction = $null; text = $null; proto = $(if ($protoText) { '0x{0:x}' -f [uint64]$protoText } else { $null }); upvalueNames = @(); localNames = @(); stringConstants = @() }
        }
        elseif ($ttValue -eq 0x16 -or ($ttValue -band 0x3f) -eq 0x26) {
            $frames += [pscustomobject][ordered]@{ level = $level; kind = 'C'; source = $null; lineDefined = $null; lastLineDefined = $null; line = $null; cFunction = (Get-MarkedValue $b 'LF_CFN'); text = $null; proto = $null; upvalueNames = @(); localNames = @(); stringConstants = @() }
        }
        else {
            $kindText = if ($ttValue -eq 0) { 'base (entered from C++)' } else { "other (tt=$tt)" }
            $frames += [pscustomobject][ordered]@{ level = $level; kind = $kindText; source = $null; lineDefined = $null; lastLineDefined = $null; line = $null; cFunction = $null; text = $null; proto = $null; upvalueNames = @(); localNames = @(); stringConstants = @() }
        }
    }
    return $frames
}

# Parses the Lua text that the Web API sends through SCI (bundled libraries, request message). Credentials and the
# access token payload are masked in the returned text.
function ConvertFrom-SciScript([string]$Text) {
    $info = [ordered]@{ sizeBytes = $Text.Length; modules = @(); topic = $null; contentType = $null; endpoint = $null; method = $null; remoteIp = $null; referer = $null; userAgent = $null; payload = $null; payloadEncoding = $null; maskedText = $Text; notes = @() }
    $info.modules = @([regex]::Matches($Text, "package\.loaded\[\s*['""]([^'""]+)['""]\s*\]\s*=") | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
    $topic = [regex]::Match($Text, '(?s)\btopic\s*=\s*\[\[(.*?)\]\]'); if ($topic.Success) { $info.topic = $topic.Groups[1].Value }
    $ct = [regex]::Match($Text, '(?s)\["content-type"\]\s*=\s*\[\[(.*?)\]\]'); if ($ct.Success) { $info.contentType = $ct.Groups[1].Value }
    $payload = [regex]::Match($Text, '(?s)\bpayload\s*=\s*\[\[(.*?)\]\]')
    if ($payload.Success) {
        $raw = $payload.Groups[1].Value
        $info.payload = $raw; $info.payloadEncoding = 'raw'
        if ($raw -match '^[A-Za-z0-9+/=\s]+$' -and $raw.Trim().Length % 4 -eq 0 -and $raw.Trim().Length -gt 0) {
            try {
                $decoded = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($raw.Trim()))
                $printable = @($decoded.ToCharArray() | Where-Object { [int]$_ -ge 32 -or $_ -match '\s' }).Count
                if ($decoded.Length -gt 0 -and $printable / $decoded.Length -gt 0.95) { $info.payload = $decoded; $info.payloadEncoding = 'base64-decoded' }
            }
            catch { }
        }
    }
    $req = [regex]::Match($Text, '(?s)\breq\s*=\s*\[\[(.*?)\]\]')
    if ($req.Success) {
        $masked = $null
        try {
            $json = $req.Groups[1].Value | ConvertFrom-Json
            $info.method = Get-Cfg $json 'method' $null
            $url = Get-Cfg $json 'url' $null
            if ($url) { $info.endpoint = "$(Get-Cfg $url 'pathname' '')$([Uri]::UnescapeDataString([string](Get-Cfg $url 'search' '')))" }
            $info.remoteIp = Get-Cfg $json 'remote_ip_address' $null
            $headers = Get-Cfg $json 'headers' $null
            if ($headers) {
                $info.referer = Get-Cfg $headers 'Referer' $null
                $info.userAgent = Get-Cfg $headers 'User-Agent' $null
                foreach ($h in @($headers.PSObject.Properties | Where-Object { $_.Name -match '^(Authorization|Cookie|Set-Cookie|X-Api-Key|Proxy-Authorization)$' })) { $h.Value = '***masked***' }
            }
            foreach ($prop in @($json.PSObject.Properties | Where-Object { $_.Name -match 'token|password|secret|credential' })) { $prop.Value = '***masked***' }
            $masked = $json | ConvertTo-Json -Depth 20 -Compress
        }
        catch { $info.notes += "Request JSON could not be parsed ($($_.Exception.Message)); it was removed from the saved script." }
        if (-not $masked) { $masked = '<removed: request could not be parsed for masking>' }
        $info.maskedText = $Text.Substring(0, $req.Groups[1].Index) + $masked + $Text.Substring($req.Groups[1].Index + $req.Groups[1].Length)
    }
    return [pscustomobject]$info
}

# cdb fragment that prints the contents of the TString* in pseudo-register $t8 (layout per Lua version).
function Get-LuaStringCommand([string]$LuaFlavor) {
    switch ($LuaFlavor) {
        '5.3' { return 'dx -r0 (char*)((TString*)@$t8 + 1)' }
        '5.4' { return 'dx -r0 (char*)((TString*)@$t8)->contents' }
        default { return 'r $t7 = @@c++(((TString*)@$t8)->shrlen); .if ((@$t7 & 0x80) == 0) { dx -r0 (char*)&((TString*)@$t8)->contents } .else { dx -r0 ((TString*)@$t8)->contents }' }
    }
}

# Third cdb pass: string constants, upvalue names and local variable names of the given Lua function prototypes.
function New-ProtoCommands([string[]]$Protos, [string]$LuaFlavor, [bool]$Wow64) {
    $str = Get-LuaStringCommand $LuaFlavor
    $cmds = New-Object Collections.Generic.List[string]
    if ($Wow64) { $cmds.Add('.load wow64exts'); $cmds.Add('!sw') }
    foreach ($proto in $Protos) {
        $p = '((Proto*)@$t5)'
        $cmds.Add(".echo <<<PROTO:$proto>>>")
        $cmds.Add("r `$t5 = $proto")
        foreach ($part in @(
                @('sizek', 'PK', "r `$t2 = @@c++($p->k[@`$t1].tt_); .if (((@`$t2 & 0x3f) == 4) | ((@`$t2 & 0x3f) == 0x14)) { r `$t8 = @@c++($p->k[@`$t1].value_.gc); .echo PK; $str }"),
                @('sizeupvalues', 'PU', "r `$t8 = @@c++($p->upvalues[@`$t1].name); .if (@`$t8 != 0) { .echo PU; $str }"),
                @('sizelocvars', 'PL', "r `$t8 = @@c++($p->locvars[@`$t1].varname); .if (@`$t8 != 0) { .echo PL; $str }"))) {
            $cmds.Add("r `$t6 = @@c++($p->$($part[0]))")
            $cmds.Add('.if (@$t6 > 0n256) { r $t6 = 0n256 }')
            $cmds.Add(".for (r `$t1 = 0; @`$t1 < @`$t6; r `$t1 = @`$t1 + 1) { $($part[2]) }")
        }
    }
    $cmds.Add('.echo <<<PROTO:end>>>')
    $cmds.Add('q')
    return $cmds
}

function Get-MarkedValues([string[]]$Block, [string]$Marker) {
    $values = @()
    for ($i = 0; $i -lt $Block.Count; $i++) {
        if ($Block[$i] -eq $Marker) {
            $v = Get-MarkedValue $Block[$i..([Math]::Min($Block.Count - 1, $i + 3))] $Marker
            if ($null -ne $v) { $values += $v }
        }
    }
    return $values
}

# Parses 'db' output into a byte array that starts at $Start; unreadable bytes ('??') and gaps stay 0 (a string boundary).
function ConvertFrom-DbWindow([string[]]$Lines, [uint64]$Start, [int]$Length) {
    $bytes = New-Object byte[] $Length
    $regex = [regex]'^(?<a>[0-9a-f]{8}(?:`[0-9a-f]{8})?)  (?<h>(?:(?:[0-9a-f]{2}|\?\?)[ -]){1,16})'
    foreach ($l in $Lines) {
        $m = $regex.Match($l)
        if (-not $m.Success) { continue }
        $offset = [int64]([Convert]::ToUInt64(($m.Groups['a'].Value -replace '`', ''), 16) - $Start)
        foreach ($h in ($m.Groups['h'].Value.Trim() -split '[ -]+')) {
            if ($offset -ge 0 -and $offset -lt $Length -and $h -ne '??') { $bytes[$offset] = [Convert]::ToByte($h, 16) }
            $offset++
        }
    }
    return , $bytes
}

# Checks recovered text against the Lua prototypes of the chunk: the line of 'linedefined' must start a function, the
# line of 'lastlinedefined' must contain its 'end', and most string constants of the prototype must occur in between.
function Test-LuaLibraryText([string]$Text, $LuaFrames) {
    $lines = $Text -split "\r?\n"
    $validated = @()
    foreach ($lf in $LuaFrames) {
        if (-not $lf.lineDefined -or -not $lf.lastLineDefined) { continue }
        $def = [int]$lf.lineDefined; $last = [int]$lf.lastLineDefined
        if ($def -lt 1 -or $last -lt $def -or $last -gt $lines.Count) { continue }
        if ($lines[$def - 1] -notmatch '\bfunction\b' -or $lines[$last - 1] -notmatch '\bend\b') { continue }
        $body = $lines[($def - 1)..($last - 1)] -join "`n"
        $consts = @($lf.stringConstants | Where-Object { $_.Length -ge 3 })
        $found = @($consts | Where-Object { $body.Contains($_) }).Count
        if ($consts.Count -eq 0 -or $found / $consts.Count -ge 0.5) { $validated += "$def-$last" }
    }
    return , @($validated | Select-Object -Unique)
}

# Recovers the text of Lua libraries stored in the model (chunk names '@<object path>#<library>'), which are not in the
# repository and not part of the SCI entry script: reads the prototypes of their frames, searches process memory for
# distinctive names from them, and keeps the NUL-terminated text around a hit only if it matches the prototypes' lines.
function Invoke-LuaLibraryRecovery($Ctx, $LuaFrames, [string]$LuaFlavor, $Settings) {
    $libFrames = @($LuaFrames | Where-Object { $_.kind -eq 'Lua' -and $_.source -and $_.source.StartsWith('@') -and $_.proto })
    if ($libFrames.Count -eq 0) { return @() }
    $protos = @($libFrames | ForEach-Object { $_.proto } | Select-Object -Unique | Select-Object -First 16)
    $protoCmdFile = Join-Path $Ctx.OutDir 'lua-proto.cdb.txt'
    $protoLog = Join-Path $Ctx.OutDir 'lua-proto.log'
    Set-Content -LiteralPath $protoCmdFile -Value (New-ProtoCommands $protos $LuaFlavor $Ctx.Wow64) -Encoding ASCII
    Invoke-CdbScript $Ctx.Cdb $Ctx.Dump $Ctx.SymbolPath $Ctx.ImagePath $protoLog $protoCmdFile $Ctx.Timeout
    $protoBlocks = @{}
    $current = $null
    foreach ($l in (Get-Content -LiteralPath $protoLog)) {
        if ($l -match '^<<<PROTO:(?<p>[^>]+)>>>$') { $current = $Matches['p']; $protoBlocks[$current] = New-Object Collections.Generic.List[string]; continue }
        if ($current) { $protoBlocks[$current].Add($l) }
    }
    foreach ($lf in $libFrames) {
        if (-not $protoBlocks.ContainsKey($lf.proto)) { continue }
        $block = @($protoBlocks[$lf.proto])
        $lf.stringConstants = @(Get-MarkedValues $block 'PK')
        $lf.upvalueNames = @(Get-MarkedValues $block 'PU')
        $lf.localNames = @(Get-MarkedValues $block 'PL')
    }

    $stop = '^(syslib|string|table|require|pairs|ipairs|tostring|tonumber|setmetatable|getmetatable|rawget|rawset|format|insert|remove|concat|unpack|select|assert|error|pcall|xpcall|result|results|options|params|value|values|message|payload|response|request|object|objects|config|settings|default|findOne|collection|database|filter|projection|ObjectID|length|string_format|_ENV)$'
    $results = @()
    $maxAddress = if ($Ctx.Is32Bit) { '0xffffffff' } else { '0x7fffffffffff' }
    $window = [int](Get-Cfg $Settings 'windowBytes' 131072)
    foreach ($chunk in @($libFrames | ForEach-Object { $_.source } | Select-Object -Unique)) {
        $chunkFrames = @($libFrames | Where-Object { $_.source -eq $chunk })
        $names = @($chunkFrames | ForEach-Object { $_.upvalueNames }) + @($chunkFrames | ForEach-Object { $_.stringConstants } | Sort-Object Length -Descending) + @($chunkFrames | ForEach-Object { $_.localNames } | Sort-Object Length -Descending)
        $tokens = @($names | Where-Object { $_ -cmatch '^[A-Za-z_][A-Za-z0-9_]{5,63}$' -and $_ -notmatch $stop } | Select-Object -Unique | Select-Object -First ([int](Get-Cfg $Settings 'maxTokens' 3)))
        $lib = [ordered]@{ chunk = $chunk; recovered = $false; savedPath = $null; sizeBytes = $null; address = $null; validatedFunctions = @(); tokens = $tokens; candidatesChecked = 0; note = $null }
        $results += $lib
        if ($tokens.Count -eq 0) { $lib.note = 'No distinctive names in the prototypes (stripped bytecode?); search memory manually.'; continue }

        $searchFile = Join-Path $Ctx.OutDir 'lua-search.cdb.txt'
        $searchLog = Join-Path $Ctx.OutDir 'lua-search.log'
        $cmds = @(); foreach ($t in $tokens) { $cmds += ".echo <<<SEARCH:$t>>>", "s -[1]a 0 L?$maxAddress `"$t`"" }; $cmds += '.echo <<<SEARCH:end>>>', 'q'
        Set-Content -LiteralPath $searchFile -Value $cmds -Encoding ASCII
        Invoke-CdbScript $Ctx.Cdb $Ctx.Dump $Ctx.SymbolPath $Ctx.ImagePath $searchLog $searchFile $Ctx.Timeout
        $hitsByToken = [ordered]@{}
        $currentToken = $null
        foreach ($l in [IO.File]::ReadLines($searchLog)) {
            if ($l -match '^<<<SEARCH:(?<t>[^>]+)>>>$') { $currentToken = $Matches['t']; $hitsByToken[$currentToken] = New-Object Collections.Generic.List[uint64]; continue }
            if ($currentToken -and $l -match '^0x(?<a>[0-9a-f]{8}(?:`[0-9a-f]{8})?)\s*$') { $hitsByToken[$currentToken].Add([Convert]::ToUInt64(($Matches['a'] -replace '`', ''), 16)) }
        }
        # A name that occurs everywhere (e.g. 'Property') is not distinctive; rarest names first.
        $maxTokenHits = [int](Get-Cfg $Settings 'maxTokenHits' 500)
        $usable = @($hitsByToken.Keys | Where-Object { $_ -ne 'end' -and $hitsByToken[$_].Count -gt 0 -and $hitsByToken[$_].Count -le $maxTokenHits } | Sort-Object { $hitsByToken[$_].Count })
        $selected = New-Object Collections.Generic.List[uint64]
        $maxHits = [int](Get-Cfg $Settings 'maxHits' 6)
        foreach ($t in $usable) {
            foreach ($h in $hitsByToken[$t]) {
                if ($selected.Count -ge $maxHits) { break }
                $near = $false
                foreach ($s in $selected) { if ([Math]::Abs([double]$s - [double]$h) -lt $window) { $near = $true; break } }
                if (-not $near) { $selected.Add($h) }
            }
        }
        if ($selected.Count -eq 0) {
            $lib.note = "None of the names ($(@($hitsByToken.Keys | Where-Object { $_ -ne 'end' } | ForEach-Object { "$_ x$($hitsByToken[$_].Count)" }) -join ', ')) found in process memory with at most $maxTokenHits hits."
            continue
        }

        $winFile = Join-Path $Ctx.OutDir 'lua-window.cdb.txt'
        $winLog = Join-Path $Ctx.OutDir 'lua-window.log'
        $cmds = @(); foreach ($h in $selected) { $cmds += ('.echo <<<WIN:0x{0:x}>>>' -f $h), ('db 0x{0:x} L?0x{1:x}' -f ($h - [uint64]$window), (2 * $window)) }; $cmds += '.echo <<<WIN:end>>>', 'q'
        Set-Content -LiteralPath $winFile -Value $cmds -Encoding ASCII
        Invoke-CdbScript $Ctx.Cdb $Ctx.Dump $Ctx.SymbolPath $Ctx.ImagePath $winLog $winFile $Ctx.Timeout
        $winBlocks = @{}
        $current = $null
        foreach ($l in [IO.File]::ReadLines($winLog)) {
            if ($l -match '^<<<WIN:0x(?<a>[0-9a-f]+)>>>$') { $current = $Matches['a']; $winBlocks[$current] = New-Object Collections.Generic.List[string]; continue }
            if ($current) { $winBlocks[$current].Add($l) }
        }
        $best = $null
        $seen = @{}
        foreach ($h in $selected) {
            $key = '{0:x}' -f $h
            if (-not $winBlocks.ContainsKey($key)) { continue }
            $bytes = ConvertFrom-DbWindow @($winBlocks[$key]) ($h - [uint64]$window) (2 * $window)
            $s = $window; while ($s -gt 0 -and $bytes[$s - 1] -ne 0) { $s-- }
            $e = $window; while ($e -lt $bytes.Length -and $bytes[$e] -ne 0) { $e++ }
            if ($s -eq 0 -or $e -ge $bytes.Length) { continue }
            $text = [Text.Encoding]::UTF8.GetString($bytes, $s, $e - $s)
            if ($seen.ContainsKey($text)) { continue }
            $seen[$text] = $true
            $lib.candidatesChecked++
            $valid = Test-LuaLibraryText $text $chunkFrames
            if ($valid.Count -gt 0 -and (-not $best -or $valid.Count -gt $best.Valid.Count)) { $best = @{ Text = $text; Valid = $valid; Address = ($h - [uint64]$window + [uint64]$s) } }
        }
        if (-not $best) {
            $lib.note = "Text around $($selected.Count) memory hit(s) did not match the line ranges of the prototypes (library larger than 2 x windowBytes, or a different copy); search manually."
            continue
        }
        $fileName = 'library-' + (($chunk -replace '^.*[#/\\]', '') -replace '[^A-Za-z0-9_.-]', '_') + '.lua'
        $saved = Join-Path $Ctx.OutDir $fileName
        [IO.File]::WriteAllText($saved, (Protect-ScriptText $best.Text), [Text.UTF8Encoding]::new($false))
        $lines = $best.Text -split "\r?\n"
        foreach ($lf in @($LuaFrames | Where-Object { $_.source -eq $chunk })) {
            if ($lf.line -and [int]$lf.line -ge 1 -and [int]$lf.line -le $lines.Count) { $lf.text = $lines[[int]$lf.line - 1].Trim() }
        }
        $lib.recovered = $true; $lib.savedPath = $saved; $lib.sizeBytes = [Text.Encoding]::UTF8.GetByteCount($best.Text); $lib.address = '0x{0:x}' -f $best.Address; $lib.validatedFunctions = $best.Valid
    }
    return $results
}

#endregion

#region zipped dumps

# Expands *.zip inputs that contain .dmp files into the extract root (reused on later runs) and returns the dump paths
# together with the original archive. An entry whose SHA-256 equals a dump that is already part of the input (same
# size first, then hash of the entry stream) is not extracted; it is returned as a copy of that dump (Extracted = $false).
# PDB entries of every archive (dump zips that bundle their symbols, or symbol-only zips) are listed as Symbols; they are
# extracted later by Resolve-Pdb, only after their name matches, and used only if their GUID matches the dump.
function Expand-DumpArchives([string[]]$ZipPaths, [string]$ExtractRoot, [string[]]$ExistingDumps) {
    $result = @()
    $empty = @()
    $symbols = @()
    $pool = New-Object Collections.Generic.List[string]
    foreach ($d in @($ExistingDumps)) { if ($d) { $pool.Add($d) } }
    foreach ($zipPath in $ZipPaths) {
        $zipItem = Get-Item -LiteralPath $zipPath
        $zip = [IO.Compression.ZipFile]::OpenRead($zipPath)
        try {
            foreach ($pdbEntry in @($zip.Entries | Where-Object { $_.Name -match '\.pdb$' })) {
                $symbols += [pscustomobject]@{ Archive = $zipPath; Entry = $pdbEntry.FullName; Name = $pdbEntry.Name; SizeBytes = $pdbEntry.Length }
            }
            $entries = @($zip.Entries | Where-Object { $_.Name -match '\.dmp$' })
            if ($entries.Count -eq 0) {
                if (-not ($symbols | Where-Object { $_.Archive -eq $zipPath })) { $empty += $zipPath }
                continue
            }
            $target = Join-Path $ExtractRoot ('{0}_{1}' -f [IO.Path]::GetFileNameWithoutExtension($zipItem.Name), $zipItem.Length)
            foreach ($entry in $entries) {
                $sameSize = @($pool | Where-Object { (Get-Item -LiteralPath $_).Length -eq $entry.Length })
                if ($sameSize.Count -gt 0) {
                    Write-Host "Hashing $zipPath!$($entry.FullName) to compare with $($sameSize.Count) dump(s) of the same size ..."
                    $stream = $entry.Open()
                    try { $entryHash = Get-StreamSha256 $stream } finally { $stream.Dispose() }
                    $same = $sameSize | Where-Object { (Get-FileSha256 $_) -eq $entryHash } | Select-Object -First 1
                    if ($same) {
                        Write-Host "Not extracting $zipPath!$($entry.FullName): identical (SHA-256) to $same."
                        $result += [pscustomobject]@{ DumpPath = $same; Archive = $zipPath; Entry = $entry.FullName; SizeBytes = $entry.Length; Extracted = $false }
                        continue
                    }
                }
                $dest = Join-Path $target $entry.Name
                if ((Test-Path -LiteralPath $dest) -and (Get-Item -LiteralPath $dest).Length -eq $entry.Length) {
                    Write-Host "Reusing extracted $dest"
                }
                else {
                    New-Item -ItemType Directory -Force -Path $target | Out-Null
                    $drive = [IO.Path]::GetPathRoot($target)
                    $free = (New-Object IO.DriveInfo($drive)).AvailableFreeSpace
                    if ($free -lt $entry.Length + 1GB) { throw "Not enough disk space to extract $($entry.Name) ($([Math]::Round($entry.Length / 1GB, 2)) GB) to $target (free: $([Math]::Round($free / 1GB, 2)) GB). Set extractRoot in the config." }
                    Write-Host "Extracting $zipPath!$($entry.FullName) ($([Math]::Round($entry.Length / 1GB, 2)) GB) to $target ..."
                    [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, "$dest.partial", $true)
                    Move-Item -LiteralPath "$dest.partial" -Destination $dest -Force
                }
                $pool.Add($dest)
                $result += [pscustomobject]@{ DumpPath = $dest; Archive = $zipPath; Entry = $entry.FullName; SizeBytes = $entry.Length; Extracted = $true }
            }
        }
        finally { $zip.Dispose() }
    }
    return [pscustomobject]@{ Dumps = $result; EmptyArchives = $empty; Symbols = $symbols }
}

#endregion

#region main

# Without the source repository (e.g. a support engineer's machine) the dump is still analyzed: exception, symbolized
# stack, Lua/script context. Everything that needs git (build commit estimation, source lines, history, ports) is skipped.
$repo = $null
$sourceNote = $null
if ($NoSource) { $sourceNote = 'disabled with -NoSource' }
elseif ($RepoPath) {
    if ((Invoke-Git $RepoPath @('rev-parse', '--show-toplevel')).ExitCode -ne 0) { throw "Not a git repository: $RepoPath" }
    $repo = $RepoPath
}
elseif (-not (Get-Command git -ErrorAction SilentlyContinue)) { $sourceNote = 'git is not installed' }
else {
    $top = Invoke-Git $PSScriptRoot @('rev-parse', '--show-toplevel')
    if ($top.ExitCode -eq 0 -and $top.Lines.Count -gt 0 -and $top.Lines[0]) { $repo = $top.Lines[0] }
    else { $sourceNote = 'the collector does not run from a git clone of the repository' }
}
if (-not $repo) { Write-Host "Source repository not available ($sourceNote): build commit estimation, source lines and history are skipped." }

if (-not $ConfigPath) { $ConfigPath = $env:CRASH_DUMP_ANALYZER_CONFIG }
if (-not $ConfigPath) { $ConfigPath = Join-Path $PSScriptRoot 'crash-dump-analyzer.config.json' }
$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$gitConfig = Get-Cfg $config 'git' $null
$compareRef = Get-Cfg $gitConfig 'compareRef' 'origin/main-legacy'
$binaryMap = @{}
foreach ($prop in (Get-Cfg $config 'binaries' $null).PSObject.Properties) { $binaryMap[$prop.Name.ToLowerInvariant()] = $prop.Value }
$ownModules = @($binaryMap.Keys | ForEach-Object { [IO.Path]::GetFileNameWithoutExtension($_) })

$dumpOrigin = @{}
$extracted = @()
$archiveCopies = @()
$emptyArchives = @()
$bundledPdbs = @()
$extractRootPath = Expand-PathValue (Get-Cfg $config 'extractRoot' "$env:LOCALAPPDATA\inmation-crash-analysis\extracted")
if (Test-Path -LiteralPath $DumpPath -PathType Container) {
    $dumpFiles = @(Get-ChildItem -LiteralPath $DumpPath -Filter '*.dmp' -File -Recurse:$Recurse | Sort-Object FullName | ForEach-Object { $_.FullName })
    $zipFiles = @(Get-ChildItem -LiteralPath $DumpPath -Filter '*.zip' -File -Recurse:$Recurse | Sort-Object FullName | ForEach-Object { $_.FullName })
    if ($zipFiles.Count -gt 0) {
        $expansion = Expand-DumpArchives $zipFiles $extractRootPath $dumpFiles
        $extracted = @($expansion.Dumps | Where-Object { $_.Extracted })
        $archiveCopies = @($expansion.Dumps | Where-Object { -not $_.Extracted })
        $emptyArchives = @($expansion.EmptyArchives)
        $bundledPdbs = @($expansion.Symbols)
    }
    $dumpFiles = @($dumpFiles + @($extracted | ForEach-Object { $_.DumpPath }))
    if ($dumpFiles.Count -eq 0) { throw "No *.dmp files (or zip archives containing them) in $DumpPath" }
}
elseif (Test-Path -LiteralPath $DumpPath -PathType Leaf) {
    $resolved = (Resolve-Path -LiteralPath $DumpPath).Path
    if ($resolved -match '\.zip$') {
        $expansion = Expand-DumpArchives @($resolved) $extractRootPath @()
        $extracted = @($expansion.Dumps)
        $bundledPdbs = @($expansion.Symbols)
        if ($extracted.Count -eq 0) { throw "Archive contains no *.dmp file: $resolved" }
        $dumpFiles = @($extracted | ForEach-Object { $_.DumpPath })
    }
    else { $dumpFiles = @($resolved) }
}
else { throw "Dump path not found: $DumpPath" }
foreach ($x in $extracted) { $dumpOrigin[$x.DumpPath] = $x.Archive }
foreach ($z in $emptyArchives) { Write-Host "Archive without *.dmp or *.pdb entries (ignored): $z" }
foreach ($p in $bundledPdbs) { Write-Host "Symbol file in archive (used if its GUID matches a dump): $($p.Archive)!$($p.Entry)" }

# The same crash often arrives twice (raw dump and a zip of it, or two zips). Byte-identical dumps (same size, then same
# SHA-256) are analyzed once; the other copies are kept as provenance of the analyzed dump.
$dumpCopies = @{}
foreach ($c in $archiveCopies) {
    if (-not $dumpCopies.ContainsKey($c.DumpPath)) { $dumpCopies[$c.DumpPath] = @() }
    $dumpCopies[$c.DumpPath] += [ordered]@{ path = "$($c.Archive)!$($c.Entry)"; archive = $c.Archive; extracted = $false }
}
$duplicateOf = @{}
foreach ($sizeGroup in @($dumpFiles | Group-Object { (Get-Item -LiteralPath $_).Length } | Where-Object { $_.Count -gt 1 })) {
    $ordered = @($sizeGroup.Group | Sort-Object { if ($dumpOrigin.ContainsKey($_)) { 1 } else { 0 } }, { $_ })
    foreach ($hashGroup in @($ordered | Group-Object { Get-FileSha256 $_ } | Where-Object { $_.Count -gt 1 })) {
        $primary = $hashGroup.Group[0]
        foreach ($other in @($hashGroup.Group | Select-Object -Skip 1)) {
            $duplicateOf[$other] = $primary
            if (-not $dumpCopies.ContainsKey($primary)) { $dumpCopies[$primary] = @() }
            $dumpCopies[$primary] += [ordered]@{ path = $other; archive = $(if ($dumpOrigin.ContainsKey($other)) { $dumpOrigin[$other] } else { $null }); extracted = $dumpOrigin.ContainsKey($other) }
            Write-Host "Duplicate: $other is identical (SHA-256) to $primary; analyzing it once."
        }
    }
}
$inputDumpCount = $dumpFiles.Count + $archiveCopies.Count
$dumpFiles = @($dumpFiles | Where-Object { -not $duplicateOf.ContainsKey($_) })

$runDir = if ($OutDir) { $OutDir } else { Join-Path (Expand-PathValue (Get-Cfg $config 'workRoot' "$env:LOCALAPPDATA\inmation-crash-analysis\runs")) (Get-Date -Format 'yyyyMMdd-HHmmss') }
New-Item -ItemType Directory -Force -Path $runDir | Out-Null

$cdb = Find-Cdb $config
$fetchStatus = if ($repo) { 'skipped' } else { 'no source repository' }
if ($repo -and -not $SkipFetch -and (Get-Cfg $gitConfig 'fetch' $true)) {
    $env:GIT_TERMINAL_PROMPT = '0'
    Write-Host "Fetching $(Get-Cfg $gitConfig 'remote' 'origin') ..."
    $fetch = Invoke-Git $repo @('fetch', (Get-Cfg $gitConfig 'remote' 'origin'), '--quiet')
    $fetchStatus = if ($fetch.ExitCode -eq 0) { 'ok' } else { "failed (exit $($fetch.ExitCode)); using local refs" }
}
$compareCommit = (Invoke-Git $repo @('rev-parse', '--verify', '--quiet', "$compareRef^{commit}")).Lines | Select-Object -First 1
$refCommitCache = @{ $compareRef = $compareCommit }
$results = @()
$usedOutNames = @{}
foreach ($dumpFile in $dumpFiles) {
    $dumpName = [IO.Path]::GetFileName($dumpFile)
    Write-Host "=== $dumpName ==="
    # Different dumps can share a file name (e.g. the same PID on two machines); never let one overwrite the other's output.
    $outName = $dumpName
    for ($n = 2; $usedOutNames.ContainsKey($outName.ToLowerInvariant()); $n++) { $outName = "$dumpName-$n" }
    $usedOutNames[$outName.ToLowerInvariant()] = $true
    $dumpOut = Join-Path $runDir $outName
    New-Item -ItemType Directory -Force -Path $dumpOut | Out-Null
    $errors = @()
    $copies = if ($dumpCopies.ContainsKey($dumpFile)) { @($dumpCopies[$dumpFile]) } else { @() }
    $sha = if ($script:sha256Cache.ContainsKey($dumpFile.ToLowerInvariant())) { $script:sha256Cache[$dumpFile.ToLowerInvariant()] } else { $null }
    $entry = [ordered]@{ dump = [ordered]@{ path = $dumpFile; archive = $(if ($dumpOrigin.ContainsKey($dumpFile)) { $dumpOrigin[$dumpFile] } else { $null }); sha256 = $sha; copies = $copies; sizeBytes = $null; crashTimeUtc = $null; processStartUtc = $null; uptime = $null; uptimeSeconds = $null; processId = $null; architecture = $null; wow64 = $null }; module = $null; exception = $null; assertion = $null; symbols = $null; blocked = $null; build = $null; compare = $null; analyze = $null; signature = $null; crashStack = @(); rawStack = @(); thirdParty = @(); luaStack = @(); luaLibraries = @(); scriptContext = @(); registers = $null; disassembly = $null; localsTop = $null; sourceHistory = @(); files = $null; errors = $null }

    try {
        $info = Read-MinidumpInfo $dumpFile
        $module = $info.Modules | Where-Object { $binaryMap.ContainsKey($_.Name.ToLowerInvariant()) } | Select-Object -First 1
        if (-not $module) { $module = $info.Modules | Select-Object -First 1; $errors += "No configured binary ($($binaryMap.Keys -join ', ')) in dump; main module is $($module.Name)." }
        $isWow64 = ($info.Architecture -eq 'x64' -and $module.Name -ieq 'inmation32.exe')
        $entry.dump = [ordered]@{ path = $dumpFile; archive = $entry.dump.archive; sha256 = $sha; copies = $copies; sizeBytes = $info.SizeBytes; crashTimeUtc = $info.CrashTimeUtc; processStartUtc = $info.ProcessStartUtc; uptime = $info.Uptime; uptimeSeconds = $info.UptimeSeconds; processId = $info.ProcessId; architecture = $info.Architecture; wow64 = $isWow64 }
        $entry.module = [ordered]@{ name = $module.Name; path = $module.Path; fileVersion = $module.FileVersion; productVersionInformational = $module.ProductVersion; peTimeStampUtc = ([DateTimeOffset]::FromUnixTimeSeconds($module.TimeStamp)).UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ'); pdbGuid = $module.PdbGuid; pdbAge = $module.PdbAge; pdbBuildPath = $module.PdbPath }
        $entry.exception = $info.Exception
        if (-not $info.Exception) { $errors += 'Dump has no exception stream (likely a manual/hang dump); the stack is the current thread, not necessarily a crash.' }

        $vars = @{ version = $module.FileVersion }
        if ($module.FileVersion) {
            $v = $module.FileVersion.Split('.')
            $vars.major = $v[0]; $vars.minor = $v[1]; $vars.revision = $v[2]; $vars.build = $v[3]
        }
        else { $errors += 'Binary version not present in dump module list.' }

        $productLine = Get-ProductLine $config $vars
        $channel = Get-BuildChannel $config $vars
        $candidates = if ($module.FileVersion) { @(Get-BuildFolderCandidates $config $productLine $vars $channel $module) } else { @() }

        $symbols = $null
        $pdbName = if ($binaryMap.ContainsKey($module.Name.ToLowerInvariant())) { $binaryMap[$module.Name.ToLowerInvariant()] } else { [IO.Path]::GetFileName($module.PdbPath) }
        $dumpDirs = @((Split-Path $dumpFile -Parent))
        if ($dumpOrigin.ContainsKey($dumpFile)) { $dumpDirs += (Split-Path $dumpOrigin[$dumpFile] -Parent) }
        $ownArchives = @(@($(if ($dumpOrigin.ContainsKey($dumpFile)) { $dumpOrigin[$dumpFile] })) + @($copies | ForEach-Object { $_.archive }) | Where-Object { $_ })
        $dumpBundledPdbs = @(@($bundledPdbs | Where-Object { $ownArchives -contains $_.Archive }) + @($bundledPdbs | Where-Object { $ownArchives -notcontains $_.Archive }))
        try {
            Write-Host "Resolving $pdbName ($($module.PdbGuid) age $($module.PdbAge)) ..."
            $symbols = Resolve-Pdb $config $module $pdbName $candidates $PdbPath $dumpDirs $dumpBundledPdbs
        }
        catch { $errors += "Symbols: $($_.Exception.Message)" }

        # The build folder used for build_info, manifest and binaries is the one that holds this binary: where the PDB
        # was found, else the first folder whose binary matches the dump, else the first candidate.
        $versionHit = $null
        if ($symbols -and $symbols.Candidate) { $versionHit = $symbols.Candidate }
        if (-not $versionHit) { $versionHit = $candidates | Where-Object { $_.State -eq 'match' } | Select-Object -First 1 }
        if (-not $versionHit) { $versionHit = $candidates | Where-Object { $_.State -ne 'mismatch' } | Select-Object -First 1 }
        if (-not $versionHit) { $versionHit = $candidates | Select-Object -First 1 }
        $versionDir = if ($versionHit) { $versionHit.Path } else { $null }
        $brand = if ($versionHit) { $versionHit.Brand } else { $null }
        if ($versionHit -and $versionHit.State -eq 'mismatch') {
            $errors += "No build folder holds this exact binary; build information is taken from $versionDir, whose binary differs (GUID $($versionHit.ExeGuid)). $(Format-CandidateList $candidates $module)"
        }
        if ($versionHit -and $versionHit.Channel -ne $channel) {
            $errors += "Build folder found on the $($versionHit.Channel) share although v$($module.FileVersion) looks like a $channel build: $versionDir"
        }
        if (-not $versionDir -and $module.FileVersion -and -not $PdbPath) {
            $nearby = Get-NearbyVersions $productLine $vars $channel
            $searchedRoots = @($productLine.ReleaseRoots) + @($productLine.DevRoots) + @($productLine.BrandedReleaseRoots) + @($productLine.BrandedDevRoots)
            $pdbHint = if ($symbols) { "Symbols were found elsewhere ($($symbols.Source)); build_info and manifest are unavailable." } else { 'Dev builds may have been cleaned up; ask for the PDB.' }
            $errors += "Build folder for v$($module.FileVersion) not found on the shares of product line '$($productLine.Name)' ($channel build expected; searched $($searchedRoots -join ', ')). Same major.minor on shares: $(if ($nearby) { $nearby -join ', ' } else { 'none' }). $pdbHint"
        }
        $brokenMarker = if ($versionDir) { Join-Path $versionDir 'BROKENBUILD' } else { $null }
        $brokenBuild = [bool]($brokenMarker -and (Test-Path -LiteralPath $brokenMarker))
        $candidateSummary = @($candidates | ForEach-Object { [ordered]@{ path = $_.Path; channel = $_.Channel; brand = $_.Brand; brandHint = $_.BrandHint; binaryGuid = $_.ExeGuid; binaryLinkedUtc = $_.ExeTimeUtc; state = $_.State } })
        $entry.symbols = [ordered]@{ pdbName = $pdbName; pdbPath = if ($symbols) { $symbols.PdbPath } else { $null }; source = if ($symbols) { $symbols.Source } else { $null }; guidVerified = [bool]$symbols; versionDir = $versionDir; brand = $brand; buildFolderCandidates = $candidateSummary; loadStatus = $null; cdbSymbolPath = $null; cdbImagePath = $null }

        $buildTime = Get-BuildTime $config $versionDir $module
        $buildInfo = Read-BuildInfo $config $versionDir
        $buildCompare = [pscustomobject]@{ Ref = $productLine.CompareRef; Reason = "compare ref of product line '$($productLine.Name)'" }
        $build = Find-BuildCommit $config $repo $vars $buildTime $buildInfo $buildCompare.Ref
        $build.version = $module.FileVersion
        $build.productLine = $productLine.Name
        $build.channel = $channel
        $build.folder = $versionDir
        $build.brand = $brand
        $build.folderChannel = if ($versionHit) { $versionHit.Channel } else { $null }
        $build.brokenBuildMarker = $brokenBuild
        $build.buildTimeUtc = if ($buildTime) { $buildTime.TimeUtc.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null }
        $build.buildTimeSource = if ($buildTime) { $buildTime.Source } else { $null }
        $entry.build = $build

        # The compare ref depends on the product line (major version). Dev builds are analyzed on the latest code of
        # their line; if build_info names a source branch that does not flow into that ref, use that branch's head.
        $baseCompareRef = $buildCompare.Ref
        if (-not $refCommitCache.ContainsKey($baseCompareRef)) {
            $refCommitCache[$baseCompareRef] = (Invoke-Git $repo @('rev-parse', '--verify', '--quiet', "$baseCompareRef^{commit}")).Lines | Select-Object -First 1
        }
        $baseCompareCommit = $refCommitCache[$baseCompareRef]
        if (-not $baseCompareCommit -and $repo) { $errors += "Compare ref $baseCompareRef does not exist in this repository (fetch it or fix git.compareRef / git.compareRefByMajor)." }
        $dumpCompareRef = $baseCompareRef
        $dumpCompareCommit = $baseCompareCommit
        $compareReason = $buildCompare.Reason
        if ($build.commit -and $baseCompareCommit -and $channel -eq 'dev' -and $build.sourceBranch -match '^refs/heads/(.+)$') {
            $sourceRef = "$(Get-Cfg $gitConfig 'remote' 'origin')/$($Matches[1])"
            $inCompare = (Invoke-Git $repo @('merge-base', '--is-ancestor', $build.commit, $baseCompareCommit)).ExitCode -eq 0
            $sourceCommit = (Invoke-Git $repo @('rev-parse', '--verify', '--quiet', "$sourceRef^{commit}")).Lines | Select-Object -First 1
            if (-not $inCompare -and $sourceCommit -and $sourceRef -ne $baseCompareRef) {
                $dumpCompareRef = $sourceRef
                $dumpCompareCommit = $sourceCommit
                $compareReason = "dev build from $($build.sourceBranch), which is not part of $baseCompareRef"
            }
        }

        $isAncestor = $null
        $mergeBase = $null
        if ($build.commit -and $dumpCompareCommit) {
            $isAncestor = ((Invoke-Git $repo @('merge-base', '--is-ancestor', $build.commit, $dumpCompareCommit)).ExitCode -eq 0)
            $mergeBase = (Invoke-Git $repo @('merge-base', $build.commit, $dumpCompareCommit)).Lines | Select-Object -First 1
        }
        $entry.compare = [ordered]@{ ref = $dumpCompareRef; commit = $dumpCompareCommit; reason = $compareReason; buildCommitIsAncestor = $isAncestor; mergeBase = $mergeBase; fetch = $fetchStatus }

        # cdb
        $symbolPathParts = @()
        if ($symbols) { $symbolPathParts += $symbols.SymbolDir }
        if (Get-Cfg $config 'useMicrosoftSymbolServer' $false) {
            $symbolPathParts += "srv*$(Expand-PathValue (Get-Cfg $config 'localSymbolCache' "$env:LOCALAPPDATA\inmation-crash-analysis\symbols"))\ms*https://msdl.microsoft.com/download/symbols"
        }
        if ($symbolPathParts.Count -eq 0) { $symbolPathParts += $dumpOut }
        $imagePath = $null
        if ($versionDir) {
            $candidateImageDir = Join-Path $versionDir (Get-Cfg $config 'binaryFolder' 'inmation.root\bin')
            if (Test-Path -LiteralPath $candidateImageDir) { $imagePath = $candidateImageDir }
        }

        # .ecxr sets the register context once; the following commands keep using it.
        $commands = @()
        if ($isWow64) { $commands += '.load wow64exts', '!sw' }
        $commands += '.reload /f'
        foreach ($s in @(
                @('analyze', '!analyze -v'),
                @('exr', '.exr -1'),
                @('ecxr', '.ecxr'),
                @('stack', 'kn 80'),
                @('disasm_before', 'ub @$scopeip L20'),
                @('disasm_after', 'u @$scopeip L8'),
                @('frame0_dx', '.frame 0', 'dx -r2 @$curframe.LocalVariables'))) {
            $commands += ".echo <<<SECTION:$($s[0])>>>"
            $commands += $s[1..($s.Count - 1)]
        }
        $commands += '.echo <<<SECTION:locals>>>'
        for ($f = 0; $f -lt 6; $f++) { $commands += ".frame $f", 'dv /t /v' }
        $commands += '.echo <<<SECTION:modules>>>'
        foreach ($own in $ownModules) { $commands += "lmv m $own" }
        $commands += '.echo <<<SECTION:threads>>>', '~* kn 40', '.echo <<<SECTION:end>>>', 'q'

        $cdbLog = Join-Path $dumpOut 'cdb.log'
        $symbolPath = $symbolPathParts -join ';'
        $entry.symbols.cdbSymbolPath = $symbolPath
        $entry.symbols.cdbImagePath = $imagePath
        Write-Host 'Running cdb ...'
        Invoke-Cdb $cdb $dumpFile $symbolPath $imagePath $cdbLog $commands ([int](Get-Cfg $config 'cdbTimeoutSeconds' 900))
        $sections = Split-CdbSections (Get-Content -LiteralPath $cdbLog)

        $analyzeLines = Get-Section $sections 'analyze'
        $analyze = [ordered]@{}
        foreach ($line in $analyzeLines) {
            if ($line -match '^(FAULTING_LOCAL_VARIABLE_NAME|EXCEPTION_CODE_STR|FAILURE_BUCKET_ID|SYMBOL_NAME|PRIMARY_PROBLEM_CLASS|READ_ADDRESS|WRITE_ADDRESS|EXCEPTION_PARAMETER1|EXCEPTION_PARAMETER2|ERROR_CODE|FAULTING_THREAD|IMAGE_NAME|MODULE_NAME):\s*(.*)$') {
                if (-not $analyze.Contains($Matches[1])) { $analyze[$Matches[1]] = $Matches[2].Trim() }
            }
        }
        $entry.analyze = $analyze
        $entry.registers = (Get-Section $sections 'ecxr') -join "`n"
        $marked = $false
        $afterLines = @(foreach ($l in (Get-Section $sections 'disasm_after')) {
                if (-not $marked -and $l -match '^[0-9a-f]{8}') { $marked = $true; "$l    <<< faulting instruction" } else { $l }
            })
        $entry.disassembly = (@(Get-Section $sections 'disasm_before') + $afterLines) -join "`n"
        $locals = Get-Section $sections 'locals'
        $entry.localsTop = (@($locals | Select-Object -First 250)) -join "`n"
        $frame0Dx = Get-Section $sections 'frame0_dx'

        $moduleLines = Get-Section $sections 'modules'
        $statusLine = $moduleLines | Where-Object { $_ -match '\s\(([^)]*symbols[^)]*)\)' } | Select-Object -First 1
        if ($statusLine -and $statusLine -match '\s\(([^)]*symbols[^)]*)\)') { $entry.symbols.loadStatus = $Matches[1] }
        if ($entry.symbols.loadStatus -and $entry.symbols.loadStatus -notmatch 'private pdb') { $errors += "Symbols for $($module.Name) loaded as '$($entry.symbols.loadStatus)', not private PDB symbols." }

        # Symbol gate: without a GUID-verified PDB that cdb loaded as private symbols, function names are nearest exports
        # and source lines are missing, so nothing source-level (signature by function, build commit, source mapping,
        # Lua decoding) is produced for this dump. Only raw exception facts and module+RVA addresses are reported.
        $symbolsTrusted = [bool]($symbols -and $entry.symbols.loadStatus -match 'private pdb')
        $entry.symbols.trusted = $symbolsTrusted
        if (-not $symbolsTrusted) {
            $reason = if (-not $symbols) { 'no PDB with a matching GUID was found' } elseif (-not $entry.symbols.loadStatus) { 'cdb symbol load status could not be read' } else { "cdb loaded '$($entry.symbols.loadStatus)'" }
            $entry.blocked = [ordered]@{ reason = "Symbols not verified: $reason."; requiredPdb = $pdbName; pdbGuid = $module.PdbGuid; pdbAge = $module.PdbAge; binaryLinkedUtc = $entry.module.peTimeStampUtc; installPath = $module.Path }
            if ($build.commit) {
                $build.rejectedCommit = [ordered]@{ commit = $build.commit; confidence = $build.confidence; method = $build.method }
                $build.notes += "Build commit candidate $($build.commit) ($($build.confidence), $($build.method)) is NOT accepted: the symbols are not verified, so it cannot be validated against PDB source lines."
                $build.commit = $null; $build.confidence = 'none'; $build.method = $null; $build.subject = $null; $build.commitDateUtc = $null
                $entry.compare.buildCommitIsAncestor = $null; $entry.compare.mergeBase = $null
            }
        }

        $frames = @(ConvertFrom-CdbStack (Get-Section $sections 'stack'))
        if ($frames.Count -eq 0) { $errors += 'Could not parse the crashing stack; read cdb.log.' }
        foreach ($frame in $frames) {
            if ($build.commit -and $frame.sourceFile -and $ownModules -contains $frame.module) {
                $frame.repoPath = Convert-ToRepoPath $repo $build.commit $frame.sourceFile $config
                if ($frame.repoPath -and $frame.sourceLine) {
                    $fileLines = Get-GitFileLines $repo $build.commit $frame.repoPath
                    if ($fileLines) {
                        $start = [Math]::Max(1, $frame.sourceLine - 4); $end = [Math]::Min($fileLines.Count, $frame.sourceLine + 4)
                        $frame.buildSnippet = (@($start..$end | ForEach-Object { '{0}{1,6}: {2}' -f $(if ($_ -eq $frame.sourceLine) { '>' } else { ' ' }), $_, $fileLines[$_ - 1] })) -join "`n"
                        $short = Get-ShortFunctionName $frame.function
                        if ($short) {
                            $window = $fileLines[0..([Math]::Min($fileLines.Count, $frame.sourceLine) - 1)]
                            $frame.functionFoundAtBuildCommit = [bool](@($window | Where-Object { $_.Contains("$short(") }).Count)
                        }
                    }
                }
            }
        }
        # Third-party frames (vcpkg buildtrees / vcpkg_installed headers): port, version and patches at build and compare ref.
        $portMap = [ordered]@{}
        foreach ($frame in @($frames | Where-Object { $symbolsTrusted })) {
            $tp = ConvertFrom-VcpkgSourcePath $frame.sourceFile
            if (-not $tp) { continue }
            $frame.thirdParty = $tp
            if (-not $tp.port) { continue }
            if (-not $portMap.Contains($tp.port)) {
                $portMap[$tp.port] = [ordered]@{
                    port = $tp.port; versionInBuildPath = $tp.version; sourceDirInBuild = $tp.sourceDir; frames = @()
                    atBuildCommit = Get-PortInfo $config $repo $build.commit $tp.port
                    atCompareRef = Get-PortInfo $config $repo $dumpCompareCommit $tp.port
                    localSource = @()
                }
            }
            $portMap[$tp.port].frames += $frame.index
            $local = Find-LocalPortSource $config $repo $tp
            if ($local -and $portMap[$tp.port].localSource.Count -lt 5) { $portMap[$tp.port].localSource += [ordered]@{ frame = $frame.index; path = $local.path; exactBuildTree = $local.exact } }
        }
        $entry.thirdParty = @($portMap.Values)

        $entry.crashStack = $frames
        $localsByFrame = Split-LocalsByFrame $locals
        $entry.assertion = Get-AssertionInfo $frames $localsByFrame $info.Exception
        # Signature: skip frames that only report the failure (abort, assert handlers, raise, terminate, ...).
        $top = $frames | Where-Object { -not (Test-NoiseFrame $_) } | Select-Object -First 1
        $noApplicationFrame = -not $top
        if (-not $top) { $top = $frames | Select-Object -First 1 }
        $firstOwn = if (-not $top) { $null } else { $frames | Where-Object { $_.index -ge $top.index -and $ownModules -contains $_.module -and -not $_.thirdParty -and $_.sourceFile -notmatch '[\\/](vcpkg|minkernel|vctools)[\\/]' } | Select-Object -First 1 }
        $signature = if ($top) { if ($firstOwn -and $firstOwn -ne $top) { "$($top.callSite) <- $($firstOwn.callSite)" } else { $top.callSite } } else { $null }
        if ($noApplicationFrame -and $signature) { $signature = "$signature [no application frame unwound]" }
        if ($entry.assertion -and $entry.assertion.expression) { $signature = "assert '$($entry.assertion.expression)' in $signature" }
        elseif ($entry.assertion) { $signature = "$($entry.assertion.function) in $signature" }
        if (-not $symbolsTrusted) {
            # Raw identity only: same binary (PDB GUID) and same faulting RVA. Never merged with symbolized signatures.
            $entry.rawStack = @(Get-RawStack $frames $(if ($info.Exception) { $info.Exception.address } else { $null }) $info.Modules)
            $entry.assertion = $null
            $rawTop = @($entry.rawStack | Where-Object { $_.address }) | Select-Object -First 1
            $excCode = if ($info.Exception) { $info.Exception.code } else { 'no exception' }
            $signature = "[unverified symbols] $excCode at $(if ($rawTop) { $rawTop.address } else { 'unknown address' }) (v$($module.FileVersion), PDB $($module.PdbGuid))"
        }
        $entry.signature = $signature

        # Second cdb pass: Lua call chain and script/request strings of configured entry frames.
        $hasLua = [bool]($frames | Where-Object { $_.function -match '^(luaV_execute|luaD_precall|lua_pcallk|lua_callk|luaD_call)$' } | Select-Object -First 1)
        $scriptFrames = @()
        foreach ($sc in @(Get-Cfg $config 'scriptContextFrames' @())) {
            $hit = $frames | Where-Object { $_.function -eq (Get-Cfg $sc 'function' '') } | Select-Object -First 1
            if ($hit) { $scriptFrames += [pscustomobject]@{ Frame = $hit.index; Variable = (Get-Cfg $sc 'variable' 'script'); Kind = (Get-Cfg $sc 'kind' $hit.function); Function = $hit.function } }
        }
        if ($symbolsTrusted -and ($hasLua -or $scriptFrames.Count -gt 0)) {
            # The Lua version decides the struct layout; without the repository, take it from the lua port's build path.
            $luaVersion = $null
            if ($portMap.Contains('lua')) {
                if ($portMap['lua'].atBuildCommit) { $luaVersion = $portMap['lua'].atBuildCommit.version }
                if (-not $luaVersion -and $portMap['lua'].versionInBuildPath) { $luaVersion = $portMap['lua'].versionInBuildPath -replace '^v', '' }
            }
            else {
                $luaPort = Get-PortInfo $config $repo $(if ($build.commit) { $build.commit } else { $dumpCompareCommit }) 'lua'
                if ($luaPort) { $luaVersion = $luaPort.version }
            }
            $luaFlavor = Get-LuaFlavor $luaVersion
            $maxScript = [int](Get-Cfg $config 'maxScriptBytes' 2000000)
            $contextCmdFile = Join-Path $dumpOut 'context.cdb.txt'
            $contextLog = Join-Path $dumpOut 'context.log'
            $ctxFrames = if ($hasLua) { $frames } else { @() }
            Set-Content -LiteralPath $contextCmdFile -Value (New-ContextCommands $ctxFrames $luaFlavor $scriptFrames $maxScript $isWow64) -Encoding ASCII
            Write-Host "Running cdb (Lua / script context, Lua $luaFlavor layout) ..."
            try {
                Invoke-CdbScript $cdb $dumpFile $symbolPath $imagePath $contextLog $contextCmdFile ([int](Get-Cfg $config 'cdbTimeoutSeconds' 900))
                $ctxLines = @(Get-Content -LiteralPath $contextLog)
                $ctxSections = [ordered]@{}
                $currentName = $null
                foreach ($l in $ctxLines) {
                    if ($l -match '^<<<CTX:(?<name>[^>]+)>>>$') { $currentName = $Matches['name']; $ctxSections[$currentName] = New-Object Collections.Generic.List[string]; continue }
                    if ($currentName) { $ctxSections[$currentName].Add($l) }
                }
                $scriptTexts = @()
                foreach ($sf in $scriptFrames) {
                    $name = "script:$($sf.Frame)"
                    if (-not $ctxSections.Contains($name)) { continue }
                    $block = @($ctxSections[$name])
                    $size = Get-MarkedValue $block 'SCRIPT_SIZE'
                    $from = [Array]::IndexOf($block, 'SCRIPT_BYTES'); $to = [Array]::IndexOf($block, 'SCRIPT_END')
                    $bytes = if ($from -ge 0 -and $to -gt $from) { ConvertFrom-DbLines $block[($from + 1)..($to - 1)] } else { @() }
                    $ctx = [ordered]@{ frame = $sf.Frame; function = $sf.Function; kind = $sf.Kind; variable = $sf.Variable; declaredSize = $size; capturedBytes = $bytes.Count; truncated = ($size -and [int64]$size -gt $bytes.Count); savedScript = $null; request = $null }
                    if ($bytes.Count -gt 0) {
                        $text = [Text.Encoding]::UTF8.GetString($bytes)
                        $parsed = ConvertFrom-SciScript $text
                        $saved = Join-Path $dumpOut "script-frame$($sf.Frame).lua"
                        [IO.File]::WriteAllText($saved, $parsed.maskedText, [Text.UTF8Encoding]::new($false))
                        $ctx.savedScript = $saved
                        $ctx.request = [ordered]@{ modules = $parsed.modules; topic = $parsed.topic; contentType = $parsed.contentType; method = $parsed.method; endpoint = $parsed.endpoint; remoteIp = $parsed.remoteIp; referer = $parsed.referer; userAgent = $parsed.userAgent; payload = $parsed.payload; payloadEncoding = $parsed.payloadEncoding; notes = $parsed.notes }
                        $scriptTexts += , ($text -split "`r?`n")
                    }
                    $entry.scriptContext += $ctx
                }
                if ($ctxSections.Contains('lua')) {
                    $luaFrames = @(ConvertFrom-LuaContext @($ctxSections['lua']) $luaFlavor)
                    if ($scriptTexts.Count -eq 1) {
                        foreach ($lf in $luaFrames) {
                            if ($lf.kind -eq 'Lua' -and $lf.source -and $lf.source.StartsWith('=') -and $lf.line -and [int]$lf.line -ge 1 -and [int]$lf.line -le $scriptTexts[0].Count) { $lf.text = $scriptTexts[0][[int]$lf.line - 1].Trim() }
                        }
                    }
                    $entry.luaStack = $luaFrames
                    if ($luaFrames.Count -eq 0) { $errors += "Lua frames on the stack, but the CallInfo walk returned nothing (L not available in frames near the Lua VM?). See $contextLog." }
                    $recovery = Get-Cfg $config 'luaLibraryRecovery' $null
                    if ((Get-Cfg $recovery 'enabled' $true) -and @($luaFrames | Where-Object { $_.kind -eq 'Lua' -and $_.source -and $_.source.StartsWith('@') }).Count -gt 0) {
                        Write-Host 'Running cdb (Lua prototypes / model library recovery) ...'
                        try {
                            $recoveryCtx = [pscustomobject]@{ Cdb = $cdb; Dump = $dumpFile; SymbolPath = $symbolPath; ImagePath = $imagePath; OutDir = $dumpOut; Timeout = [int](Get-Cfg $config 'cdbTimeoutSeconds' 900); Wow64 = $isWow64; Is32Bit = ($isWow64 -or $info.Architecture -eq 'x86') }
                            $entry.luaLibraries = @(Invoke-LuaLibraryRecovery $recoveryCtx $luaFrames $luaFlavor $recovery)
                            foreach ($lib in @($entry.luaLibraries | Where-Object { -not $_.recovered })) { $errors += "Model library $($lib.chunk) not recovered from memory: $($lib.note)" }
                        }
                        catch { $errors += "Library recovery: $($_.Exception.Message)" }
                    }
                }
            }
            catch { $errors += "Context pass: $($_.Exception.Message)" }
        }

        if ($build.commit -and $dumpCompareCommit) {
            $histFiles = @($frames | Where-Object { $_.repoPath } | Select-Object -First ([int](Get-Cfg $config 'topFramesForHistory' 6)) | ForEach-Object { $_.repoPath } | Select-Object -Unique)
            foreach ($rel in $histFiles) {
                $log = Invoke-Git $repo @('log', '--format=%h%x09%ad%x09%an%x09%s', '--date=short', '-n', '60', "$($build.commit)..$dumpCompareCommit", '--', $rel)
                $existsNow = (Invoke-Git $repo @('cat-file', '-e', ('{0}:{1}' -f $dumpCompareCommit, $rel))).ExitCode -eq 0
                $entry.sourceHistory += [ordered]@{ file = $rel; existsInCompareRef = $existsNow; commitsNotInBuild = @($log.Lines | Where-Object { $_ }) }
            }
        }

        $threadsFile = Join-Path $dumpOut 'threads.txt'
        Set-Content -LiteralPath $threadsFile -Value (Get-Section $sections 'threads')
        $localsFile = Join-Path $dumpOut 'locals.txt'
        Set-Content -LiteralPath $localsFile -Value $locals
        $frame0DxFile = Join-Path $dumpOut 'frame0-locals-dx.txt'
        Set-Content -LiteralPath $frame0DxFile -Value $frame0Dx
        $analyzeFile = Join-Path $dumpOut 'analyze.txt'
        Set-Content -LiteralPath $analyzeFile -Value $analyzeLines
        $contextLogFile = Join-Path $dumpOut 'context.log'
        $entry.files = [ordered]@{ cdbLog = $cdbLog; analyze = $analyzeFile; locals = $localsFile; frame0LocalsDx = $frame0DxFile; threads = $threadsFile; contextLog = $(if (Test-Path -LiteralPath $contextLogFile) { $contextLogFile } else { $null }); scripts = @($entry.scriptContext | Where-Object { $_.savedScript } | ForEach-Object { $_.savedScript }); libraries = @($entry.luaLibraries | Where-Object { $_.savedPath } | ForEach-Object { $_.savedPath }) }
    }
    catch {
        $errors += "Fatal: $($_.Exception.Message) at line $($_.InvocationInfo.ScriptLineNumber)"
    }
    $entry.errors = $errors
    $results += [pscustomobject]$entry
    $versionText = if ($entry.module) { $entry.module.fileVersion } else { '?' }
    $buildText = if ($entry.build) { "$($entry.build.commit) ($($entry.build.confidence), $($entry.build.channel))" } else { '?' }
    Write-Host ("  version={0} signature={1} build={2} errors={3}" -f $versionText, $entry.signature, $buildText, $errors.Count)
    if ($entry.blocked) { Write-Host "  BLOCKED: $($entry.blocked.reason) Only raw exception facts are valid for this dump." }
    foreach ($e in $errors) { Write-Host "  ! $e" }
}

$groups = @($results | Group-Object { if ($_.signature) { $_.signature } else { '<unknown>' } } | ForEach-Object {
        [ordered]@{ signature = $_.Name; count = $_.Count; blocked = [bool]($_.Group | Where-Object { $_.blocked }); dumps = @($_.Group | ForEach-Object { $_.dump.path }) }
    })

function Test-Writable([string]$Directory) {
    try {
        $probe = Join-Path $Directory ('.write-probe-' + [Guid]::NewGuid().ToString('N'))
        [IO.File]::WriteAllText($probe, '')
        Remove-Item -LiteralPath $probe -Force
        return $true
    }
    catch { return $false }
}

$reportDir = if (Test-Path -LiteralPath $DumpPath -PathType Container) { (Resolve-Path -LiteralPath $DumpPath).Path } else { Split-Path (Resolve-Path -LiteralPath $DumpPath).Path -Parent }
$reportName = if ($dumpFiles.Count -eq 1) { [IO.Path]::GetFileName($dumpFiles[0]) + '.crash-report.md' } else { 'crash-report.md' }
$reportPath = if (Test-Writable $reportDir) { Join-Path $reportDir $reportName } else { Join-Path $runDir $reportName }

$summary = [ordered]@{
    generatedUtc = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    repo         = $repo
    sourceAvailable = [bool]$repo
    sourceNote   = $sourceNote
    config       = (Resolve-Path -LiteralPath $ConfigPath).Path
    cdb          = $cdb
    compareRef   = $compareRef
    runDir       = $runDir
    reportPath   = $reportPath
    extractedDumps = @($extracted | ForEach-Object { [ordered]@{ dump = $_.DumpPath; archive = $_.Archive; sizeBytes = $_.SizeBytes } })
    inputDumpFiles = $inputDumpCount
    uniqueDumps  = $dumpFiles.Count
    duplicates   = @($dumpCopies.Keys | ForEach-Object { [ordered]@{ analyzed = $_; sha256 = $(if ($script:sha256Cache.ContainsKey($_.ToLowerInvariant())) { $script:sha256Cache[$_.ToLowerInvariant()] } else { $null }); copies = @($dumpCopies[$_]) } })
    emptyArchives = @($emptyArchives)
    bundledSymbols = @($bundledPdbs | ForEach-Object { [ordered]@{ archive = $_.Archive; entry = $_.Entry; sizeBytes = $_.SizeBytes } })
    blockedDumps = @($results | Where-Object { $_.blocked } | ForEach-Object { $_.dump.path })
    groups       = $groups
    dumps        = $results
}
$summaryPath = Join-Path $runDir 'summary.json'
$summary | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $summaryPath -Encoding UTF8

function Limit-Lines([string]$Text, [int]$Max, [int]$MaxWidth = 200) {
    if (-not $Text) { return '' }
    $lines = @($Text -split "`n" | ForEach-Object { if ($_.Length -gt $MaxWidth) { $_.Substring(0, $MaxWidth) + ' ...' } else { $_ } })
    if ($lines.Count -le $Max) { return $lines -join "`n" }
    return (($lines | Select-Object -First $Max) -join "`n") + "`n... ($($lines.Count - $Max) more lines in file)"
}

$fence = '```'
$digest = New-Object Text.StringBuilder
[void]$digest.AppendLine("# Crash dump digest")
[void]$digest.AppendLine("")
if ($repo) {
    [void]$digest.AppendLine("- Source: available, repo $repo")
    [void]$digest.AppendLine("- Default compare ref: $compareRef ($compareCommit), fetch: $fetchStatus. Per-dump analysis ref: see 'Analysis ref' below (depends on major version and build channel).")
}
else {
    [void]$digest.AppendLine("- Source: **not available** ($sourceNote). Build commit estimation, source lines at the build commit, file history and vcpkg port details are skipped; stage 3 (code analysis) needs a machine with the repository.")
}
[void]$digest.AppendLine("- Report path: $reportPath")
[void]$digest.AppendLine("- Full data: $summaryPath")
if ($extracted.Count -gt 0) {
    $extractedGb = [Math]::Round((@($extracted | Measure-Object -Property SizeBytes -Sum).Sum) / 1GB, 2)
    [void]$digest.AppendLine("- Extracted from zip archives ($extractedGb GB, kept for further cdb queries; delete when done): $((@($extracted | ForEach-Object { Split-Path $_.DumpPath -Parent }) | Select-Object -Unique) -join ', ')")
}
[void]$digest.AppendLine("- Dumps: $($dumpFiles.Count) unique (analyzed) from $inputDumpCount dump file(s) / archive entries. Count crashes by unique dumps only.")
foreach ($key in @($dumpCopies.Keys)) {
    [void]$digest.AppendLine("  - Identical copies (SHA-256 $(if ($script:sha256Cache.ContainsKey($key.ToLowerInvariant())) { $script:sha256Cache[$key.ToLowerInvariant()].Substring(0, 16) + '...' } else { 'verified' })) of $([IO.Path]::GetFileName($key)), analyzed once: $(@($dumpCopies[$key] | ForEach-Object { $_.path }) -join '; ')")
}
foreach ($z in $emptyArchives) { [void]$digest.AppendLine("- Archive without dumps or symbols (ignored): $z") }
if ($bundledPdbs.Count -gt 0) { [void]$digest.AppendLine("- Symbol files bundled in the input archives (tried before the build shares, GUID-verified; see 'Symbols: ... from' per dump): $(@($bundledPdbs | ForEach-Object { "$($_.Archive)!$($_.Entry)" }) -join '; ')") }
$blockedResults = @($results | Where-Object { $_.blocked })
if ($blockedResults.Count -gt 0) {
    [void]$digest.AppendLine("- **BLOCKED dumps ($($blockedResults.Count)) - symbols not verified.** Report only their raw exception facts and the required PDB; no function names, signature grouping, build commit, source mapping or root cause. They do not block the other dumps of this run.")
    foreach ($b in $blockedResults) {
        [void]$digest.AppendLine("  - $([IO.Path]::GetFileName($b.dump.path)) v$($b.module.fileVersion): needs $($b.blocked.requiredPdb) GUID $($b.blocked.pdbGuid) age $($b.blocked.pdbAge) (binary linked $($b.blocked.binaryLinkedUtc), installed at $($b.blocked.installPath)). $($b.blocked.reason)")
    }
}
[void]$digest.AppendLine("")
[void]$digest.AppendLine("## Dumps")
[void]$digest.AppendLine("")
[void]$digest.AppendLine("| Dump | Version | Crash time (UTC) | Process uptime | PID | Exception | Signature | Build commit (confidence) | Copies | Errors |")
[void]$digest.AppendLine("|---|---|---|---|---|---|---|---|---|---|")
foreach ($r in $results) {
    $exceptionText = if ($r.exception) { "$($r.exception.code) $($r.exception.name)" } else { 'none' }
    $buildText = if ($r.blocked) { 'not accepted (symbols unverified)' } elseif ($r.build -and $r.build.commit) { "$($r.build.commit.Substring(0, 10)) ($($r.build.confidence))" } else { 'unknown' }
    $dumpText = if ($r.dump) { [IO.Path]::GetFileName($r.dump.path) } else { '?' }
    $versionText = if ($r.module) { $r.module.fileVersion } else { '?' }
    $timeText = if ($r.dump) { $r.dump.crashTimeUtc } else { '?' }
    $pidText = if ($r.dump) { $r.dump.processId } else { '?' }
    $uptimeText = if ($r.dump -and $r.dump.uptime) { $r.dump.uptime } else { '?' }
    $copiesText = if ($r.dump -and @($r.dump.copies).Count -gt 0) { @($r.dump.copies | ForEach-Object { if ($_.archive) { [IO.Path]::GetFileName($_.archive) } else { $_.path } }) -join ', ' } else { '' }
    [void]$digest.AppendLine("| $dumpText | $versionText | $timeText | $uptimeText | $pidText | $exceptionText | ``$($r.signature)`` | $buildText | $copiesText | $(@($r.errors) -join '<br>') |")
}

foreach ($group in $groups) {
    $r = $results | Where-Object { $_.dump -and $_.dump.path -eq $group.dumps[0] } | Select-Object -First 1
    if (-not $r) { continue }
    [void]$digest.AppendLine("")
    [void]$digest.AppendLine("## Signature: ``$($group.signature)`` ($($group.count) dump(s))")
    [void]$digest.AppendLine("")
    [void]$digest.AppendLine("Representative dump: $($r.dump.path)")
    [void]$digest.AppendLine("")
    if ($r.blocked) {
        [void]$digest.AppendLine("> **BLOCKED - $($r.blocked.reason)** Use only the exception code/address/parameters and the raw module+RVA addresses below. Function names from export symbols are nearest exports, not the crashing function. No build commit, source mapping, fix search or root cause until the matching $($r.blocked.requiredPdb) (GUID $($r.blocked.pdbGuid), age $($r.blocked.pdbAge)) is supplied with -PdbPath. Do not substitute a neighboring build's PDB.")
        [void]$digest.AppendLine("")
    }
    if ($r.exception) {
        $accessText = if ($r.exception.access) { " - attempted $($r.exception.access)" } else { '' }
        [void]$digest.AppendLine("- Exception: $($r.exception.code) $($r.exception.name) at $($r.exception.address)$accessText, thread $($r.exception.threadId), parameters: $(@($r.exception.parameters) -join ', ')")
    }
    if ($r.assertion) {
        $a = $r.assertion
        $where = if ($a.file) { " at $($a.file):$($a.line)" } else { '' }
        $inFn = if ($a.inFunction) { " in $($a.inFunction)()" } else { '' }
        $expr = if ($a.expression) { " - expression ``$($a.expression)``" } else { ' - no assertion text in the locals' }
        $reportedBy = if ($a.reportedBy) { "``$($a.reportedBy)``" } else { 'none (no application frame)' }
        [void]$digest.AppendLine("- Assertion / abort: $($a.kind) (frame $($a.frame) ``$($a.function)``)$expr$inFn$where; first reporting frame: $reportedBy")
        if ($a.note) { [void]$digest.AppendLine("  - $($a.note) Analyze the asserted condition, not memory corruption.") }
        if ($a.PSObject.Properties['unwindNote'] -and $a.unwindNote) { [void]$digest.AppendLine("  - $($a.unwindNote)") }
    }
    if ($r.dump -and $r.dump.uptime) { [void]$digest.AppendLine("- Process: started $($r.dump.processStartUtc), crashed $($r.dump.crashTimeUtc) (uptime $($r.dump.uptime))") }
    if ($r.symbols) {
        [void]$digest.AppendLine("- Symbols: $($r.symbols.pdbName) GUID verified=$($r.symbols.guidVerified), load status '$($r.symbols.loadStatus)', from $($r.symbols.source)")
        if ($r.symbols.brand) { [void]$digest.AppendLine("- Branded build: '$($r.symbols.brand)' (the binary matches the branded build folder; build information below is taken from it)") }
        $checked = @($r.symbols.buildFolderCandidates)
        if ($checked.Count -gt 1 -or @($checked | Where-Object { $_.state -ne 'match' }).Count -gt 0) {
            foreach ($c in $checked) {
                $brandText = if ($c.brand) { "brand $($c.brand)$(if ($c.brandHint) { " (install path contains '$($c.brandHint)')" })" } else { 'unbranded' }
                [void]$digest.AppendLine("  - Build folder $($c.path) [$brandText, $($c.channel)]: binary GUID $($c.binaryGuid), linked $($c.binaryLinkedUtc) -> $($c.state)")
            }
        }
    }
    if ($r.build) {
        $channelText = if ($r.build.channel -eq 'dev') { 'DEV build (odd minor version) - analyze root cause on the latest compare ref; skip fixed-in-branch/backport analysis' } else { 'release build' }
        [void]$digest.AppendLine("- Product line: $($r.build.productLine); build channel: $channelText; folder: $($r.build.folder)")
        if ($r.build.brokenBuildMarker) { [void]$digest.AppendLine("  - Note: the build folder contains a BROKENBUILD marker (some build step failed); binaries and symbols may still be usable.") }
        $productVersionText = if ($r.module -and $r.module.productVersionInformational -and $r.module.productVersionInformational -ne $r.build.version) { " (product version $($r.module.productVersionInformational) - informational only, all routing uses the file version)" } else { '' }
        [void]$digest.AppendLine("- Build: file version v$($r.build.version)$productVersionText, built $($r.build.buildTimeUtc) ($($r.build.buildTimeSource))")
        $sourceBranchText = if ($r.build.sourceBranch) { "; source branch per build_info: $($r.build.sourceBranch)" } else { '' }
        if ($r.build.commit) { [void]$digest.AppendLine("- Build commit: $($r.build.commit) [$($r.build.confidence)] via '$($r.build.method)'$sourceBranchText; version branch: $($r.build.branch); $($r.build.subject) ($($r.build.commitDateUtc))") }
        else { [void]$digest.AppendLine("- Build commit: none accepted$sourceBranchText") }
        foreach ($note in @($r.build.notes)) { [void]$digest.AppendLine("  - Note: $note") }
    }
    if ($r.compare -and $repo) {
        [void]$digest.AppendLine("- Analysis ref (latest code): $($r.compare.ref) @ $($r.compare.commit) ($($r.compare.reason))")
        [void]$digest.AppendLine("- Build commit is ancestor of $($r.compare.ref): $($r.compare.buildCommitIsAncestor); merge-base: $($r.compare.mergeBase)")
    }
    if ($r.analyze) {
        $wrongSymbols = $false
        foreach ($key in @($r.analyze.Keys)) {
            if ([string]$r.analyze[$key] -match 'wrong[._]symbols|^A211E4D0$') { $wrongSymbols = $true; continue }
            if ($r.blocked -and $key -match '^(SYMBOL_NAME|FAILURE_BUCKET_ID|FAULTING_LOCAL_VARIABLE_NAME|PRIMARY_PROBLEM_CLASS)$') { continue }
            [void]$digest.AppendLine("- !analyze $key = $($r.analyze[$key])")
        }
        if ($wrongSymbols) { [void]$digest.AppendLine("- !analyze bucket fields omitted: they report WRONG_SYMBOLS for Windows DLLs (no Microsoft symbols); this does not affect inmation frames.") }
    }
    [void]$digest.AppendLine("")
    if ($r.blocked) {
        [void]$digest.AppendLine("### Raw stack (no verified symbols - addresses only)")
        [void]$digest.AppendLine("")
        [void]$digest.AppendLine("| # | Address (module+RVA) | Inline |")
        [void]$digest.AppendLine("|---|---|---|")
        foreach ($rf in @($r.rawStack | Select-Object -First 40)) { [void]$digest.AppendLine("| $($rf.index) | $($rf.address) | $($rf.inline) |") }
    }
    else {
        [void]$digest.AppendLine("### Crashing stack")
        [void]$digest.AppendLine("")
        [void]$digest.AppendLine("| # | Call site | Source (build) | Repo path | Function name above line at build commit |")
        [void]$digest.AppendLine("|---|---|---|---|---|")
        foreach ($frame in @($r.crashStack | Select-Object -First 40)) {
            $sourceText = if ($frame.sourceFile) { "$([IO.Path]::GetFileName($frame.sourceFile)):$($frame.sourceLine)" } else { '' }
            $inlineText = if ($frame.inline) { ' (inline)' } else { '' }
            $pathText = $frame.repoPath
            if (-not $pathText -and $frame.thirdParty) { $pathText = if ($frame.thirdParty.port) { "vcpkg port $($frame.thirdParty.port) ($($frame.thirdParty.version)): $($frame.thirdParty.relPath)" } else { "vcpkg_installed: $($frame.thirdParty.relPath)" } }
            [void]$digest.AppendLine("| $($frame.index) | ``$($frame.callSite)``$inlineText | $sourceText | $pathText | $($frame.functionFoundAtBuildCommit) |")
        }
    }
    [void]$digest.AppendLine("")
    [void]$digest.AppendLine("Frame numbers in this digest are decimal; cdb ``.frame`` and ``kn`` use hex. Use ``.frame 0n<N>``.")
    if (@($r.thirdParty).Count -gt 0) {
        [void]$digest.AppendLine("")
        [void]$digest.AppendLine("### Third-party (vcpkg) ports in the crashing stack")
        [void]$digest.AppendLine("")
        [void]$digest.AppendLine("| Port | Version in build path | Frames | At build commit | At $($r.compare.ref) | Local source |")
        [void]$digest.AppendLine("|---|---|---|---|---|---|")
        foreach ($tp in @($r.thirdParty)) {
            $fmt = {
                param($pi)
                if (-not $pi) { return 'n/a' }
                if (-not $pi.dir) { return $pi.note }
                $pv = if ($null -ne $pi.portVersion) { "#$($pi.portVersion)" } else { '' }
                $pt = if (@($pi.patches).Count -gt 0) { "; patches: $(@($pi.patches) -join ', ')" } else { '; no patches' }
                return "``$($pi.dir)`` $($pi.version)$pv$pt"
            }
            $localText = @($tp.localSource | Select-Object -First 1 | ForEach-Object { if ($_.exactBuildTree) { $_.path } else { "$($_.path) (same version, different patch hash)" } }) -join ''
            [void]$digest.AppendLine("| $($tp.port) | $($tp.versionInBuildPath) | $(@($tp.frames) -join ', ') | $(& $fmt $tp.atBuildCommit) | $(& $fmt $tp.atCompareRef) | $localText |")
        }
    }
    if (@($r.luaStack).Count -gt 0) {
        [void]$digest.AppendLine("")
        [void]$digest.AppendLine("### Lua call chain (innermost first, from lua_State CallInfo)")
        [void]$digest.AppendLine("")
        [void]$digest.AppendLine("| Level | Kind | Chunk / C function | Current line | Function defined at | Source text |")
        [void]$digest.AppendLine("|---|---|---|---|---|---|")
        foreach ($lf in @($r.luaStack | Select-Object -First 40)) {
            $what = if ($lf.kind -eq 'Lua') { "``$($lf.source)``" } elseif ($lf.cFunction) { "``$($lf.cFunction)``" } else { '' }
            $textCell = if ($lf.text) { "``$(($lf.text -replace '\|', '\|'))``" } else { '' }
            $defText = if ($lf.lastLineDefined -and $lf.lineDefined -and [int]$lf.lineDefined -gt 0) { "$($lf.lineDefined)-$($lf.lastLineDefined)" } else { $lf.lineDefined }
            [void]$digest.AppendLine("| $($lf.level) | $($lf.kind) | $what | $($lf.line) | $defText | $textCell |")
        }
        [void]$digest.AppendLine("")
        [void]$digest.AppendLine("Chunks ``= ...`` are the entry script (saved script-frame*.lua). Chunks ``@<object path>#<library>`` are libraries stored in the model; their text is not in the repository and not in the entry script.")
        $protoFrames = @($r.luaStack | Where-Object { $_.kind -eq 'Lua' -and (@($_.upvalueNames).Count + @($_.localNames).Count + @($_.stringConstants).Count) -gt 0 })
        if ($protoFrames.Count -gt 0) {
            [void]$digest.AppendLine("")
            [void]$digest.AppendLine("### Lua function prototypes of model-library frames (names the function uses)")
            [void]$digest.AppendLine("")
            [void]$digest.AppendLine("| Level | Function (chunk:lines) | Upvalues (enclosing locals / _ENV) | Locals | String constants (globals, fields, literals) |")
            [void]$digest.AppendLine("|---|---|---|---|---|")
            foreach ($lf in $protoFrames) {
                $fmtList = { param($list) (@($list | Select-Object -First 25 | ForEach-Object { "``$(([string]$_) -replace '\|', '\|' -replace '`', "'")``" }) -join ', ') }
                [void]$digest.AppendLine("| $($lf.level) | $($lf.source):$($lf.lineDefined)-$($lf.lastLineDefined) | $(& $fmtList $lf.upvalueNames) | $(& $fmtList $lf.localNames) | $(& $fmtList $lf.stringConstants) |")
            }
        }
        foreach ($lib in @($r.luaLibraries)) {
            [void]$digest.AppendLine("")
            if (-not $lib.recovered) {
                [void]$digest.AppendLine("Model library ``$($lib.chunk)``: NOT recovered ($($lib.note)) Searched names: $(@($lib.tokens) -join ', '). Its text is unknown; do not attribute its lines to the entry script.")
                continue
            }
            [void]$digest.AppendLine("### Recovered model library ``$($lib.chunk)``")
            [void]$digest.AppendLine("")
            [void]$digest.AppendLine("Recovered from process memory at $($lib.address) ($($lib.sizeBytes) bytes; found via $(@($lib.tokens) -join ', ')); validated against the Lua prototypes (function start/end lines and string constants) for lines $(@($lib.validatedFunctions) -join ', '). Saved (credentials masked, line numbers preserved) to $($lib.savedPath).")
            $libLines = @(Get-Content -LiteralPath $lib.savedPath -Encoding UTF8)
            foreach ($lf in @($r.luaStack | Where-Object { $_.source -eq $lib.chunk -and $_.line })) {
                $ln = [int]$lf.line
                $from = [Math]::Max(1, [int]$(if ($lf.lineDefined -and [int]$lf.lineDefined -gt 0 -and $ln - [int]$lf.lineDefined -le 12) { $lf.lineDefined } else { $ln - 6 }))
                $to = [Math]::Min($libLines.Count, $ln + 4)
                [void]$digest.AppendLine("")
                [void]$digest.AppendLine("Level $($lf.level), line $ln (function $($lf.lineDefined)-$($lf.lastLineDefined)):")
                [void]$digest.AppendLine("")
                [void]$digest.AppendLine("${fence}lua")
                foreach ($i in $from..$to) { [void]$digest.AppendLine(('{0}{1,5}: {2}' -f $(if ($i -eq $ln) { '>' } else { ' ' }), $i, $libLines[$i - 1])) }
                [void]$digest.AppendLine($fence)
            }
        }
    }
    foreach ($sc in @($r.scriptContext)) {
        [void]$digest.AppendLine("")
        [void]$digest.AppendLine("### Script context: $($sc.kind) (frame $($sc.frame), variable ``$($sc.variable)``)")
        [void]$digest.AppendLine("")
        $truncText = if ($sc.truncated) { ' (truncated, raise maxScriptBytes)' } else { '' }
        [void]$digest.AppendLine("- Script: $($sc.declaredSize) bytes, $($sc.capturedBytes) captured$truncText; saved (credentials masked) to $($sc.savedScript)")
        if ($sc.request) {
            $q = $sc.request
            if (@($q.modules).Count -gt 0) { [void]$digest.AppendLine("- Bundled modules: $(@($q.modules) -join ', ')") }
            if ($q.endpoint) { [void]$digest.AppendLine("- Request: $($q.method) ``$($q.endpoint)`` from $($q.remoteIp); topic $($q.topic); content type $($q.contentType)") }
            if ($q.referer) { [void]$digest.AppendLine("- Referer: $($q.referer)") }
            if ($q.userAgent) { [void]$digest.AppendLine("- User agent: $($q.userAgent)") }
            if ($q.payload) {
                $pl = [string]$q.payload; if ($pl.Length -gt 1500) { $pl = $pl.Substring(0, 1500) + ' ...' }
                [void]$digest.AppendLine("- Payload ($($q.payloadEncoding)): ``$($pl -replace '`', "'")``")
            }
            foreach ($n in @($q.notes)) { [void]$digest.AppendLine("- Note: $n") }
        }
    }
    $groupResults = @($results | Where-Object { $_.dump -and $group.dumps -contains $_.dump.path })
    if ($groupResults.Count -gt 1) {
        [void]$digest.AppendLine("")
        [void]$digest.AppendLine("### Per-dump comparison (look for the common trigger)")
        [void]$digest.AppendLine("")
        [void]$digest.AppendLine("| Dump | Crash time (UTC) | Uptime | Innermost Lua frame | Request | Payload |")
        [void]$digest.AppendLine("|---|---|---|---|---|---|")
        foreach ($g in $groupResults) {
            $lua = @($g.luaStack | Where-Object { $_.kind -eq 'Lua' }) | Select-Object -First 1
            $luaText = if ($lua) { "$($lua.source):$($lua.line)" } else { '' }
            $req = @($g.scriptContext | Where-Object { $_.request }) | Select-Object -First 1
            $reqText = if ($req -and $req.request.endpoint) { "$($req.request.method) $($req.request.endpoint)" } else { '' }
            $plText = if ($req -and $req.request.payload) { [string]$req.request.payload } else { '' }
            if ($plText.Length -gt 200) { $plText = $plText.Substring(0, 200) + ' ...' }
            [void]$digest.AppendLine("| $([IO.Path]::GetFileName($g.dump.path)) | $($g.dump.crashTimeUtc) | $($g.dump.uptime) | $luaText | $reqText | $($plText -replace '\|', '\|') |")
        }
    }
    $snippetFrames = @($r.crashStack | Where-Object { $_.buildSnippet } | Select-Object -First 3)
    if ($snippetFrames.Count -gt 0) {
        [void]$digest.AppendLine("")
        [void]$digest.AppendLine("### Source at build commit")
        foreach ($frame in $snippetFrames) {
            [void]$digest.AppendLine("")
            [void]$digest.AppendLine("Frame $($frame.index) ``$($frame.function)`` - $($frame.repoPath):$($frame.sourceLine)")
            [void]$digest.AppendLine("")
            [void]$digest.AppendLine("${fence}cpp")
            [void]$digest.AppendLine($frame.buildSnippet)
            [void]$digest.AppendLine($fence)
        }
    }
    [void]$digest.AppendLine("")
    [void]$digest.AppendLine("### Registers / faulting instruction")
    [void]$digest.AppendLine("")
    [void]$digest.AppendLine($fence)
    [void]$digest.AppendLine((Limit-Lines $r.registers 20))
    [void]$digest.AppendLine($fence)
    [void]$digest.AppendLine("")
    [void]$digest.AppendLine("### Disassembly around the fault")
    [void]$digest.AppendLine("")
    [void]$digest.AppendLine($fence)
    [void]$digest.AppendLine((Limit-Lines $r.disassembly 50))
    [void]$digest.AppendLine($fence)
    [void]$digest.AppendLine("")
    [void]$digest.AppendLine("### Locals (frames 0-3, truncated)")
    [void]$digest.AppendLine("")
    [void]$digest.AppendLine($fence)
    [void]$digest.AppendLine((Limit-Lines $r.localsTop 40 160))
    [void]$digest.AppendLine($fence)
    if (@($r.sourceHistory).Count -gt 0) {
        $historyRef = $r.compare.ref
        [void]$digest.AppendLine("")
        [void]$digest.AppendLine("### Commits on $historyRef not contained in the build commit, touching crashing files (newest first)")
        foreach ($h in @($r.sourceHistory | Select-Object -First 3)) {
            [void]$digest.AppendLine("")
            [void]$digest.AppendLine("**$($h.file)** (exists in $historyRef`: $($h.existsInCompareRef), $(@($h.commitsNotInBuild).Count) commits)")
            [void]$digest.AppendLine("")
            foreach ($c in @($h.commitsNotInBuild | Select-Object -First 15)) { [void]$digest.AppendLine("- $($c -replace "`t", ' | ')") }
        }
        if (@($r.sourceHistory).Count -gt 3) { [void]$digest.AppendLine(""); [void]$digest.AppendLine("History for $(@($r.sourceHistory).Count - 3) more file(s) is in summary.json (sourceHistory).") }
    }
    if ($r.files) {
        [void]$digest.AppendLine("")
        [void]$digest.AppendLine("Raw files: cdb log $($r.files.cdbLog); locals $($r.files.locals); frame 0 locals (dx -r2) $($r.files.frame0LocalsDx); all threads $($r.files.threads); !analyze $($r.files.analyze)$(if ($r.files.contextLog) { "; Lua/script context $($r.files.contextLog)" })")
    }
    if ($r.symbols -and $r.symbols.trusted) {
        $imageArg = if ($r.symbols.cdbImagePath) { " -i `"$($r.symbols.cdbImagePath)`"" } else { '' }
        [void]$digest.AppendLine("")
        [void]$digest.AppendLine("Further cdb queries: ``& `"$cdb`" -z `"$($r.dump.path)`" -y `"$($r.symbols.cdbSymbolPath)`"$imageArg -lines -c `".ecxr; .frame 0n<N>; dx -r2 <expr>; q`"``. For longer or quoted queries write the commands to a file and pass ``-cf <file>`` instead of ``-c`` (see $(if ($r.files -and $r.files.contextLog) { "$(Split-Path $r.files.contextLog -Parent)\context.cdb.txt" } else { 'context.cdb.txt in the dump folder of the run' }) for an example).")
    }
}
$digestPath = Join-Path $runDir 'digest.md'
Set-Content -LiteralPath $digestPath -Value $digest.ToString() -Encoding UTF8

Write-Host "REPORT_PATH=$reportPath"
Write-Host "SUMMARY_JSON=$summaryPath"
Write-Host "DIGEST_MD=$digestPath"
Write-Host "SOURCE_AVAILABLE=$(if ($repo) { 'true' } else { "false ($sourceNote)" })"
foreach ($dir in @($extracted | ForEach-Object { Split-Path $_.DumpPath -Parent } | Select-Object -Unique)) { Write-Host "EXTRACTED_DIR=$dir" }
foreach ($b in @($results | Where-Object { $_.blocked })) { Write-Host "BLOCKED_DUMP=$($b.dump.path) | needs $($b.blocked.requiredPdb) GUID $($b.blocked.pdbGuid) age $($b.blocked.pdbAge)" }

#endregion
