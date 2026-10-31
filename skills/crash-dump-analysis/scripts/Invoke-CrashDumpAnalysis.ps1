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

.PARAMETER ReportDir
Folder for the crash report. Default: the dump's folder (or the run folder if that is read-only).

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
    [switch]$NoSource,
    [string]$ReportDir
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem

foreach ($lib in 'Common', 'Minidump', 'BuildLookup', 'Cdb', 'Source', 'Frames', 'Vcpkg', 'Lua', 'Archives', 'CppException', 'Classification', 'Report') { . (Join-Path $PSScriptRoot "lib\$lib.ps1") }

$configInfo = Read-AnalyzerConfig $ConfigPath $PSScriptRoot
$config = $configInfo.Config

# Without the source repository (e.g. a support engineer's machine) the dump is still analyzed: exception, symbolized
# stack, Lua/script context. Everything that needs git (build commit estimation, source lines, history, ports) is skipped.
$sourceInfo = Resolve-SourceRepo $RepoPath ([bool]$NoSource) $config
$repo = $sourceInfo.Repo
$sourceNote = $sourceInfo.Note
if (-not $repo) { Write-Host "Source repository not available ($sourceNote): build commit estimation, source lines and history are skipped." }

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
    $entry = [ordered]@{ dump = [ordered]@{ path = $dumpFile; archive = $(if ($dumpOrigin.ContainsKey($dumpFile)) { $dumpOrigin[$dumpFile] } else { $null }); sha256 = $sha; copies = $copies; sizeBytes = $null; crashTimeUtc = $null; processStartUtc = $null; uptime = $null; uptimeSeconds = $null; processId = $null; architecture = $null; wow64 = $null }; module = $null; exception = $null; assertion = $null; symbols = $null; blocked = $null; build = $null; compare = $null; analyze = $null; signature = $null; signatureFamily = $null; signatureInfo = $null; classification = $null; cppException = $null; crashStack = @(); rawStack = @(); thirdParty = @(); luaStack = @(); luaLibraries = @(); scriptContext = @(); registers = $null; disassembly = $null; localsTop = $null; sourceHistory = @(); files = $null; errors = $null }

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
        $sig = Get-CrashSignature $frames $entry.assertion $ownModules
        $signature = $sig.Signature
        $entry.signatureFamily = $sig.Family
        $entry.signatureInfo = [ordered]@{ topFrame = $(if ($sig.TopFrame) { $sig.TopFrame.index } else { $null }); firstOwnFrame = $(if ($sig.FirstOwnFrame) { $sig.FirstOwnFrame.index } else { $null }); noApplicationFrame = $sig.NoApplicationFrame }
        $is32Bit = ($isWow64 -or $info.Architecture -eq 'x86')

        # Unhandled C++ exception: the thrown object and the throw site are still on the stack even when the unwind
        # stopped in the exception dispatch. Decode them with a raw stack scan.
        $isTerminate = ($entry.assertion -and $entry.assertion.kind -like 'std::terminate*') -or ($info.Exception -and $info.Exception.code -eq '0xE06D7363')
        if ($symbolsTrusted -and $isTerminate) {
            Write-Host 'Running cdb (C++ exception record scan) ...'
            try {
                $cxxCmdFile = Join-Path $dumpOut 'cxx-scan.cdb.txt'
                $cxxLog = Join-Path $dumpOut 'cxx-scan.log'
                Set-Content -LiteralPath $cxxCmdFile -Value (New-CppExceptionCommands $is32Bit $isWow64) -Encoding ASCII
                Invoke-CdbScript $cdb $dumpFile $symbolPath $imagePath $cxxLog $cxxCmdFile ([int](Get-Cfg $config 'cdbTimeoutSeconds' 900))
                $cxx = @(ConvertFrom-CppExceptionScan @(Get-Content -LiteralPath $cxxLog) $ownModules)
                if ($cxx.Count -gt 0) {
                    $entry.cppException = $cxx[0]
                    if ($cxx.Count -gt 1) { $errors += "Several C++ exception records on the stack ($(@($cxx | ForEach-Object { $_.thrownType }) -join ', ')); the first (innermost) is reported. See $cxxLog." }
                    if ($sig.NoApplicationFrame -and $cxx[0].throwSite) {
                        $ts = $cxx[0].throwSite
                        $signature = "terminate: $($cxx[0].thrownType) thrown in $($ts.callSite) [stack scan]"
                        $entry.signatureFamily = "terminate: $(Get-CompactFunctionName $cxx[0].thrownType) thrown in $($ts.module)!$(Get-CompactFunctionName $ts.function) [stack scan]"
                    }
                }
                else { $errors += "Unhandled C++ exception, but no C++ exception record (0xE06D7363 / 0x19930520) was found on the stack. See $cxxLog." }
            }
            catch { $errors += "C++ exception scan: $($_.Exception.Message)" }
        }

        if (-not $symbolsTrusted) {
            # Raw identity only: same binary (PDB GUID) and same faulting RVA. Never merged with symbolized signatures.
            $entry.rawStack = @(Get-RawStack $frames $(if ($info.Exception) { $info.Exception.address } else { $null }) $info.Modules)
            $entry.assertion = $null
            $rawTop = @($entry.rawStack | Where-Object { $_.address }) | Select-Object -First 1
            $excCode = if ($info.Exception) { $info.Exception.code } else { 'no exception' }
            $signature = "[unverified symbols] $excCode at $(if ($rawTop) { $rawTop.address } else { 'unknown address' }) (v$($module.FileVersion), PDB $($module.PdbGuid))"
            $entry.signatureFamily = $signature
        }
        $entry.signature = $signature
        $entry.classification = Get-CrashClassification $info.Exception $entry.assertion $(if ($symbolsTrusted) { $frames } else { @() }) $(if ($symbolsTrusted) { $sig } else { $null }) $entry.cppException $ownModules $is32Bit

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
        $cxxScanFile = Join-Path $dumpOut 'cxx-scan.log'
        $entry.files = [ordered]@{ cdbLog = $cdbLog; analyze = $analyzeFile; locals = $localsFile; frame0LocalsDx = $frame0DxFile; threads = $threadsFile; contextLog = $(if (Test-Path -LiteralPath $contextLogFile) { $contextLogFile } else { $null }); cxxScan = $(if (Test-Path -LiteralPath $cxxScanFile) { $cxxScanFile } else { $null }); scripts = @($entry.scriptContext | Where-Object { $_.savedScript } | ForEach-Object { $_.savedScript }); libraries = @($entry.luaLibraries | Where-Object { $_.savedPath } | ForEach-Object { $_.savedPath }) }
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

$groups = @($results | Group-Object { if ($_.signatureFamily) { $_.signatureFamily } elseif ($_.signature) { $_.signature } else { '<unknown>' } } | ForEach-Object {
        [ordered]@{ signature = $_.Name; count = $_.Count; blocked = [bool]($_.Group | Where-Object { $_.blocked }); exactSignatures = @($_.Group | ForEach-Object { $_.signature } | Select-Object -Unique); versions = @($_.Group | Where-Object { $_.module } | ForEach-Object { $_.module.fileVersion } | Select-Object -Unique); dumps = @($_.Group | ForEach-Object { $_.dump.path }) }
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

$reportDir = if ($ReportDir) { New-Item -ItemType Directory -Force -Path $ReportDir | Out-Null; (Resolve-Path -LiteralPath $ReportDir).Path } elseif (Test-Path -LiteralPath $DumpPath -PathType Container) { (Resolve-Path -LiteralPath $DumpPath).Path } else { Split-Path (Resolve-Path -LiteralPath $DumpPath).Path -Parent }
$reportName = if ($dumpFiles.Count -eq 1) { [IO.Path]::GetFileName($dumpFiles[0]) + '.crash-report.md' } else { 'crash-report.md' }
$reportPath = if (Test-Writable $reportDir) { Join-Path $reportDir $reportName } else { Join-Path $runDir $reportName }
# Never overwrite an earlier report (it may hold stage 2/3 results): add a timestamp.
if (Test-Path -LiteralPath $reportPath) { $reportPath = $reportPath -replace '\.md$', ".$(Split-Path $runDir -Leaf).md" }

$summary = [ordered]@{
    generatedUtc = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    repo         = $repo
    sourceAvailable = [bool]$repo
    sourceNote   = $sourceNote
    config       = @($configInfo.Sources)
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

# Report draft (header + section 1) and chat summary, rendered from the summary as written.
$summaryData = Get-Content -LiteralPath $summaryPath -Raw -Encoding UTF8 | ConvertFrom-Json
$utf8NoBom = [Text.UTF8Encoding]::new($false)
[IO.File]::WriteAllText($reportPath, (New-CrashReportMarkdown $summaryData "crash-dump-analyzer $(Get-ToolVersion $PSScriptRoot)"), $utf8NoBom)
$chatSummaryPath = Join-Path $runDir 'chat-summary.md'
[IO.File]::WriteAllText($chatSummaryPath, (New-ChatSummaryMarkdown $summaryData $reportPath), $utf8NoBom)

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
    if (@($group.exactSignatures).Count -gt 1 -or @($group.versions).Count -gt 1) {
        [void]$digest.AppendLine("Same crashing functions in $(@($group.versions).Count) file version(s) ($(@($group.versions) -join ', ')); exact signatures: $(@($group.exactSignatures | ForEach-Object { '`' + $_ + '`' }) -join '; ')")
        [void]$digest.AppendLine("")
    }
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
    if ($r.classification) {
        [void]$digest.AppendLine("- Classification: **$($r.classification.category)** - $($r.classification.text) (stack role: $($r.classification.stackRole))")
        foreach ($h in @($r.classification.hints)) { if ($h) { [void]$digest.AppendLine("  - $h") } }
    }
    if ($r.cppException) {
        $c = $r.cppException
        $errText = if ($c.errorText) { ", error $($c.errorText)" } else { '' }
        $siteText = if ($c.throwSite) { "``$($c.throwSite.callSite)`` ($([IO.Path]::GetFileName([string]$c.throwSite.sourceFile)):$($c.throwSite.sourceLine))" } else { 'not found' }
        [void]$digest.AppendLine("- Thrown C++ exception (decoded from record $($c.record) on the stack): type ``$($c.thrownType)``$errText; throw site $siteText; thrown via $(@($c.thrownVia) -join ' <- ')")
        $aboveThrow = @($c.frames | Where-Object { $_.application -or $_.helper } | Select-Object -First 12 | ForEach-Object { '`' + (Get-CompactFunctionName $_.function) + '`' }) -join ' <- '
        [void]$digest.AppendLine("  - Frames above the throw ($($c.source)): $aboveThrow")
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
Write-Host "CHAT_SUMMARY=$chatSummaryPath"
Write-Host "SOURCE_AVAILABLE=$(if ($repo) { 'true' } else { "false ($sourceNote)" })"
$searchable = @($results | Where-Object { $_.module -and -not $_.blocked })
$psExe = 'powershell -NoProfile -ExecutionPolicy Bypass -File'
if ($searchable.Count -gt 0) {
    Write-Host "STAGE2_COMMAND=$psExe `"$(Join-Path $PSScriptRoot 'Search-TfsCrashBugs.ps1')`" -SummaryJson `"$summaryPath`" -Auto"
    if ($repo) { Write-Host "STAGE3_COMMAND=$psExe `"$(Join-Path $PSScriptRoot 'Get-CodeEvidence.ps1')`" -SummaryJson `"$summaryPath`"" }
}
foreach ($dir in @($extracted | ForEach-Object { Split-Path $_.DumpPath -Parent } | Select-Object -Unique)) { Write-Host "EXTRACTED_DIR=$dir" }
foreach ($b in @($results | Where-Object { $_.blocked })) { Write-Host "BLOCKED_DUMP=$($b.dump.path) | needs $($b.blocked.requiredPdb) GUID $($b.blocked.pdbGuid) age $($b.blocked.pdbAge)" }
