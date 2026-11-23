# Symbols for one Windows minidump, for scripts that need verified type information but not the crash analysis
# (perf-counter-analysis). Same lookup order and GUID check as Invoke-CrashDumpAnalysis.ps1: -PdbPath, next to the dump,
# bundled in the input zip, build folders on the shares (unbranded and branded). The caller applies the symbol gate
# with the cdb load status (Test-PrivateSymbolStatus): no verified private PDB, no type-based reading.
# Needs Common.ps1, Minidump.ps1 and BuildLookup.ps1.

function Resolve-WindowsDumpSymbols($Config, [string]$DumpFile, [string]$PdbPath, [string[]]$DumpDirs, $BundledPdbs) {
    $binaryMap = @{}
    foreach ($prop in (Get-Cfg $Config 'binaries' $null).PSObject.Properties) { $binaryMap[$prop.Name.ToLowerInvariant()] = $prop.Value }
    $info = Read-MinidumpInfo $DumpFile
    $module = $info.Modules | Where-Object { $binaryMap.ContainsKey($_.Name.ToLowerInvariant()) } | Select-Object -First 1
    if (-not $module) {
        $main = $info.Modules | Select-Object -First 1
        throw "No configured binary ($($binaryMap.Keys -join ', ')) in the dump; its main module is $(if ($main) { $main.Name } else { 'unknown' })."
    }
    $vars = @{ version = $module.FileVersion }
    if ($module.FileVersion) {
        $v = $module.FileVersion.Split('.')
        $vars.major = $v[0]; $vars.minor = $v[1]; $vars.revision = $v[2]; $vars.build = $v[3]
    }
    $productLine = Get-ProductLine $Config $vars
    $channel = Get-BuildChannel $Config $vars
    $candidates = if ($module.FileVersion) { @(Get-BuildFolderCandidates $Config $productLine $vars $channel $module) } else { @() }
    $pdbName = $binaryMap[$module.Name.ToLowerInvariant()]
    $dirs = @(@((Split-Path $DumpFile -Parent)) + @($DumpDirs) | Where-Object { $_ } | Select-Object -Unique)

    $symbols = $null
    $symbolError = $null
    try {
        Write-Host "Resolving $pdbName ($($module.PdbGuid) age $($module.PdbAge)) ..."
        $symbols = Resolve-Pdb $Config $module $pdbName $candidates $PdbPath $dirs $BundledPdbs
    }
    catch { $symbolError = $_.Exception.Message }

    # The build folder whose binary matches the dump gives cdb the image (needed for code and read-only data).
    $versionHit = $null
    if ($symbols -and $symbols.Candidate) { $versionHit = $symbols.Candidate }
    if (-not $versionHit) { $versionHit = $candidates | Where-Object { $_.State -eq 'match' } | Select-Object -First 1 }
    $imagePath = $null
    if ($versionHit) {
        $candidateImageDir = Join-Path $versionHit.Path (Get-Cfg $Config 'binaryFolder' 'inmation.root\bin')
        if (Test-Path -LiteralPath $candidateImageDir) { $imagePath = $candidateImageDir }
    }
    $symbolPathParts = @()
    if ($symbols) { $symbolPathParts += $symbols.SymbolDir }
    if (Get-Cfg $Config 'useMicrosoftSymbolServer' $false) {
        $symbolPathParts += "srv*$(Expand-PathValue (Get-Cfg $Config 'localSymbolCache' "$env:LOCALAPPDATA\inmation-crash-analysis\symbols"))\ms*https://msdl.microsoft.com/download/symbols"
    }

    return [pscustomobject]@{
        Info        = $info
        Module      = $module
        ModuleName  = [IO.Path]::GetFileNameWithoutExtension($module.Name)
        Wow64       = ($info.Architecture -eq 'x64' -and $module.Name -ieq 'inmation32.exe')
        PdbName     = $pdbName
        Symbols     = $symbols
        SymbolError = $symbolError
        SymbolPath  = ($symbolPathParts -join ';')
        ImagePath   = $imagePath
        VersionDir  = if ($versionHit) { $versionHit.Path } else { $null }
    }
}

# The load status cdb prints in 'lmv m <module>', e.g. 'private pdb symbols'.
function Get-SymbolLoadStatus([string[]]$Lines) {
    $line = $Lines | Where-Object { $_ -match '\s\(([^)]*symbols[^)]*)\)' } | Select-Object -First 1
    if ($line -and $line -match '\s\(([^)]*symbols[^)]*)\)') { return $Matches[1] }
    return $null
}

function Test-PrivateSymbolStatus([string]$LoadStatus) { return [bool]($LoadStatus -and $LoadStatus -match 'private pdb') }
