# Linux core dumps (OT Data Fabric containers, e.g. WSL / Docker crash dumps 'wsl-crash-<time>-<pid>-<exe>-<signal>.dmp'):
# ELF core parsing, debug file lookup by GNU build-id, sysroot from the product image, gdb in WSL, and conversion of the
# result into the same summary entry as a Windows dump.

$script:signalNames = @{ 1 = 'SIGHUP'; 2 = 'SIGINT'; 3 = 'SIGQUIT'; 4 = 'SIGILL'; 5 = 'SIGTRAP'; 6 = 'SIGABRT'; 7 = 'SIGBUS'; 8 = 'SIGFPE'; 9 = 'SIGKILL'; 10 = 'SIGUSR1'; 11 = 'SIGSEGV'; 12 = 'SIGUSR2'; 13 = 'SIGPIPE'; 14 = 'SIGALRM'; 15 = 'SIGTERM'; 24 = 'SIGXCPU'; 25 = 'SIGXFSZ'; 31 = 'SIGSYS' }
$script:signalTexts = @{ 'SIGSEGV' = 'Segmentation fault'; 'SIGABRT' = 'Aborted'; 'SIGBUS' = 'Bus error'; 'SIGFPE' = 'Floating point exception'; 'SIGILL' = 'Illegal instruction'; 'SIGTRAP' = 'Trace/breakpoint trap'; 'SIGQUIT' = 'Quit'; 'SIGSYS' = 'Bad system call'; 'SIGXCPU' = 'CPU time limit exceeded'; 'SIGXFSZ' = 'File size limit exceeded' }
# Images that could not be pulled in this run (not retried for every core of the same version).
$script:failedImages = @{}

function Test-ElfCoreFile([string]$Path) {
    $fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
        $b = New-Object byte[] 18
        if ($fs.Read($b, 0, 18) -lt 18) { return $false }
        return ($b[0] -eq 0x7f -and $b[1] -eq 0x45 -and $b[2] -eq 0x4c -and $b[3] -eq 0x46 -and [BitConverter]::ToUInt16($b, 16) -eq 4)
    }
    finally { $fs.Dispose() }
}

function Read-ElfNotes([byte[]]$Data) {
    $notes = @()
    $i = 0
    while ($i + 12 -le $Data.Length) {
        $namesz = [BitConverter]::ToUInt32($Data, $i); $descsz = [BitConverter]::ToUInt32($Data, $i + 4); $type = [BitConverter]::ToUInt32($Data, $i + 8)
        $i += 12
        $name = if ($namesz -gt 0 -and $i + $namesz -le $Data.Length) { [Text.Encoding]::ASCII.GetString($Data, $i, [int]$namesz).TrimEnd([char]0) } else { '' }
        $i += [int](($namesz + 3) -band -bnot 3)
        $descStart = $i
        $i += [int](($descsz + 3) -band -bnot 3)
        if ($descStart + $descsz -gt $Data.Length) { break }
        $notes += [pscustomobject]@{ Name = $name; Type = $type; Offset = $descStart; Size = [int]$descsz }
    }
    return $notes
}

# Facts from the ELF core without a debugger: crashing thread and signal, siginfo, process name, mapped files and the
# GNU build-id of every mapped ELF (read from the ELF header pages the kernel puts into the core).
function Read-ElfCoreInfo([string]$Path) {
    $fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
        $br = New-Object IO.BinaryReader($fs)
        $fs.Position = 18; $machine = $br.ReadUInt16()
        $fs.Position = 32; $phoff = $br.ReadUInt64()
        $fs.Position = 54; $phentsize = $br.ReadUInt16(); $phnum = $br.ReadUInt16()
        $phs = @()
        for ($i = 0; $i -lt $phnum; $i++) {
            $fs.Position = [int64]$phoff + $i * $phentsize
            $phs += [pscustomobject]@{ Type = $br.ReadUInt32(); Flags = $br.ReadUInt32(); Offset = $br.ReadUInt64(); VAddr = $br.ReadUInt64(); PAddr = $br.ReadUInt64(); FileSz = $br.ReadUInt64(); MemSz = $br.ReadUInt64() }
        }
        $loads = @($phs | Where-Object { $_.Type -eq 1 -and $_.FileSz -gt 0 })
        $readVa = {
            param([uint64]$Va, [int]$Count)
            foreach ($l in $loads) {
                if ($Va -ge $l.VAddr -and $Va -lt ($l.VAddr + $l.FileSz)) {
                    $fs.Position = [int64]($l.Offset + ($Va - $l.VAddr))
                    return $br.ReadBytes([int][Math]::Min([uint64]$Count, $l.VAddr + $l.FileSz - $Va))
                }
            }
            return $null
        }
        $threads = @(); $siginfo = $null; $prps = $null; $files = @()
        foreach ($ph in @($phs | Where-Object { $_.Type -eq 4 })) {
            $fs.Position = [int64]$ph.Offset
            $data = $br.ReadBytes([int]$ph.FileSz)
            foreach ($n in (Read-ElfNotes $data)) {
                switch ($n.Type) {
                    1 { $threads += [pscustomobject]@{ Signal = [BitConverter]::ToInt16($data, $n.Offset + 12); Tid = [BitConverter]::ToInt32($data, $n.Offset + 32) } }
                    3 {
                        if (-not $prps -and $n.Size -ge 136) {
                            $prps = [pscustomobject]@{ Pid = [BitConverter]::ToInt32($data, $n.Offset + 24); Name = [Text.Encoding]::ASCII.GetString($data, $n.Offset + 40, 16).TrimEnd([char]0); Args = [Text.Encoding]::ASCII.GetString($data, $n.Offset + 56, 80).TrimEnd([char]0).Trim() }
                        }
                    }
                    0x53494749 {
                        if (-not $siginfo) {
                            $signo = [BitConverter]::ToInt32($data, $n.Offset); $code = [BitConverter]::ToInt32($data, $n.Offset + 8)
                            $siginfo = [pscustomobject]@{ Signo = $signo; Code = $code; Addr = $(if ($n.Size -ge 24) { [BitConverter]::ToUInt64($data, $n.Offset + 16) } else { $null }); SenderPid = $(if ($n.Size -ge 24) { [BitConverter]::ToInt32($data, $n.Offset + 16) } else { $null }) }
                        }
                    }
                    0x46494c45 {
                        $count = [BitConverter]::ToUInt64($data, $n.Offset); $page = [BitConverter]::ToUInt64($data, $n.Offset + 8)
                        $strStart = $n.Offset + 16 + 24 * [int]$count
                        $names = [Text.Encoding]::UTF8.GetString($data, $strStart, $n.Offset + $n.Size - $strStart).Split([char]0)
                        for ($k = 0; $k -lt $count; $k++) {
                            $e = $n.Offset + 16 + 24 * $k
                            $files += [pscustomobject]@{ Start = [BitConverter]::ToUInt64($data, $e); End = [BitConverter]::ToUInt64($data, $e + 8); FileOffset = [BitConverter]::ToUInt64($data, $e + 16) * $page; Path = $names[$k] }
                        }
                    }
                }
            }
        }
        $objects = @()
        foreach ($path in @($files | ForEach-Object { $_.Path } | Select-Object -Unique)) {
            $maps = @($files | Where-Object { $_.Path -eq $path })
            $first = $maps | Where-Object { $_.FileOffset -eq 0 } | Select-Object -First 1
            $buildId = $null
            if ($first) {
                $hdr = & $readVa $first.Start 4096
                if ($hdr -and $hdr.Length -ge 64 -and $hdr[0] -eq 0x7f -and $hdr[1] -eq 0x45) {
                    $po = [BitConverter]::ToUInt64($hdr, 32); $pes = [BitConverter]::ToUInt16($hdr, 54); $pn = [BitConverter]::ToUInt16($hdr, 56)
                    for ($k = 0; $k -lt $pn -and -not $buildId; $k++) {
                        $b = [int]$po + $k * $pes
                        if ($b + 56 -gt $hdr.Length) { break }
                        if ([BitConverter]::ToUInt32($hdr, $b) -ne 4) { continue }
                        $o = [BitConverter]::ToUInt64($hdr, $b + 8); $sz = [BitConverter]::ToUInt64($hdr, $b + 32)
                        $nd = if ($o + $sz -le [uint64]$hdr.Length) { [byte[]]$hdr[[int]$o..([int]($o + $sz) - 1)] } else { & $readVa ($first.Start + $o) ([int]$sz) }
                        if (-not $nd) { continue }
                        foreach ($note in (Read-ElfNotes $nd)) {
                            if ($note.Type -eq 3 -and $note.Name -eq 'GNU') { $buildId = (($nd[$note.Offset..($note.Offset + $note.Size - 1)] | ForEach-Object { '{0:x2}' -f $_ }) -join '') }
                        }
                    }
                }
            }
            $minStart = [uint64]::MaxValue; $maxEnd = [uint64]0
            foreach ($mp in $maps) { if ($mp.Start -lt $minStart) { $minStart = $mp.Start }; if ($mp.End -gt $maxEnd) { $maxEnd = $mp.End } }
            $objects += [pscustomobject]@{ Path = $path; Name = [IO.Path]::GetFileName($path); Base = $(if ($first) { [uint64]$first.Start } else { $minStart }); End = $maxEnd; BuildId = $buildId; IsElf = [bool]$buildId }
        }
        $arch = switch ($machine) { 62 { 'x64' } 183 { 'arm64' } 3 { 'x86' } default { "elf-machine-$machine" } }
        return [pscustomobject]@{ Path = $Path; SizeBytes = $fs.Length; Architecture = $arch; Threads = $threads; CrashThread = ($threads | Select-Object -First 1); SigInfo = $siginfo; Process = $prps; Objects = $objects }
    }
    finally { $fs.Dispose() }
}

# GNU build-id of an ELF file (executable or separate debug file), from the .note.gnu.build-id section.
function Read-ElfBuildId([string]$Path) {
    $fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
        $br = New-Object IO.BinaryReader($fs)
        if ($br.ReadUInt32() -ne 0x464c457f) { return $null }
        $fs.Position = 40; $shoff = $br.ReadUInt64()
        $fs.Position = 58; $shentsize = $br.ReadUInt16(); $shnum = $br.ReadUInt16()
        for ($i = 0; $i -lt $shnum; $i++) {
            $fs.Position = [int64]$shoff + $i * $shentsize + 4
            $type = $br.ReadUInt32()
            if ($type -ne 7) { continue }
            $fs.Position = [int64]$shoff + $i * $shentsize + 24
            $off = $br.ReadUInt64(); $size = $br.ReadUInt64()
            $fs.Position = [int64]$off
            $data = $br.ReadBytes([int]$size)
            foreach ($n in (Read-ElfNotes $data)) { if ($n.Type -eq 3 -and $n.Name -eq 'GNU') { return (($data[$n.Offset..($n.Offset + $n.Size - 1)] | ForEach-Object { '{0:x2}' -f $_ }) -join '') } }
        }
        return $null
    }
    finally { $fs.Dispose() }
}

# Build version from the memory of the core: the product version string is in the process memory several times.
# Used when no build folder matched the build-id (dev builds, unreachable shares). Returns the most frequent match.
function Find-CoreVersionString([string]$Path, [int]$MinMajor = 26) {
    $rx = [regex]'(?<![\d.])((\d{2})\.\d{1,2}\.\d{1,2}\.\d{3,5})(\.dev)?(?![\d.])'
    $counts = @{}
    $enc = [Text.Encoding]::GetEncoding(28591)
    $buf = New-Object byte[] (32MB)
    $fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
        $carry = ''
        while (($n = $fs.Read($buf, 0, $buf.Length)) -gt 0) {
            $s = $carry + $enc.GetString($buf, 0, $n)
            foreach ($m in $rx.Matches($s)) {
                if ([int]$m.Groups[2].Value -lt $MinMajor -or $m.Index + $m.Length -gt $s.Length - 32) { continue }
                $k = $m.Value
                if ($counts.ContainsKey($k)) { $counts[$k]++ } else { $counts[$k] = 1 }
            }
            $carry = if ($s.Length -gt 32) { $s.Substring($s.Length - 32) } else { $s }
        }
    }
    finally { $fs.Dispose() }
    $best = $counts.GetEnumerator() | Where-Object { $_.Value -ge 2 } | Sort-Object Value -Descending | Select-Object -First 1
    if (-not $best) { return $null }
    $parts = $best.Name -split '\.'
    return [pscustomobject]@{ Version = ($parts[0..3] -join '.'); Dev = ($best.Name -like '*.dev'); Text = $best.Name; Count = $best.Value }
}

# Crash time: WSL names the dump 'wsl-crash-<unix time>-<pid>-<exe>-<signal>.dmp'; else the file time.
function Get-CoreCrashTime([string]$Path) {
    if ([IO.Path]::GetFileName($Path) -match '^wsl-crash-(\d{9,11})-') { return ([DateTimeOffset]::FromUnixTimeSeconds([int64]$Matches[1])).UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ') }
    return (Get-Item -LiteralPath $Path).LastWriteTimeUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
}

#region WSL / gdb

function Get-WslDistroArgs($Config) {
    $distro = [string](Get-Cfg (Get-Cfg $Config 'linux' $null) 'wslDistribution' '')
    if ($distro) { return @('-d', $distro) }
    return @()
}

function Invoke-Wsl($Config, [string[]]$Command) {
    $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { $out = & wsl.exe @(Get-WslDistroArgs $Config) -e @Command 2>&1 } finally { $ErrorActionPreference = $eap }
    return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Lines = @($out | ForEach-Object { "$_" }) }
}

function ConvertTo-WslPath($Config, [string]$WindowsPath) {
    $r = Invoke-Wsl $Config @('wslpath', '-a', ($WindowsPath -replace '\\', '/'))
    if ($r.ExitCode -ne 0 -or -not $r.Lines) { throw "Cannot map $WindowsPath into WSL (wslpath failed). Copy the file to a local drive." }
    return $r.Lines[0].Trim()
}

function Test-WslGdb($Config) {
    if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) { return 'WSL is not installed (wsl --install), needed for Linux core dumps' }
    $r = Invoke-Wsl $Config @('sh', '-c', 'command -v gdb')
    if ($r.ExitCode -ne 0 -or -not ($r.Lines -match '/gdb')) { return 'gdb is not installed in the WSL distribution (sudo apt install gdb)' }
    return $null
}

#endregion

#region symbols and sysroot

# Debug file for a build-id: local cache, next to the core, -PdbPath, then the build folders of the product line(s).
function Find-LinuxDebugFile($Config, [string]$BuildId, [string]$Arch, [string[]]$Dirs, [string]$Override) {
    $linuxCfg = Get-Cfg $Config 'linux' $null
    $cacheRoot = Join-Path (Expand-PathValue (Get-Cfg $Config 'localSymbolCache' "$env:LOCALAPPDATA\inmation-crash-analysis\symbols")) 'linux'
    $target = Join-Path (Join-Path (Join-Path $cacheRoot '.build-id') $BuildId.Substring(0, 2)) "$($BuildId.Substring(2)).debug"
    $indexPath = Join-Path $cacheRoot 'build-folders.json'
    $index = @{}
    if (Test-Path -LiteralPath $indexPath) { (Get-Content -LiteralPath $indexPath -Raw | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $index[$_.Name] = $_.Value } }
    if ((Test-Path -LiteralPath $target) -and $index.ContainsKey($BuildId)) { return [pscustomobject]@{ Path = $target; Folder = $index[$BuildId].folder; Source = 'local cache' } }
    $cached = Test-Path -LiteralPath $target
    $checked = @()
    $candidates = @()
    if (-not $cached) {
        if ($Override) { $candidates += [pscustomobject]@{ Path = $Override; Folder = $null; Source = $Override } }
        foreach ($d in @($Dirs | Where-Object { $_ -and (Test-Path -LiteralPath $_) })) {
            foreach ($f in @(Get-ChildItem -LiteralPath $d -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.dbg', '.debug' })) { $candidates += [pscustomobject]@{ Path = $f.FullName; Folder = $null; Source = "$($f.FullName) (next to the core)" } }
        }
    }
    foreach ($c in $candidates) {
        $checked += $c.Path
        $id = $null; try { $id = Read-ElfBuildId $c.Path } catch { }
        if ($id -eq $BuildId) { return (Copy-LinuxDebugFile $c $target) }
    }
    # The build folders are scanned also for a cached debug file: the folder name is the build version.
    $relative = Expand-Template ([string](Get-Cfg $linuxCfg 'debugFile' 'symbols\linux_{arch}\inmation.dbg')) @{ arch = $(if ($Arch -eq 'arm64') { 'arm64' } else { 'amd64' }) }
    $roots = @()
    foreach ($line in @(Get-Cfg $Config 'productLines' @() | Where-Object { [int](Get-Cfg $_ 'minMajor' 0) -ge 26 })) {
        foreach ($k in 'releaseRoots', 'devRoots') { $roots += @(Get-Cfg $line $k @() | ForEach-Object { Expand-PathValue $_ }) }
    }
    $maxFolders = [int](Get-Cfg $linuxCfg 'maxFoldersScanned' 400)
    $scanned = 0
    $changed = $false
    foreach ($root in @($roots | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $root)) { $checked += "$root (not reachable)"; continue }
        foreach ($folder in @(Get-ChildItem -LiteralPath $root -Directory -Filter 'v*' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)) {
            if ($scanned -ge $maxFolders) { break }
            $dbg = Join-Path $folder.FullName $relative
            $known = $index.GetEnumerator() | Where-Object { $_.Value.folder -eq $folder.FullName } | Select-Object -First 1
            $id = if ($known) { $known.Name } else { $null }
            if (-not $id) {
                if (-not (Test-Path -LiteralPath $dbg)) { continue }
                $scanned++
                try { $id = Read-ElfBuildId $dbg } catch { continue }
                if ($id) { $index[$id] = [pscustomobject]@{ folder = $folder.FullName; debugFile = $dbg }; $changed = $true }
            }
            if ($id -eq $BuildId) {
                if ($changed) { New-Item -ItemType Directory -Force -Path $cacheRoot | Out-Null; ConvertTo-Json -InputObject $index -Depth 3 | Set-Content -LiteralPath $indexPath -Encoding UTF8 }
                if ($cached) { return [pscustomobject]@{ Path = $target; Folder = $folder.FullName; Source = "local cache (build folder $($folder.FullName))" } }
                return (Copy-LinuxDebugFile ([pscustomobject]@{ Path = $dbg; Folder = $folder.FullName; Source = $dbg }) $target)
            }
        }
    }
    if ($changed) { New-Item -ItemType Directory -Force -Path $cacheRoot | Out-Null; ConvertTo-Json -InputObject $index -Depth 3 | Set-Content -LiteralPath $indexPath -Encoding UTF8 }
    if ($cached) { return [pscustomobject]@{ Path = $target; Folder = $null; Source = 'local cache (build folder unknown - version not determined)' } }
    $checkedText = if ($checked) { "Checked: $(@($checked) -join '; '); " } else { 'Checked: ' }
    throw "No debug file with build-id $BuildId. $checkedText$scanned build folder(s) with $relative on $(@($roots | Select-Object -Unique) -join ', '). Pass the matching inmation.dbg with -PdbPath or put it next to the core."
}

function Copy-LinuxDebugFile($Candidate, [string]$Target) {
    New-Item -ItemType Directory -Force -Path (Split-Path $Target -Parent) | Out-Null
    Write-Host "  Copying $($Candidate.Path) ($([Math]::Round((Get-Item -LiteralPath $Candidate.Path).Length / 1MB)) MB) to the symbol cache ..."
    Copy-Item -LiteralPath $Candidate.Path -Destination "$Target.partial" -Force
    Move-Item -LiteralPath "$Target.partial" -Destination $Target -Force
    return [pscustomobject]@{ Path = $Target; Folder = $Candidate.Folder; Source = $Candidate.Source }
}

# Executable and shared libraries exactly as in the container, extracted from the product image into the WSL file system
# (keeps symlinks). gdb needs them to unwind (.eh_frame) - the core holds no code pages.
function Get-LinuxSysroot($Config, [string]$Version, [string]$BuildId, [string]$Override, [string]$ExePath) {
    if ($Override) { return [pscustomobject]@{ Path = (ConvertTo-WslPath $Config $Override); Source = $Override; Image = $null } }
    $wslHome = ((Invoke-Wsl $Config @('sh', '-c', 'echo $HOME')).Lines | Select-Object -First 1).Trim()
    $dir = "$wslHome/.cache/inmation-crash-analysis/sysroot/$BuildId"
    $exeRel = $ExePath.TrimStart('/')
    $check = Invoke-Wsl $Config @('test', '-f', "$dir/$exeRel")
    if ($check.ExitCode -eq 0) { return [pscustomobject]@{ Path = $dir; Source = 'cached sysroot'; Image = $null } }
    if (-not $Version) { throw 'No sysroot: the image tag is unknown because the build version is unknown.' }
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw "No sysroot: docker is not available to extract the image of v$Version. Pass -SysrootPath (folder with $ExePath and usr/lib64 of the image)." }
    $errors = @()
    foreach ($pattern in @(Get-Cfg (Get-Cfg $Config 'linux' $null) 'images' @())) {
        $image = Expand-Template ([string]$pattern) @{ version = $Version }
        if ($script:failedImages.ContainsKey($image)) { $errors += "$image ($($script:failedImages[$image]))"; continue }
        $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        try {
            & docker image inspect $image *> $null
            if ($LASTEXITCODE -ne 0) {
                Write-Host "  Pulling $image ..."
                & docker pull $image *> $null
                if ($LASTEXITCODE -ne 0) { $script:failedImages[$image] = 'pull failed'; $errors += "$image (pull failed)"; continue }
            }
            $cid = (& docker create $image 2>$null | Select-Object -First 1)
            if (-not $cid) { $errors += "$image (create failed)"; continue }
            [void](Invoke-Wsl $Config @('mkdir', '-p', $dir))
            $wslArgs = (@(Get-WslDistroArgs $Config) -join ' ')
            Write-Host "  Extracting $ExePath and libraries from $image ..."
            cmd.exe /c "docker export $cid | wsl.exe $wslArgs -e tar -x -C $dir --wildcards lib64 usr/lib64/* lib/* usr/lib/* $exeRel 2>nul" | Out-Null
            & docker rm $cid *> $null
        }
        finally { $ErrorActionPreference = $eap }
        if ((Invoke-Wsl $Config @('test', '-f', "$dir/$exeRel")).ExitCode -eq 0) { return [pscustomobject]@{ Path = $dir; Source = $image; Image = $image } }
        $errors += "$image (no $ExePath inside)"
    }
    throw "No sysroot for v${Version}: $($errors -join '; '). Configure linux.images or pass -SysrootPath."
}

#endregion

#region gdb run and parsing

# gdb command files: the first one loads executable, debug info and core; every further one is a section. gdb stops a
# command file at its first error but continues with the next -x file, so a failing query (no frame 5, no __abort_msg
# symbol, no stack) cannot hide the other sections.
function New-GdbCommands([string]$Sysroot, [string]$DebugDir, [string]$Exe, [string]$Core) {
    $setup = @(
        'set pagination off', 'set width 0', 'set height 0', 'set confirm off', 'set print frame-arguments scalars', 'set print demangle on', 'set print asm-demangle on',
        'set auto-load safe-path /', "set debug-file-directory $DebugDir"
    )
    # Without the image libraries gdb would load the host's libraries and name frames wrongly.
    $setup += "set sysroot $(if ($Sysroot) { $Sysroot } else { '/nonexistent-sysroot' })"
    if ($Exe) { $setup += "file $Exe" }
    $setup += "core-file $Core"
    $chunks = New-Object Collections.Generic.List[object]
    $chunks.Add([string[]]$setup)
    $chunks.Add([string[]]@('echo <<<SECTION:siginfo>>>\n', 'p $_siginfo'))
    # glibc keeps the assert / fatal error text in __abort_msg (struct abort_msg_s { unsigned size; char msg[]; }).
    $chunks.Add([string[]]@('echo <<<SECTION:abortmsg>>>\n', 'x/s *(char**)&__abort_msg + 4'))
    $chunks.Add([string[]]@('echo <<<SECTION:stack>>>\n', 'bt 60'))
    $chunks.Add([string[]]@('echo <<<SECTION:registers>>>\n', 'info registers'))
    $chunks.Add([string[]]@('echo <<<SECTION:disasm>>>\n', 'x/12i $pc'))
    $chunks.Add([string[]]@('echo <<<SECTION:locals>>>\n'))
    for ($f = 0; $f -lt 6; $f++) { $chunks.Add([string[]]@("frame $f", 'info args', 'info locals')) }
    $chunks.Add([string[]]@('echo <<<SECTION:modules>>>\n', 'info sharedlibrary'))
    $chunks.Add([string[]]@('echo <<<SECTION:threads>>>\n', 'thread apply all bt 25'))
    $chunks.Add([string[]]@('echo <<<SECTION:end>>>\n'))
    return , $chunks.ToArray()
}

# Writes the command files (<prefix>.cmd for the setup, <prefix>-<n>.cmd for the rest) and runs gdb with one -x per file.
function Invoke-GdbChunks($Config, [object[]]$Chunks, [string]$Folder, [string]$Prefix) {
    $gdbArgs = @('gdb', '-batch', '-nx')
    $wslFolder = ConvertTo-WslPath $Config $Folder
    for ($i = 0; $i -lt $Chunks.Count; $i++) {
        $name = if ($i -eq 0) { "$Prefix.cmd" } else { "$Prefix-$i.cmd" }
        [IO.File]::WriteAllText((Join-Path $Folder $name), ((@($Chunks[$i]) -join "`n") + "`n"), [Text.UTF8Encoding]::new($false))
        $gdbArgs += @('-x', "$wslFolder/$name")
    }
    return (Invoke-Wsl $Config $gdbArgs)
}

# Splits 'name(args)' into name and '(args)' at the balanced trailing parenthesis group; 'operator()' is kept intact.
function Split-TrailingParens([string]$Text) {
    if (-not $Text.EndsWith(')') -or $Text -match 'operator\s*\(\)$') { return @($Text, $null) }
    $depth = 0
    for ($i = $Text.Length - 1; $i -ge 0; $i--) {
        if ($Text[$i] -eq ')') { $depth++ } elseif ($Text[$i] -eq '(') { $depth--; if ($depth -eq 0) { return @($Text.Substring(0, $i).Trim(), $Text.Substring($i)) } }
    }
    return @($Text, $null)
}

# Parses 'bt' output. Arguments are dropped from the function name; frames without an address are inline frames.
# Names are normalized like cdb names: no parameter signature, no ' [clone .cold]', no '@@GLIBC_2.3.2' symbol version.
function ConvertFrom-GdbBacktrace([string[]]$Lines, $Objects, [string[]]$OwnModules) {
    $frames = @()
    foreach ($line in $Lines) {
        $m = [regex]::Match($line, '^#(?<n>\d+)\s+(?:(?<addr>0x[0-9a-f]+) in )?(?<rest>.+?)(?: at (?<file>\S+):(?<line>\d+))?(?: from (?<lib>\S+))?\s*$')
        if (-not $m.Success) { continue }
        $parts = Split-TrailingParens $m.Groups['rest'].Value.Trim()
        $function = $parts[0]; $argText = $parts[1]
        $function = $function -replace ' \[clone [^\]]+\]$', '' -replace '@@?[A-Z][A-Z_]*[\d.]+$', '' -replace '(\.(cold|part|isra|constprop|lto_priv)(\.\d+)?)+$', ''
        $function = (Split-TrailingParens $function)[0]
        $addr = if ($m.Groups['addr'].Success) { [Convert]::ToUInt64($m.Groups['addr'].Value.Substring(2), 16) } else { $null }
        $module = $null
        if ($m.Groups['lib'].Success) { $module = [IO.Path]::GetFileName($m.Groups['lib'].Value) }
        elseif ($null -ne $addr) { $o = $Objects | Where-Object { $addr -ge $_.Base -and $addr -lt $_.End } | Select-Object -First 1; if ($o) { $module = $o.Name } }
        $frames += [pscustomobject][ordered]@{
            index = [int]$m.Groups['n'].Value; inline = ($null -eq $addr -and [int]$m.Groups['n'].Value -gt 0); module = $module
            function = $(if ($function -eq '??') { if ($null -ne $addr) { '0x{0:x}' -f $addr } else { '??' } } else { $function }); arguments = $argText
            callSite = $null; retAddr = $(if ($null -ne $addr) { '0x{0:x}' -f $addr } else { $null })
            sourceFile = $(if ($m.Groups['file'].Success) { $m.Groups['file'].Value } else { $null }); sourceLine = $(if ($m.Groups['line'].Success) { [int]$m.Groups['line'].Value } else { $null })
            repoPath = $null; buildSnippet = $null; functionFoundAtBuildCommit = $null; thirdParty = $null
        }
    }
    # Inline frames belong to the module of the next physical frame.
    for ($i = $frames.Count - 1; $i -ge 0; $i--) {
        if (-not $frames[$i].module -and -not $frames[$i].retAddr -and $i + 1 -lt $frames.Count) { $frames[$i].module = $frames[$i + 1].module }
    }
    foreach ($f in $frames) {
        $f.callSite = if ($f.module -and $f.function -notmatch '^0x') { "$($f.module)!$($f.function)" } elseif ($f.module -and $f.retAddr) { $o = $Objects | Where-Object { $_.Name -eq $f.module } | Select-Object -First 1; $a = [Convert]::ToUInt64($f.retAddr.Substring(2), 16); if ($o -and $a -ge [uint64]$o.Base) { '{0}+0x{1:x}' -f $f.module, [uint64]($a - [uint64]$o.Base) } else { $f.function } } else { $f.function }
    }
    return , $frames
}

# Text of glibc's __abort_msg from the gdb 'x/s' output: '0x7f..:\t"text"'. Null when not set.
function ConvertFrom-GdbAbortMessage([string[]]$Lines) {
    $text = (@($Lines) -join "`n")
    if ($text -notmatch '(?s)^0x[0-9a-f]+(?: <[^>]*>)?:\s+"(.*)"\s*$') { return $null }
    $msg = $Matches[1] -replace '\\n', "`n" -replace '\\t', "`t" -replace '\\"', '"' -replace '\\\\', '\'
    $msg = $msg.Trim()
    if ($msg) { return $msg }
    return $null
}

# Reporting / runtime frames: abort and throw machinery and frames of the C/C++ runtime libraries.
function Test-LinuxRuntimeFrame($Frame) {
    return (Test-NoiseFrame $Frame) -or $Frame.module -match '^(libc|libstdc\+\+|libgcc_s|ld-linux[^.]*|libpthread|libm)\.so'
}

# Parts of a glibc assert message: '<prog>: <file>:<line>: <function>: Assertion `<expr>' failed.'
function ConvertFrom-AssertMessage([string]$Message) {
    if (-not $Message) { return $null }
    $m = [regex]::Match($Message, '^(?:[^:\s]+: )?(?<file>[^:]+):(?<line>\d+): (?<fn>.*?): Assertion [`''](?<expr>.*)'' failed\.?$', 'Singleline')
    if (-not $m.Success) { return $null }
    return [pscustomobject]@{ File = $m.Groups['file'].Value; Line = $m.Groups['line'].Value; Function = $m.Groups['fn'].Value; Expression = $m.Groups['expr'].Value }
}

# Assertion / abort / terminate facts from the gdb frames (arguments printed as scalars, strings included) and the
# glibc abort message.
function Get-LinuxAssertionInfo($Frames, [string]$AbortMessage) {
    $parsed = ConvertFrom-AssertMessage $AbortMessage
    $assert = $Frames | Where-Object { $_.function -match '^(__assert_fail|__assert_fail_base|__assert_perror_fail)$' -and $_.index -lt 12 } | Select-Object -First 1
    if ($assert -or $parsed) {
        $a = if ($assert) { [string]$assert.arguments } else { '' }
        $get = { param($n) if ($a -match "$n=0x[0-9a-f]+ ""((?:[^""\\]|\\.)*)""") { $Matches[1] } elseif ($a -match "$n=(\d+)") { $Matches[1] } else { $null } }
        $after = if ($assert) { $assert.index } else { -1 }
        $reporter = $Frames | Where-Object { $_.index -gt $after -and -not (Test-LinuxRuntimeFrame $_) } | Select-Object -First 1
        $pick = { param($fromArgs, $fromMessage) if ($fromArgs) { $fromArgs } else { $fromMessage } }
        return [pscustomobject][ordered]@{
            kind = 'assert() (glibc __assert_fail)'; frame = $(if ($assert) { $assert.index } else { $null }); function = $(if ($assert) { $assert.function } else { '__assert_fail' })
            expression = (& $pick (& $get 'assertion') $(if ($parsed) { $parsed.Expression })); file = (& $pick (& $get 'file') $(if ($parsed) { $parsed.File }))
            line = (& $pick (& $get 'line') $(if ($parsed) { $parsed.Line })); inFunction = (& $pick (& $get 'function') $(if ($parsed) { $parsed.Function }))
            reportedBy = $(if ($reporter) { $reporter.callSite } else { $null }); deliberate = $true; note = $(if ($AbortMessage) { "glibc abort message: $AbortMessage" } else { $null }); unwindNote = $null
        }
    }
    if ($AbortMessage) {
        # glibc fatal errors (heap corruption checks, fortify, stack protector) also set __abort_msg.
        $reporter = $Frames | Where-Object { -not (Test-LinuxRuntimeFrame $_) } | Select-Object -First 1
        return [pscustomobject][ordered]@{ kind = 'glibc fatal error'; frame = $null; function = 'abort'; expression = $AbortMessage; file = $null; line = $null; inFunction = $null; reportedBy = $(if ($reporter) { $reporter.callSite } else { $null }); deliberate = $false; note = "glibc abort message: $AbortMessage"; unwindNote = $null }
    }
    $terminate = $Frames | Where-Object { $_.function -match '^(std::terminate|__cxxabiv1::__terminate|__gnu_cxx::__verbose_terminate_handler|__cxa_call_terminate)' -and $_.index -lt 15 } | Select-Object -First 1
    if ($terminate) {
        $reporter = $Frames | Where-Object { $_.index -gt $terminate.index -and -not (Test-LinuxRuntimeFrame $_) } | Select-Object -First 1
        return [pscustomobject][ordered]@{ kind = 'std::terminate (unhandled C++ exception or noexcept violation)'; frame = $terminate.index; function = 'std::terminate'; expression = $null; file = $null; line = $null; inFunction = $null; reportedBy = $(if ($reporter) { $reporter.callSite } else { $null }); deliberate = $true; note = $null; unwindNote = $null }
    }
    $pure = $Frames | Where-Object { $_.function -eq '__cxa_pure_virtual' } | Select-Object -First 1
    if ($pure) { return [pscustomobject][ordered]@{ kind = 'pure virtual call'; frame = $pure.index; function = '__cxa_pure_virtual'; expression = $null; file = $null; line = $null; inFunction = $null; reportedBy = $null; deliberate = $true; note = $null; unwindNote = $null } }
    return $null
}

# Thrown type of an unhandled C++ exception: on Linux the throwing frames stay on the stack (terminate is called from
# __cxa_throw when no handler is found); the type comes from the typeinfo argument of __cxa_throw.
function Get-LinuxCppException($Frames, [string[]]$OwnModules) {
    $throw = $Frames | Where-Object { $_.function -match '^(__cxa_throw|__cxa_rethrow)$' } | Select-Object -First 1
    if (-not $throw) { return $null }
    $after = @($Frames | Where-Object { $_.index -gt $throw.index })
    # libstdc++ throw helpers name the type: std::__throw_system_error -> std::system_error.
    $helper = $after | Select-Object -First 3 | Where-Object { $_.function -match '^std::__throw_([a-z_]+?)(?:_fmt)?(?:\(|$)' } | Select-Object -First 1
    $type = if ([string]$throw.arguments -match '<typeinfo for ([^>]+(?:<[^>]*>)*[^>]*)>') { $Matches[1] }
    elseif ($helper -and $helper.function -match '^std::__throw_([a-z_]+?)(?:_fmt)?(?:\(|$)') { "std::$($Matches[1])" }
    else { 'unknown type (rethrow or typeinfo not printed)' }
    $site = $after | Where-Object { Test-ApplicationFrame $_ $OwnModules } | Select-Object -First 1
    return [pscustomobject][ordered]@{ record = $null; thrownType = $type; errorCategory = $null; errorValue = $null; errorText = $null; throwSite = $site; thrownVia = @($after | Where-Object { $_.function -match '^std::__throw_|^std::_Throw|^boost::throw_exception' } | ForEach-Object { $_.function }); frames = @($after | Select-Object -First 30); source = 'unwound stack (gdb)' }
}

#endregion

#region entry

# Analyzes one Linux core and fills the summary entry (same schema as a Windows dump). $Ctx: Config, Repo, OwnModules,
# DumpFile, DumpOut, Entry, PdbPath, SysrootPath, DumpDirs, FetchStatus.
function Invoke-LinuxCoreDump($Ctx) {
    $config = $Ctx.Config; $repo = $Ctx.Repo; $entry = $Ctx.Entry; $errors = @()
    $core = Read-ElfCoreInfo $Ctx.DumpFile
    $linuxCfg = Get-Cfg $config 'linux' $null
    $exePaths = @(Get-Cfg $linuxCfg 'executables' @('/inmation/bin/inmation'))
    $exe = $core.Objects | Where-Object { $exePaths -contains $_.Path } | Select-Object -First 1
    if (-not $exe) { $exe = $core.Objects | Where-Object { $Ctx.OwnModules -contains $_.Name } | Select-Object -First 1 }
    if (-not $exe -and $core.Process) { $exe = $core.Objects | Where-Object { $_.Name -eq $core.Process.Name } | Select-Object -First 1 }
    if (-not $exe) { throw "No inmation executable ($($exePaths -join ', ')) among the mapped files of the core." }
    $signal = if ($core.SigInfo) { $core.SigInfo.Signo } elseif ($core.CrashThread) { [int]$core.CrashThread.Signal } else { 0 }
    $sigName = if ($script:signalNames.ContainsKey($signal)) { $script:signalNames[$signal] } else { "signal $signal" }
    $siCode = if ($core.SigInfo) { $core.SigInfo.Code } else { $null }
    # si_code <= 0 means the signal was sent (kill, tgkill, sigqueue), not raised by a fault. abort() sends SIGABRT to the
    # process itself (tgkill), so the sender PID (si_pid, namespace-local like the core PID) tells self from others.
    $senderPid = if ($core.SigInfo -and $null -ne $siCode -and $siCode -le 0) { [int64]$core.SigInfo.SenderPid } else { $null }
    $ownPid = if ($core.Process) { [int64]$core.Process.Pid } else { $null }
    $external = $false
    if ($null -ne $siCode -and $siCode -le 0) {
        if ($senderPid -and $ownPid) { $external = $senderPid -ne $ownPid }
        else { $external = ($sigName -ne 'SIGABRT') -or ($siCode -eq 0) }
    }
    $faultAddress = if ($core.SigInfo -and -not $external -and $sigName -in 'SIGSEGV', 'SIGBUS', 'SIGFPE', 'SIGILL') { '0x{0:X}' -f $core.SigInfo.Addr } else { $null }
    $entry.dump.sizeBytes = $core.SizeBytes
    $entry.dump.crashTimeUtc = Get-CoreCrashTime $Ctx.DumpFile
    $entry.dump.processId = if ($core.Process) { $core.Process.Pid } else { $null }
    $entry.dump.architecture = $core.Architecture
    $entry.dump.wow64 = $false
    $entry.dump.platform = 'linux'
    $entry.exception = [ordered]@{
        threadId = $(if ($core.CrashThread) { $core.CrashThread.Tid } else { $null }); code = $sigName; name = $(if ($script:signalTexts.ContainsKey($sigName)) { $script:signalTexts[$sigName] } else { $sigName })
        signal = $signal; siCode = $siCode; external = $external; failFastCode = $null; failFastName = $null; flags = $null
        address = $faultAddress; senderPid = $senderPid; access = $(if ($faultAddress) { "fault at $faultAddress" } elseif ($external) { "sent by another process (si_code $siCode$(if ($senderPid) { ", sender PID $senderPid" }))" } else { $null })
        parameters = @($(if ($faultAddress) { '0xFF'; $faultAddress }))
    }
    $entry.module = [ordered]@{ name = $exe.Name; path = $exe.Path; fileVersion = $null; productVersionInformational = $null; peTimeStampUtc = $null; pdbGuid = "build-id $($exe.BuildId)"; pdbAge = $null; pdbBuildPath = $null; buildId = $exe.BuildId }

    $dbg = $null
    try { if ($exe.BuildId) { $dbg = Find-LinuxDebugFile $config $exe.BuildId $core.Architecture $Ctx.DumpDirs $Ctx.PdbPath } else { $errors += 'The core has no build-id for the executable (ELF header page not in the core).' } }
    catch { $errors += "Symbols: $($_.Exception.Message)" }
    $versionDir = if ($dbg) { $dbg.Folder } else { $null }
    $version = if ($versionDir -and (Split-Path $versionDir -Leaf) -match '^v(\d+\.\d+\.\d+\.\d+)') { $Matches[1] } else { $null }
    $entry.module.versionSource = if ($version) { "build folder $versionDir" } else { $null }
    $devBuild = $false
    if (-not $version) {
        $found = $null
        try { $found = Find-CoreVersionString $Ctx.DumpFile } catch { $errors += "Version scan of the core failed: $($_.Exception.Message)" }
        if ($found) {
            $version = $found.Version
            $devBuild = $found.Dev
            $entry.module.productVersionInformational = $found.Text
            $entry.module.versionSource = "version string '$($found.Text)' found $($found.Count) times in the process memory (no build folder matched the build-id)"
        }
    }
    $entry.module.fileVersion = $version
    $vars = @{ version = $version }
    if ($version) { $v = $version.Split('.'); $vars.major = $v[0]; $vars.minor = $v[1]; $vars.revision = $v[2]; $vars.build = $v[3] }
    $line = Get-ProductLine $config $(if ($version) { $vars } else { @{ major = '26' } })
    $channel = if ($version) { Get-BuildChannel $config $vars } else { 'unknown' }
    $buildInfo = Read-BuildInfo $config $versionDir
    $buildTime = Get-BuildTime $config $versionDir ([pscustomobject]@{ TimeStamp = 0 })
    $build = Find-BuildCommit $config $repo $vars $buildTime $buildInfo $line.CompareRef
    $build.version = $version; $build.productLine = $line.Name; $build.channel = $channel; $build.folder = $versionDir; $build.brand = $null
    $build.folderChannel = $null; $build.brokenBuildMarker = $false
    $build.buildTimeUtc = if ($buildTime) { $buildTime.TimeUtc.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null }
    $build.buildTimeSource = if ($buildTime) { $buildTime.Source } else { $null }
    $entry.build = $build
    $compareCommit = (Invoke-Git $repo @('rev-parse', '--verify', '--quiet', "$($line.CompareRef)^{commit}")).Lines | Select-Object -First 1
    $entry.compare = [ordered]@{ ref = $line.CompareRef; commit = $compareCommit; reason = "compare ref of product line '$($line.Name)'"; buildCommitIsAncestor = $null; mergeBase = $null; fetch = $Ctx.FetchStatus }
    if ($build.commit -and $compareCommit) {
        $entry.compare.buildCommitIsAncestor = (Invoke-Git $repo @('merge-base', '--is-ancestor', $build.commit, $compareCommit)).ExitCode -eq 0
        $entry.compare.mergeBase = (Invoke-Git $repo @('merge-base', $build.commit, $compareCommit)).Lines | Select-Object -First 1
    }
    $entry.symbols = [ordered]@{ pdbName = 'inmation.dbg'; pdbPath = $(if ($dbg) { $dbg.Path } else { $null }); source = $(if ($dbg) { $dbg.Source } else { $null }); guidVerified = [bool]$dbg; versionDir = $versionDir; brand = $null; buildFolderCandidates = @(); loadStatus = $null; cdbSymbolPath = $null; cdbImagePath = $null; trusted = $false; sysroot = $null; buildId = $exe.BuildId }

    $gdbProblem = Test-WslGdb $config
    $frames = @()
    $sections = @{}
    $abortMessage = $null
    if ($gdbProblem) { $errors += "Linux core: $gdbProblem." }
    else {
        $sysroot = $null
        try { $sysroot = Get-LinuxSysroot $config $version $exe.BuildId $Ctx.SysrootPath $exe.Path; $entry.symbols.sysroot = "$($sysroot.Path) ($($sysroot.Source))" }
        catch { $errors += "Sysroot: $($_.Exception.Message) Without the executable gdb cannot unwind the stack (the core has no code pages)." }
        $debugDir = ConvertTo-WslPath $config (Join-Path (Expand-PathValue (Get-Cfg $config 'localSymbolCache' "$env:LOCALAPPDATA\inmation-crash-analysis\symbols")) 'linux')
        $coreWsl = ConvertTo-WslPath $config $Ctx.DumpFile
        $exeWsl = if ($sysroot) { "$($sysroot.Path)/$($exe.Path.TrimStart('/'))" } else { $null }
        $chunks = New-GdbCommands $(if ($sysroot) { $sysroot.Path } else { $null }) $debugDir $exeWsl $coreWsl
        Write-Host 'Running gdb (WSL) ...'
        $run = Invoke-GdbChunks $config $chunks $Ctx.DumpOut 'gdb'
        $gdbLog = Join-Path $Ctx.DumpOut 'gdb.log'
        Set-Content -LiteralPath $gdbLog -Value ($run.Lines | Where-Object { $_ -notmatch '^\[New LWP \d+\]$' }) -Encoding UTF8
        $sections = Split-CdbSections $run.Lines
        $frames = ConvertFrom-GdbBacktrace (Get-Section $sections 'stack') $core.Objects $Ctx.OwnModules
        $abortMessage = ConvertFrom-GdbAbortMessage (Get-Section $sections 'abortmsg')
        $entry.abortMessage = $abortMessage
        if ($frames.Count -eq 0) { $errors += "gdb returned no stack; see $gdbLog." }
        $entry.files = [ordered]@{ cdbLog = $gdbLog; analyze = $null; locals = $null; frame0LocalsDx = $null; threads = $null; contextLog = $null; cxxScan = $null; scripts = @(); libraries = @() }
        $threadsFile = Join-Path $Ctx.DumpOut 'threads.txt'; Set-Content -LiteralPath $threadsFile -Value (Get-Section $sections 'threads'); $entry.files.threads = $threadsFile
        $localsFile = Join-Path $Ctx.DumpOut 'locals.txt'; Set-Content -LiteralPath $localsFile -Value (Get-Section $sections 'locals'); $entry.files.locals = $localsFile
        $entry.registers = (Get-Section $sections 'registers') -join "`n"
        $dis = @(Get-Section $sections 'disasm')
        $entry.disassembly = (@($dis | ForEach-Object -Begin { $first = $true } -Process { if ($first -and $_ -match '^=>') { $first = $false; "$_    <<< faulting instruction" } else { $_ } })) -join "`n"
        $entry.localsTop = (@(Get-Section $sections 'locals' | Select-Object -First 250)) -join "`n"
        $entry.symbols.loadStatus = if (@($frames | Where-Object { $_.module -eq $exe.Name -and $_.sourceFile }).Count) { 'DWARF debug info (build-id verified)' } elseif ($dbg) { 'debug file found, but no source lines in the stack' } else { 'no debug info' }
    }
    $trusted = [bool]($dbg -and $entry.symbols.loadStatus -like 'DWARF*')
    $entry.symbols.trusted = $trusted
    $entry.crashStack = $frames
    if (-not $trusted) {
        $reason = if (-not $dbg) { 'no debug file with a matching build-id was found' } elseif ($gdbProblem) { $gdbProblem } else { "gdb: $($entry.symbols.loadStatus)" }
        $entry.blocked = [ordered]@{ reason = "Symbols not verified: $reason."; requiredPdb = 'inmation.dbg'; pdbGuid = "build-id $($exe.BuildId)"; pdbAge = $null; identity = "build-id $($exe.BuildId)"; binaryLinkedUtc = $null; installPath = $exe.Path; hint = $null }
        if (-not $dbg) {
            $relative = Expand-Template ([string](Get-Cfg $linuxCfg 'debugFile' 'symbols\linux_{arch}\inmation.dbg')) @{ arch = $(if ($core.Architecture -eq 'arm64') { 'arm64' } else { 'amd64' }) }
            $entry.blocked.hint = if ($version) { "Get $relative from the build folder v$version ($channel build; $($entry.module.versionSource)) and pass it with -PdbPath, or put it next to the core." } else { "The build version is unknown; ask the reporter for the image tag or version, then get $relative from that build folder." }
        }
        $entry.rawStack = @($frames | ForEach-Object { [pscustomobject][ordered]@{ index = $_.index; inline = $_.inline; address = $_.callSite } })
        $rawTop = @($entry.rawStack | Where-Object { $_.address }) | Select-Object -First 1
        $entry.signature = "[unverified symbols] $sigName at $(if ($rawTop) { $rawTop.address } elseif ($faultAddress) { $faultAddress } else { 'unknown address' }) (build-id $($exe.BuildId))"
        $entry.signatureFamily = $entry.signature
        if ($build.commit) { $build.rejectedCommit = [ordered]@{ commit = $build.commit; confidence = $build.confidence; method = $build.method }; $build.commit = $null; $build.confidence = 'none'; $build.method = $null }
        $entry.classification = Get-CrashClassification $entry.exception $null @() $null $null $Ctx.OwnModules $false
        $entry.errors = $errors
        return $entry
    }
    Add-SourceSnippets $frames $repo $build.commit $config $Ctx.OwnModules
    $entry.thirdParty = @(Get-ThirdPartyPorts $frames $config $repo $build.commit $compareCommit)
    $entry.assertion = Get-LinuxAssertionInfo $frames $abortMessage
    $entry.cppException = Get-LinuxCppException $frames $Ctx.OwnModules
    $sig = Get-CrashSignature $frames $entry.assertion $Ctx.OwnModules
    $entry.signature = $sig.Signature
    $entry.signatureFamily = $sig.Family
    $entry.signatureInfo = [ordered]@{ topFrame = $(if ($sig.TopFrame) { $sig.TopFrame.index } else { $null }); firstOwnFrame = $(if ($sig.FirstOwnFrame) { $sig.FirstOwnFrame.index } else { $null }); noApplicationFrame = $sig.NoApplicationFrame }
    $entry.classification = Get-CrashClassification $entry.exception $entry.assertion $frames $sig $entry.cppException $Ctx.OwnModules $false
    $entry.sourceHistory = @(Get-SourceHistory $frames $repo $build.commit $compareCommit $config)
    if (@($frames | Where-Object { $_.function -match '^(luaV_execute|luaD_precall|lua_pcallk)$' }).Count) { $errors += 'Lua frames on the stack: the Lua call chain is not decoded for Linux cores yet; use gdb manually (see references/linux-cores.md).' }
    $entry.errors = $errors
    return $entry
}

#endregion
