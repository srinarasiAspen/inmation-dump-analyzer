# Binary parsing without a debugger: minidump streams, PDB info stream, PE CodeView record.

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
            # Memory64ListStream: the dump holds full process memory (heap), not only stacks and selected ranges.
            FullMemory   = $streams.ContainsKey(9)
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
