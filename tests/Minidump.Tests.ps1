. (Join-Path $script:LibRoot 'Common.ps1')
. (Join-Path $script:LibRoot 'Minidump.ps1')

# Writes a minimal minidump: SystemInfo, MiscInfo, Exception and ModuleList streams with one module and a CodeView record.
function New-TestMinidump([string]$Path, [uint32]$ExceptionCode, [uint64[]]$Parameters, [string]$ModulePath, [string]$FileVersion, [Guid]$PdbGuid) {
    $ms = New-Object IO.MemoryStream
    $w = New-Object IO.BinaryWriter($ms)
    $w.Write([byte[]]::new(4096))
    $at = { param([int64]$Pos) $ms.Position = $Pos }
    $dumpTime = [uint32]1790000000
    # header + 4 directory entries
    & $at 0
    $w.Write([uint32]0x504D444D); $w.Write([uint32]0xA793); $w.Write([uint32]4); $w.Write([uint32]32); $w.Write([uint32]0); $w.Write($dumpTime); $w.Write([uint64]0)
    $dir = @(@(7, 56, 200), @(15, 24, 300), @(6, 168, 400), @(4, 112, 700))
    foreach ($d in $dir) { $w.Write([uint32]$d[0]); $w.Write([uint32]$d[1]); $w.Write([uint32]$d[2]) }
    & $at 200; $w.Write([uint16]9)
    & $at 300; $w.Write([uint32]24); $w.Write([uint32]3); $w.Write([uint32]4242); $w.Write([uint32]($dumpTime - 3725))
    & $at 400; $w.Write([uint32]77); $w.Write([uint32]0); $w.Write($ExceptionCode); $w.Write([uint32]0); $w.Write([uint64]0); $w.Write([uint64]0x7FF612345678); $w.Write([uint32]$Parameters.Count); $w.Write([uint32]0)
    for ($i = 0; $i -lt 15; $i++) { $w.Write([uint64]$(if ($i -lt $Parameters.Count) { $Parameters[$i] } else { 0 })) }
    $v = $FileVersion.Split('.') | ForEach-Object { [uint32]$_ }
    & $at 700; $w.Write([uint32]1)
    $w.Write([uint64]0x7FF600000000); $w.Write([uint32]0x1000000); $w.Write([uint32]0); $w.Write([uint32]1780000000); $w.Write([uint32]1000)
    $w.Write([uint32]0xFEEF04BDL); $w.Write([uint32]0x10000); $w.Write([uint32](($v[0] -shl 16) -bor $v[1])); $w.Write([uint32](($v[2] -shl 16) -bor $v[3])); $w.Write([uint32]0x10003); $w.Write([uint32]0)
    & $at (704 + 76); $w.Write([uint32]40); $w.Write([uint32]1200)
    $name = [Text.Encoding]::Unicode.GetBytes($ModulePath)
    & $at 1000; $w.Write([uint32]$name.Length); $w.Write($name)
    & $at 1200; $w.Write([Text.Encoding]::ASCII.GetBytes('RSDS')); $w.Write($PdbGuid.ToByteArray()); $w.Write([uint32]1); $w.Write([Text.Encoding]::ASCII.GetBytes("inmation.pdb`0"))
    [IO.File]::WriteAllBytes($Path, $ms.ToArray())
}

Describe 'minidump parsing' {
    $guid = [Guid]'ea4ae679-76a5-457c-afea-3711ab45b4ae'
    $path = Join-Path $env:TEMP "cda-test-$([Guid]::NewGuid().ToString('N')).dmp"
    try {
        New-TestMinidump $path 0xC0000005L @(0, 0x24) 'C:\inmation.root\bin\inmation.exe' '1.113.0.32906' $guid
        $info = Read-MinidumpInfo $path

        It 'reads architecture, process id and uptime' {
            Assert-Equal 'x64' $info.Architecture
            Assert-Equal 4242 $info.ProcessId
            Assert-Equal 3725 $info.UptimeSeconds
            Assert-Equal '01:02:05' $info.Uptime
        }
        It 'decodes an access violation with the access type' {
            Assert-Equal '0xC0000005' $info.Exception.code
            Assert-Equal 'ACCESS_VIOLATION' $info.Exception.name
            Assert-Equal 'read from 0x24' $info.Exception.access
            Assert-Equal 77 $info.Exception.threadId
        }
        It 'reads module file version and PDB identity' {
            $m = $info.Modules[0]
            Assert-Equal 'inmation.exe' $m.Name
            Assert-Equal '1.113.0.32906' $m.FileVersion
            Assert-Equal $guid.ToString() $m.PdbGuid
            Assert-Equal 1 $m.PdbAge
        }
    }
    finally { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }

    It 'labels fail-fast abort (subcode 7) as a deliberate abort' {
        $p = Join-Path $env:TEMP "cda-test-$([Guid]::NewGuid().ToString('N')).dmp"
        try {
            New-TestMinidump $p 0xC0000409L @(7) 'C:\inmation.root\bin\inmation.exe' '26.1.0.8800' $guid
            $e = (Read-MinidumpInfo $p).Exception
            Assert-Equal 7 $e.failFastCode
            Assert-Match '^ABORT' $e.name
        }
        finally { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue }
    }
    It 'rejects files that are not minidumps' {
        $p = Join-Path $env:TEMP "cda-test-$([Guid]::NewGuid().ToString('N')).dmp"
        try {
            [IO.File]::WriteAllBytes($p, [byte[]](0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0))
            Assert-Throws { Read-MinidumpInfo $p } 'MDMP'
        }
        finally { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'exception names' {
    It 'names common codes and fail-fast subcodes' {
        Assert-Equal 'STACK_OVERFLOW' (Get-ExceptionName 0xC00000FDL)
        Assert-Equal 'UNKNOWN' (Get-ExceptionName 0x12345678)
        Assert-Equal 'FAST_FAIL_STACK_COOKIE_CHECK_FAILURE' (Get-FailFastName 2)
        Assert-Match '/GS' (Get-FailFastLabel 2)
    }
}
