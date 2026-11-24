. (Join-Path $script:LibRoot 'Common.ps1')
. (Join-Path $script:LibRoot 'Frames.ps1')
. (Join-Path $script:LibRoot 'Classification.ps1')
. (Join-Path $script:LibRoot 'Report.ps1')

function New-TestFrame([int]$Index, [string]$Function, [string]$Module = 'inmation', [string]$File = 'E:\ws\server\inmation\x.cpp') {
    return [pscustomobject]@{ index = $Index; inline = $false; module = $Module; function = $Function; callSite = "$Module!$Function+0x10"; sourceFile = $File; sourceLine = 10; thirdParty = $null }
}

function New-TestException([string]$Code, [string[]]$Parameters, [string]$Address = '0x00007FF600001000', $FailFast = $null) {
    return [pscustomobject]@{ code = $Code; name = 'X'; address = $Address; parameters = $Parameters; failFastCode = $FailFast; failFastName = $null; access = $null; threadId = 1 }
}

Describe 'crash classification' {
    $frames = @((New-TestFrame 0 'inmation::server::cache::get'), (New-TestFrame 1 'inmation::server::access::get_metaevents'))
    $sig = Get-CrashSignature $frames $null @('inmation')

    It 'classifies a read near address 0 as a null-pointer access' {
        $c = Get-CrashClassification (New-TestException '0xC0000005' @('0x0', '0x24')) $null $frames $sig $null @('inmation') $false
        Assert-Equal 'null-pointer' $c.category
        Assert-Match 'Null-pointer read in cache::get' $c.title
        Assert-Match 'offset 0x24' $c.text
    }
    It 'classifies a non-null invalid address as a wild pointer' {
        $c = Get-CrashClassification (New-TestException '0xC0000005' @('0x0', '0x15E3AA5E464')) $null $frames $sig $null @('inmation') $false
        Assert-Equal 'wild-pointer' $c.category
        Assert-Equal 'culprit-or-victim' $c.stackRole
    }
    It 'classifies execute access as a bad code pointer' {
        $c = Get-CrashClassification (New-TestException '0xC0000005' @('0x8', '0x1234')) $null $frames $sig $null @('inmation') $false
        Assert-Equal 'bad-code-pointer' $c.category
    }
    It 'classifies a negative offset from null as null-pointer' {
        $c = Get-CrashClassification (New-TestException '0xC0000005' @('0x1', '0xFFFFFFFFFFFFFFF8')) $null $frames $sig $null @('inmation') $false
        Assert-Equal 'null-pointer' $c.category
        Assert-Match 'write' $c.title
    }
    It 'treats heap corruption as a possible victim stack' {
        $c = Get-CrashClassification (New-TestException '0xC0000374' @()) $null $frames $sig $null @('inmation') $false
        Assert-Equal 'heap-corruption' $c.category
        Assert-Equal 'victim-possible' $c.stackRole
    }
    It 'distinguishes fail-fast subcodes' {
        Assert-Equal 'stack-buffer-overrun' (Get-CrashClassification (New-TestException '0xC0000409' @('0x2') -FailFast 2) $null $frames $sig $null @('inmation') $false).category
        Assert-Equal 'deliberate-abort' (Get-CrashClassification (New-TestException '0xC0000409' @('0x7') -FailFast 7) $null $frames $sig $null @('inmation') $false).category
        Assert-Equal 'memory-corruption-detected' (Get-CrashClassification (New-TestException '0xC0000409' @('0x3') -FailFast 3) $null $frames $sig $null @('inmation') $false).category
    }
    It 'reports failed assertions with the expression' {
        $a = [pscustomobject]@{ kind = 'BSON_ASSERT (libbson/libmongoc)'; expression = '*collection_len > 0'; function = '_bson_assert_failed_on_line' }
        $c = Get-CrashClassification (New-TestException '0xC0000409' @('0x7') -FailFast 7) $a $frames $sig $null @('inmation') $false
        Assert-Equal 'failed-assertion' $c.category
        Assert-Match "BSON_ASSERT '\*collection_len > 0'" $c.title
    }
    It 'reports unhandled C++ exceptions with type and destructor hint' {
        $a = [pscustomobject]@{ kind = 'std::terminate (unhandled C++ exception or noexcept violation)'; expression = $null; function = 'terminate' }
        $cpp = [pscustomobject]@{ thrownType = 'std::system_error'; errorText = 'generic_category 36 = resource_deadlock_would_occur (EDEADLK)'; throwSite = (New-TestFrame 2 'OpcUa::Server::RequestContext::~RequestContext') }
        $c = Get-CrashClassification (New-TestException '0xC0000409' @('0x7') -FailFast 7) $a $frames $sig $cpp @('inmation') $false
        Assert-Equal 'unhandled-cpp-exception' $c.category
        Assert-Equal 'Unhandled std::system_error thrown in RequestContext::~RequestContext' $c.title
        Assert-True (@($c.hints | Where-Object { $_ -match 'implicitly noexcept' }).Count -eq 1)
    }
    It 'detects recursion in stack overflows' {
        $rec = @(0..5 | ForEach-Object { New-TestFrame $_ 'inmation::model::walk' })
        $c = Get-CrashClassification (New-TestException '0xC00000FD' @()) $null $rec (Get-CrashSignature $rec $null @('inmation')) $null @('inmation') $false
        Assert-Equal 'stack-overflow' $c.category
        Assert-Match 'recursion' $c.title
    }
    It 'handles dumps without exception record' {
        Assert-Equal 'no-exception' (Get-CrashClassification $null $null $frames $sig $null @('inmation') $false).category
    }
    It 'points at external modules' {
        $ext = @((New-TestFrame 0 'h21_read_event_header_data' 'h21sys' 'C:\x\h21.c'), (New-TestFrame 1 'Aspentech::InfoPlus21::DatasourceApi::ProcessBatchOfAttributeData'))
        $c = Get-CrashClassification (New-TestException '0xC0000005' @('0x0', '0x10')) $null $ext (Get-CrashSignature $ext $null @('inmation')) $null @('inmation') $false
        Assert-Match 'external module h21sys' $c.text
        Assert-True (@($c.hints | Where-Object { $_ -match 'not an inmation binary' }).Count -eq 1)
    }
}

Describe 'crash report' {
    $dump = [pscustomobject]@{
        dump = [pscustomobject]@{ path = 'C:\d\inmation.exe.1.dmp'; archive = $null; copies = @(); crashTimeUtc = '2026-01-01T00:00:00Z'; uptime = '01:00:00'; processId = 1 }
        module = [pscustomobject]@{ name = 'inmation.exe'; fileVersion = '1.112.0.1'; pdbGuid = 'g' }
        exception = (New-TestException '0xC0000005' @('0x0', '0x24'))
        assertion = $null; cppException = $null; blocked = $null
        symbols = [pscustomobject]@{ pdbName = 'inmation.pdb'; loadStatus = 'private pdb symbols'; source = 'local cache' }
        build = [pscustomobject]@{ productLine = 'inmation (v1.x)'; channel = 'release'; commit = $null }
        compare = [pscustomobject]@{ ref = 'origin/main-legacy' }
        signatureInfo = [pscustomobject]@{ topFrame = 0; firstOwnFrame = 0; noApplicationFrame = $false }
        classification = [pscustomobject]@{ category = 'null-pointer'; title = 'Null-pointer read in cache::get'; text = 't'; hints = @() }
        crashStack = @((New-TestFrame 0 'inmation::server::cache::get'), (New-TestFrame 1 'inmation::server::access::get_metaevents'))
        luaStack = @(); scriptContext = @(); rawStack = @(); errors = @()
    }
    $summary = [pscustomobject]@{ generatedUtc = 'now'; uniqueDumps = 1; inputDumpFiles = 1; sourceAvailable = $true; sourceNote = $null; runDir = 'C:\run'; extractedDumps = @()
        groups = @([pscustomobject]@{ signature = 'inmation!inmation::server::cache::get'; dumps = @('C:\d\inmation.exe.1.dmp'); exactSignatures = @('x') })
        dumps = @($dump) }
    $md = New-CrashReportMarkdown $summary

    It 'uses the classification as title' {
        Assert-Match '^# Crash analysis: Null-pointer read in cache::get' $md
    }
    It 'attributes the generated report to the dump analyzer plugin' {
        Assert-Match '> Generated by inmation dump analyzer \(stage 1\) on now\.' $md
    }
    It 'has the numbered sections in order' {
        $positions = @(1..5 | ForEach-Object { $md.IndexOf("## $($script:ReportSections[$_])") })
        Assert-False ($positions -contains -1) 'all sections present'
        Assert-Equal (@($positions | Sort-Object)) $positions
    }
    It 'lists the first frames' {
        Assert-Match ' 0  inmation!inmation::server::cache::get\+0x10  \(x\.cpp:10\)' $md
    }
    It 'replaces a section and header rows' {
        $path = Join-Path $env:TEMP "cda-report-$([Guid]::NewGuid().ToString('N')).md"
        try {
            [IO.File]::WriteAllText($path, $md)
            Set-ReportSection $path 2 "Found #123.`n`nDetails." @{ 'Existing work item' = '#123 (same)'; 'Stages done' = '1, 2' }
            $text = [IO.File]::ReadAllText($path)
            Assert-Match 'Found #123' $text
            Assert-NotMatch '_Not done yet - stage 2._' $text
            Assert-Match '_Not done yet - stage 3._' $text
            Assert-Equal '#123 (same)' (Get-ReportHeaderValue $path 'Existing work item')
            Assert-Equal '1, 2' (Get-ReportHeaderValue $path 'Stages done')
        }
        finally { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
    }
}
