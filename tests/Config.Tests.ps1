. (Join-Path $script:LibRoot 'Common.ps1')
. (Join-Path $script:LibRoot 'BuildLookup.ps1')
. (Join-Path $script:LibRoot 'Vcpkg.ps1')

$script:DefaultConfig = Get-Content -LiteralPath (Join-Path $script:ScriptRoot 'crash-dump-analyzer.config.json') -Raw | ConvertFrom-Json

Describe 'configuration' {
    It 'merges user overrides recursively and replaces arrays' {
        $base = '{"a":1,"tfs":{"url":"u","top":15},"brands":[{"name":"aspen"}]}' | ConvertFrom-Json
        $over = '{"tfs":{"top":5},"brands":[{"name":"x"}],"_comment":"ignored"}' | ConvertFrom-Json
        $m = Merge-ConfigObject $base $over
        Assert-Equal 1 $m.a
        Assert-Equal 'u' $m.tfs.url
        Assert-Equal 5 $m.tfs.top
        Assert-Equal 'x' @($m.brands)[0].name
        Assert-Null $m.PSObject.Properties['_comment']
    }
    It 'expands templates' {
        Assert-Equal 'origin/release/v1.94' (Expand-Template 'origin/release/v{major}.{minor}' @{ major = '1'; minor = '94' })
    }
    It 'ships a valid default configuration' {
        Assert-True (@($script:DefaultConfig.productLines).Count -ge 2)
        Assert-NotNull $script:DefaultConfig.tfs.url
    }
}

Describe 'product line and channel routing' {
    It 'routes file major 26+ to OT Data Fabric and origin/main' {
        $line = Get-ProductLine $script:DefaultConfig @{ major = '26'; minor = '1' }
        Assert-Match 'OT Data Fabric' $line.Name
        Assert-Equal 'origin/main' $line.CompareRef
    }
    It 'routes file major 1 to inmation 1.x and origin/main-legacy' {
        $line = Get-ProductLine $script:DefaultConfig @{ major = '1'; minor = '112' }
        Assert-Equal 'origin/main-legacy' $line.CompareRef
    }
    It 'treats odd minor versions as dev builds' {
        Assert-Equal 'dev' (Get-BuildChannel $script:DefaultConfig @{ minor = '113' })
        Assert-Equal 'release' (Get-BuildChannel $script:DefaultConfig @{ minor = '112' })
        Assert-Equal 'dev' (Get-BuildChannel $script:DefaultConfig @{ minor = '1' })
        Assert-Equal 'release' (Get-BuildChannel $script:DefaultConfig @{ minor = '0' })
    }
    It 'orders brands by install path hints' {
        $brands = @(Get-OrderedBrands $script:DefaultConfig 'D:\AspenTech\inmation.root\bin\inmation.exe')
        Assert-Equal 'aspen' $brands[0].Name
        Assert-Equal 'AspenTech' $brands[0].Hint
    }
}

Describe 'vcpkg source paths' {
    It 'maps buildtrees paths to port, version and relative path' {
        $tp = ConvertFrom-VcpkgSourcePath 'E:\ws\vcpkg\buildtrees\mongo-c-driver\src\1.24.4-3a1b2c3d4e.clean\src\libmongoc\src\mongoc\mongoc-cursor.c'
        Assert-Equal 'mongo-c-driver' $tp.port
        Assert-Equal '1.24.4' $tp.version
        Assert-Equal 'src/libmongoc/src/mongoc/mongoc-cursor.c' $tp.relPath
    }
    It 'takes the version from shortened source folder names' {
        $tp = ConvertFrom-VcpkgSourcePath 'E:\ws\vcpkg\buildtrees\mongo-cxx-driver-legacy10\src\gacy-1.0.7-9300c7d0ac.clean\src\mongo\bson\bsonobj.cpp'
        Assert-Equal '1.0.7' $tp.version
        Assert-Equal 'gacy-1.0.7' $tp.dirPrefix
        Assert-Equal 'efb1cc9977' (ConvertFrom-VcpkgSourcePath 'E:\ws\vcpkg\buildtrees\opcua-ansic\src\efb1cc9977-a43567395d.clean\Stack\x.c').version
    }
    It 'maps vcpkg_installed headers without a port' {
        $tp = ConvertFrom-VcpkgSourcePath 'E:\ws\vcpkg_installed\x64-windows-static\include\boost\asio\detail\impl\win_iocp_io_context.hpp'
        Assert-Null $tp.port
        Assert-Equal 'include/boost/asio/detail/impl/win_iocp_io_context.hpp' $tp.relPath
    }
    It 'ignores product sources' {
        Assert-Null (ConvertFrom-VcpkgSourcePath 'E:\ws\server\inmation\inServer.cpp')
    }
}
