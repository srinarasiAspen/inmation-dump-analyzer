. (Join-Path $script:LibRoot 'Common.ps1')
. (Join-Path $script:LibRoot 'Frames.ps1')
. (Join-Path $script:LibRoot 'CodeEvidence.ps1')

$script:CppSample = @'
#include "x.h"

namespace inmation { namespace server {

// cache::get returns the cached object
BSONObj cache::get(const std::string& tag)
{
    std::unique_lock<std::mutex> l(_mutex);
    auto it = _entries.find(tag);   // "{" in a string is ignored: "}"
    if (it == _entries.end()) {
        return BSONObj();
    }
    /* a block comment with { */
    return it->second.getObjectField("x");
}

void cache::put(const std::string& tag, BSONObj obj);

void user()
{
    auto o = c.get("tag");
}

RequestContext::~RequestContext()
{
    _timer.cancel();
}

}}
'@ -split "`r?`n"

Describe 'function names' {
    It 'splits class and method, maps constructors and destructors' {
        $f = Split-FunctionName 'inmation::server::cache::get'
        Assert-Equal 'cache' $f.Class; Assert-Equal 'get' $f.Method; Assert-True $f.Usable
        Assert-Equal '~RequestContext' (Split-FunctionName 'OpcUa::Server::RequestContext::{dtor}').Method
        Assert-Equal 'BSONObjIterator' (Split-FunctionName 'mongo::BSONObjIterator::{ctor}').Method
        Assert-False (Split-FunctionName '`anonymous namespace''::<lambda_1>::operator()').Usable
    }
}

Describe 'function boundaries' {
    It 'finds the definition and its end, ignoring braces in strings and comments' {
        $defs = Find-FunctionDefinitions $script:CppSample 'cache' 'get'
        Assert-Equal 1 $defs.Count
        Assert-Equal 6 $defs[0].Start
        Assert-Equal 15 $defs[0].End
    }
    It 'skips declarations and calls' {
        Assert-Equal 0 (Find-FunctionDefinitions $script:CppSample 'cache' 'put').Count
    }
    It 'finds destructors' {
        $defs = Find-FunctionDefinitions $script:CppSample 'RequestContext' '~RequestContext'
        Assert-Equal 1 $defs.Count
        Assert-Equal 24 $defs[0].Start
    }
    It 'finds free functions with a template return type, but not member calls' {
        $src = @(
            'namespace DatasourceApi {',
            'std::unordered_map<idandft_key, IP21_grpc::Result> ReadHistory(',
            '    const Request& r)',
            '{',
            '    auto x = other->ReadHistory(r);',
            '    return x;',
            '}',
            '}'
        )
        $defs = Find-FunctionDefinitions $src 'DatasourceApi' 'ReadHistory'
        Assert-Equal 1 $defs.Count
        Assert-Equal 2 $defs[0].Start
        Assert-Equal 7 $defs[0].End
    }
    It 'selects the definition that contains the faulting line' {
        $defs = Find-FunctionDefinitions $script:CppSample 'cache' 'get'
        Assert-Equal 6 (Select-FunctionDefinition $defs 14 $script:CppSample $null).Start
        Assert-Null (Select-FunctionDefinition $defs 22 $script:CppSample $null)
    }
}

Describe 'text diff' {
    It 'returns hunks for changed lines only' {
        $d = Get-TextDiff @('a', 'b', 'c') @('a', 'B', 'c') 0
        Assert-True (@($d | Where-Object { $_ -eq '-b' }).Count -eq 1)
        Assert-True (@($d | Where-Object { $_ -eq '+B' }).Count -eq 1)
        Assert-Equal 0 @(Get-TextDiff @('a') @('a')).Count
    }
}
