. (Join-Path $script:LibRoot 'Common.ps1')
. (Join-Path $script:LibRoot 'Frames.ps1')
. (Join-Path $script:LibRoot 'SearchTerms.ps1')
. (Join-Path $script:LibRoot 'TfsMatch.ps1')

$script:AvDump = [pscustomobject]@{
    exception      = [pscustomobject]@{ code = '0xC0000005' }
    classification = [pscustomobject]@{ category = 'wild-pointer' }
    assertion      = $null
    crashStack     = @(
        [pscustomobject]@{ index = 0; module = 'inmation'; function = 'mongo::BSONObjIterator::{ctor}' },
        [pscustomobject]@{ index = 1; module = 'inmation'; function = 'mongo::BSONObj::getField' },
        [pscustomobject]@{ index = 2; module = 'inmation'; function = 'mongo::BSONObj::getObjectField' },
        [pscustomobject]@{ index = 3; module = 'inmation'; function = 'inmation::server::cache::get' },
        [pscustomobject]@{ index = 4; module = 'inmation'; function = 'inmation::server::access::get_metaevents' })
}

Describe 'TFS pre-verdict' {
    It 'calls a work item with the same frames and exception kind the same bug' {
        $text = "Server crashed: Access violation reading location`ninmation.exe!mongo::BSONObjIterator::BSONObjIterator() Line 42`ninmation.exe!mongo::BSONObj::getField(...)`ninmation.exe!inmation::server::cache::get(...)"
        $v = Get-WorkItemPreVerdict $script:AvDump $text
        Assert-Equal 'same (to confirm)' $v.Verdict
        Assert-Equal 'yes' $v.ExceptionKind
        Assert-True $v.HasStack
    }
    It 'calls a work item with the faulting function and exception kind but no other frames likely the same' {
        $v = Get-WorkItemPreVerdict $script:AvDump 'Access violation in BSONObjIterator::BSONObjIterator while browsing events'
        Assert-Equal 'likely same' $v.Verdict
        Assert-False $v.HasStack
    }
    It 'calls a work item with only the faulting function related' {
        Assert-Equal 'related' (Get-WorkItemPreVerdict $script:AvDump 'BSONObjIterator::BSONObjIterator is slow').Verdict
    }
    It 'does not match a destructor by its class name used as a parameter type' {
        $dump = [pscustomobject]@{ exception = $null; classification = $null; assertion = $null; crashStack = @([pscustomobject]@{ index = 0; module = 'inmation'; function = 'OpcUa::Server::RequestContext::~RequestContext' }) }
        Assert-Equal 'different' (Get-WorkItemPreVerdict $dump 'Service<12>::Call(std::shared_ptr<OpcUa::Server::RequestContext> context)').Verdict
        Assert-Equal 'same (to confirm)' (Get-WorkItemPreVerdict $dump 'inmation.exe!OpcUa::Server::RequestContext::~RequestContext() Line 120').Verdict
    }
    It 'calls a work item that only shares callers related' {
        $v = Get-WorkItemPreVerdict $script:AvDump 'get_metaevents is slow'
        Assert-Equal 'related' $v.Verdict
    }
    It 'does not call a work item with other exception codes the same' {
        $v = Get-WorkItemPreVerdict $script:AvDump 'BSONObjIterator::{ctor} getField getObjectField heap corruption 0xC0000374'
        Assert-Equal 'different' $v.ExceptionKind
        Assert-Equal 'related' $v.Verdict
    }
    It 'returns different without any match' {
        Assert-Equal 'different' (Get-WorkItemPreVerdict $script:AvDump 'UI glitch in the tree view').Verdict
    }
}

Describe 'work item state' {
    It 'maps state and reason to a meaning' {
        Assert-Equal 'fixed' (Get-WorkItemStateMeaning 'Resolved' 'Fixed')
        Assert-Equal 'fixed' (Get-WorkItemStateMeaning 'Closed' 'Verified')
        Assert-Equal 'open' (Get-WorkItemStateMeaning 'Active' 'New')
        Assert-Equal 'duplicate' (Get-WorkItemStateMeaning 'Closed' 'Duplicate')
        Assert-Equal 'closed without fix' (Get-WorkItemStateMeaning 'Closed' 'Obsolete')
    }
}

Describe 'candidate selection' {
    It 'takes the strongest candidate and others with the same first frame terms' {
        $entry = [pscustomobject]@{
            terms      = @(
                [pscustomobject]@{ term = 'a'; kind = 'frame 0'; hits = 3; tooGeneric = $false },
                [pscustomobject]@{ term = 'b'; kind = 'frame 1'; hits = 5; tooGeneric = $false },
                [pscustomobject]@{ term = 'c'; kind = 'frame 2'; hits = 3; tooGeneric = $false })
            candidates = @(
                [pscustomobject]@{ id = 1; matchedTerms = @('a', 'b', 'c') },
                [pscustomobject]@{ id = 2; matchedTerms = @('a', 'b') },
                [pscustomobject]@{ id = 3; matchedTerms = @('a', 'b', 'c') },
                [pscustomobject]@{ id = 4; matchedTerms = @('c') })
        }
        Assert-Equal @(1, 2, 3) (Select-CandidatesToVerify $entry)
    }
    It 'skips candidates that match only broad terms' {
        $entry = [pscustomobject]@{
            terms      = @(
                [pscustomobject]@{ term = 'cache::get'; kind = 'frame 0'; hits = 160; tooGeneric = $false },
                [pscustomobject]@{ term = 'x'; kind = 'frame 1'; hits = 4; tooGeneric = $false },
                [pscustomobject]@{ term = 'y'; kind = 'frame 2'; hits = 4; tooGeneric = $false },
                [pscustomobject]@{ term = 'z'; kind = 'frame 3'; hits = 4; tooGeneric = $false })
            candidates = @(
                [pscustomobject]@{ id = 7; matchedTerms = @('cache::get', 'x') },
                [pscustomobject]@{ id = 8; matchedTerms = @('cache::get') },
                [pscustomobject]@{ id = 9; matchedTerms = @('y') })
        }
        Assert-Equal @(7, 9) (Select-CandidatesToVerify $entry)
    }
}
