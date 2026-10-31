# How the scripts work

Reference for maintainers and for anyone who wants to run the scripts without the agent. The agent and skill use only
the `KEY=value` lines the scripts print; this document explains what is behind them.

`<scripts>` = [skills/crash-dump-analysis/scripts](../skills/crash-dump-analysis/scripts).

| Script | Stage | Purpose |
|---|---|---|
| `Invoke-CrashDumpAnalysis.ps1` | 1 | Collector: Windows minidumps (cdb) and Linux cores (gdb in WSL) -> `summary.json`, `digest.md`, report, chat summary |
| `Search-TfsCrashBugs.ps1` | 2 | TFS full-text search per signature; `-Auto` fetches candidates, pre-verdicts them and fills report section 2 |
| `Get-CodeEvidence.ps1` | 3 | Build commit, faulting function at build vs. latest code, commits and linked fixes -> `code-evidence.md`, report sections 3-5 with placeholders |
| `Test-CrashReport.ps1` | 2, 3 | Report linter: `REPORT_ISSUE=` per unfinished part, `REPORT_OK` when done |
| `Invoke-DumpQuery.ps1` | any | Read-only cdb/gdb queries against a dump of a run with the run's verified symbols |
| `Test-AnalyzerSetup.ps1` | - | Machine check: cdb, config, folders, source repository, shares, TFS, WSL/gdb, docker |

## Product lines and build types

Stage 3 depends on the product line and the build type. All of it is decided from the binary's **file version**:

| Line | File version | Release share | Latest code |
|---|---|---|---|
| OT Data Fabric ("2.x", "OT DF") | major >= 26 | `\\file2\LatestRelease\OT_DATA_FABRIC` | `origin/main` |
| inmation | 1.x | `\\file2\LatestRelease\RELEASE` | `origin/main-legacy` |

OT Data Fabric binaries also carry a product version such as 1.3. It is informational only and never used for routing.

Branded builds (for example AspenTech or PlantWeb installations) have the same file version as the unbranded build but are separate binaries with their own PDBs under `\\file2\LatestRelease\BRANDED_RELEASE\<brand>`. The script compares the PDB GUID of the binary in every candidate folder with the dump and uses the folder that holds the crashed binary.

- **Release builds** (even minor file version, e.g. 1.112, 26.0): the agent checks whether the defect still exists on the line's latest code, then reports the fixing commit (including backports) or the root cause.
- **Dev builds** (odd minor file version, e.g. 1.113, 26.1): the agent goes straight to root-cause analysis on the line's latest code. If `build_info.txt` names a source branch outside it, the agent uses that branch's head instead.

The collector writes `<dump>.crash-report.md` next to the dump. For a folder it writes `crash-report.md` in that folder; if the location is read-only, the report goes to the run folder instead. Stage 1 creates the report; stages 2 and 3 fill in their sections.

## Prerequisites

- Windows with *Debugging Tools for Windows* (`cdb.exe`, part of the Windows SDK).
- Read access to the release shares and the dev build share (see `productLines`), or the matching PDB (next to the dump, inside its zip, or `-PdbPath`).
- Stage 2: read access to the TFS project in the config's `tfs` section - a domain account (Windows integrated authentication) or a PAT in `TFS_PAT` / `SOURCE_ADO_PAT` or `~/.config/inmation-ado/.env`.
- Stage 3: a clone of the inmation server repository with the `origin` remote; the script runs `git fetch` unless `-SkipFetch` is passed. Without a clone (for example a support engineer's machine with only this plugin), the collector runs in **no-source mode**: the crash data is complete, but the build commit is only taken from `build_info.txt` (not verified), and source lines, file history and vcpkg port details are skipped. It prints `SOURCE_AVAILABLE=false` and the digest says "Source: not available". `-NoSource` forces this mode.

## Running the collector directly

```powershell
.\skills\crash-dump-analysis\scripts\Invoke-CrashDumpAnalysis.ps1 -DumpPath <file-or-folder-or-zip> [-Recurse] [-PdbPath <pdb>] [-SkipFetch] [-NoSource] [-OutDir <dir>] [-ConfigPath <json>]
```

Zip archives (as `-DumpPath` or inside the folder) are extracted to `extractRoot` (about 1 GB per full dump; the free space is checked first). Extracted dumps are reused by later runs; the script prints their folders as `EXTRACTED_DIR=` - delete them when the analysis is done. A zip entry that is byte-identical to a dump already in the input (same size, then same SHA-256 of the entry stream) is not extracted, wherever that dump lies. `.pdb` entries of the input zips (a dump zip that also carries `inmation.pdb`, or a symbol-only zip in the input folder) are used as symbols, see step 3; they are listed in the digest and as `bundledSymbols` in `summary.json`. Archives with neither `.dmp` nor `.pdb` entries are listed and ignored.

Byte-identical dumps (a raw dump and its zip, or the same dump in two archives) are analyzed **once**. The digest counts unique dumps and lists the other files in the "Copies" column (`dump.copies` and `duplicates` in `summary.json`). Each dump gets its own output folder even if two different dumps share a file name.

For each dump, the script:

1. Reads the crashing binary's file version (and, for information, its product version), PDB GUID/age and link time from the dump's module list, and the process start time (uptime at the crash).
2. Picks the product line by the file major version. Then it collects the candidate build folders `v<version>`: the unbranded folder (odd minor versions are dev builds and are looked up on the line's `devRoots` first; even minor versions on its `releaseRoots` first; the other share is the fallback; folder-name suffixes such as `_keep_for_qa` are accepted) and the same version on every branded root (`brandedReleaseRoots` / `brandedDevRoots` per brand). For each folder it reads the PDB GUID of the binary in `binaryFolder` and marks the folder as match, mismatch or unknown. Brands whose path hints occur in the binary's install path are tried first.
3. Finds the PDB, checking the GUID against the dump at each step. It looks in the local cache first, then next to the dump (or its zip), then inside the input zip archives (the dump's own zip first, then the other zips of the input; a bundled PDB with a different GUID is skipped), then in `<build folder>\symbols\symbols.zip` of the matching folders, and caches the result. Folders whose binary is a different build are skipped without extracting their symbols. If nothing matches, the error lists every folder with its binary GUID and link time.
   **Symbol gate:** a dump whose PDB is not GUID-verified, or that cdb does not load as `private pdb symbols`, is marked **BLOCKED** (digest banner, `BLOCKED_DUMP=` console line, `blocked` in `summary.json`). It keeps only raw facts: exception record, registers, disassembly and a raw stack of `module+RVA` addresses. Its signature is `[unverified symbols] <code> at <module+RVA> (v<version>, PDB <guid>)`, so it is never grouped with symbolized crashes. It gets no build commit (a low-confidence candidate is kept only as `build.rejectedCommit`), no source mapping, and no Lua decoding. Other dumps in the same run are analyzed normally.
4. Runs `cdb`: `!analyze -v`, the exception record and context, the crashing stack with source lines, disassembly around the faulting instruction, locals (`dv` for frames 0-5, plus `dx -r2` for frame 0), and all thread stacks. Fail-fast exceptions (`0xC0000409`) are labeled by subcode (subcode 7 = `abort()`, 2 = `/GS` stack cookie). Assertion and abort frames (`abort`, `_wassert`, `_bson_assert_failed_on_line`, `std::terminate`, ...) are detected and their expression, file and line are read from the locals. The crash signature skips such reporting frames, the MSVC C++ exception-dispatch frames and bare addresses below frame 0 (wrong unwinds), and starts with the asserted expression. If no application frame is left (typical for `std::terminate` in a minidump without KERNELBASE/ntdll), the signature ends with `[no application frame unwound]` and the digest points to the agent's recipe for decoding the thrown C++ exception and its throw site.
5. Determines the build commit. It tries, in order:
   - `build_info.txt` in the build folder (exact commit and source branch; dev builds and newer releases have it);
   - a `v<version>` tag;
   - a `make v<major>.<minor>.<revision>` commit on the version branch (for example `origin/release/v1.94`);
   - the last commit on that branch before the `Build time (UTC)` in the manifest.
6. Maps the stack frames to repository files and shows the source lines at the build commit. It also lists the commits on the analysis ref that touch those files and are not contained in the build commit. The analysis ref is the line's `compareRef`; for a dev build from a branch outside it, it is that branch's head.
7. Maps third-party frames (`...\vcpkg\buildtrees\<port>\src\<version>-<hash>.clean\...`) to their vcpkg port: version in the build path, port version and active patches at the build commit and on the analysis ref (overlay folders first, else the port of the pinned `vcpkg` submodule commit), and the matching local source under `vcpkg\buildtrees` if present.
8. If Lua frames or a configured script entry frame (`scriptContextFrames`) are on the stack, runs a second cdb pass from a command file (`context.cdb.txt`). It walks the Lua `CallInfo` chain (chunk name, current line, line defined, C functions; the structure layout is chosen from the `lua` port version: 5.3, 5.4 or 5.5) and extracts the script string of the entry frame. For Web API / SCI scripts it lists the bundled modules, the request (method, endpoint, remote address, referer, user agent) and the decoded payload. The saved script has `Authorization`/`Cookie` headers and token fields masked. This entry script is only the Web API / SCI wrapper.
9. For Lua frames in libraries stored in the model (chunk `@<object path>#<library>`), it runs a third cdb pass (`lua-proto.cdb.txt`). That pass reads each function prototype: upvalue names, local variable names and string constants. It then searches process memory for the least common distinctive names (`lua-search.log`; names with more than `maxTokenHits` hits are skipped) and dumps memory around the hits (`lua-window.log`). It keeps the NUL-terminated text only if the prototype's `linedefined` line starts a function, its `lastlinedefined` line holds the `end`, and most of its constants occur in between. A validated library is saved as `library-<name>.lua` with credentials masked and line numbers preserved. The digest then shows the current line of every library frame and the code around it.

Output goes to `%LOCALAPPDATA%\inmation-crash-analysis\runs\<timestamp>\`:
`digest.md` (compact, grouped by crash signature), `summary.json` (all data), and one folder per dump with
`cdb.log`, `analyze.txt`, `locals.txt`, `frame0-locals-dx.txt` and `threads.txt`. When the context pass ran, the folder also has `context.cdb.txt`, `context.log` and `script-frame<N>.lua`. When library recovery ran, it has `lua-*.cdb.txt`, `lua-*.log` and `library-<name>.lua`. The digest groups dumps by signature and, for groups with several dumps, compares crash time, uptime, innermost Lua frame, request and payload per dump.

## Searching TFS for an existing bug (stage 2)

```powershell
# Search: terms per crash signature from a collector run
.\skills\crash-dump-analysis\scripts\Search-TfsCrashBugs.ps1 -SummaryJson <run>\summary.json [-Signature <text>] [-Term <extra>, ...] [-Top 15]
# Verify candidates: full work item text, links (commits, pull requests) and a match-evidence table
.\skills\crash-dump-analysis\scripts\Search-TfsCrashBugs.ps1 -Id 30584,16939 -SummaryJson <run>\summary.json
# Without a collector run
.\skills\crash-dump-analysis\scripts\Search-TfsCrashBugs.ps1 -Term process_vqt_writes, OnOxRegularRequest
```

Read-only: the only POST is the WIQL query endpoint; nothing is created or changed. For every signature with verified symbols the script takes the identifiers of the asserted expression and the function names of the first meaningful frames (reporting frames such as `abort`, MSVC C++ exception-dispatch frames such as `__CxxFrameHandler4` / `FindHandler`, the Lua VM, OS and `std::` frames are skipped; short generic method names are qualified with their class) and runs one full-text query per term over the configured title and text fields. Candidates are ranked by matched terms - earlier frames and rarer terms weigh more; terms with more than `maxHitsPerTerm` hits are reported as too generic and not scored. A signature without any distinctive frame (e.g. `std::terminate` in a minidump whose unwind stopped in the exception dispatch) is not searched and printed as `NO_DISTINCTIVE_TERMS=<signature>`; rerun it with `-Signature` and `-Term`. `-Id` and `-Term` accept a comma-separated list, also when the script is started with `powershell -File` (which passes `-Id 1,2` as one string). Results go to `tfs-search.md` / `tfs-search.json` next to `summary.json`; `-Id` writes `tfs-<id>.md`. A ranking is only a pointer: the agent reads the candidates and decides same / likely same / related / different.

Authentication uses a PAT from `SOURCE_ADO_PAT` / `TFS_PAT` or `~/.config/inmation-ado/.env` (the same as the `inmation-ado-*` skills), otherwise the Windows account of the current user. Errors are printed as `TFS_ERROR=<message>` with exit code 2; credentials are never printed.

## Configuration (`crash-dump-analyzer.config.json`)

Override the location with `-ConfigPath` or the `CRASH_DUMP_ANALYZER_CONFIG` environment variable.

| Key | Meaning |
|---|---|
| `productLines` | List of product lines. The first entry whose `minMajor`/`maxMajor` range contains the file major version wins; an entry without a range matches everything, so put it last. Each line has `name`, `releaseRoots` (one folder per released version), `devRoots` (one folder per dev build), `brandedReleaseRoots` / `brandedDevRoots` (same, with a `{brand}` placeholder) and `compareRef` (latest code of the line). |
| `brands` | Brands to search on the branded roots: `name` (replaces `{brand}`) and `pathHints` (substrings of the install path, e.g. `AspenTech`, that make this brand the first candidate). |
| `devBuildRule` | `oddMinor`: an odd minor file version marks a dev build. Any other value treats all builds as release builds. |
| `versionFolderPattern` | Folder name per version; placeholders `{version}`, `{major}`, `{minor}`, `{revision}`, `{build}`. |
| `symbolArchive` | Path of the symbol zip inside the version folder. A loose PDB next to it is used if the zip is missing. |
| `binaryFolder` | Folder with the released binaries (passed to cdb as image path). |
| `manifestPattern` | Release manifest that contains `Build time (UTC)`. |
| `buildInfoFile` | File with `Source Branch:` and `Commit ID:` of the build (exact build commit). |
| `binaries` | Supported executables and the PDB name for each. |
| `localSymbolCache`, `workRoot` | Local PDB cache (keyed by PDB GUID) and run output folder. |
| `extractRoot` | Folder for dumps extracted from zip archives (reused across runs). |
| `vcpkgPortRoots`, `vcpkgSubmodule` | Overlay port folders searched for third-party frames, and the vcpkg submodule used when a port is not an overlay. |
| `localBuildtrees` | Local vcpkg buildtrees with extracted library sources; empty = `<repo>\vcpkg\buildtrees`. |
| `scriptContextFrames` | Frames whose `std::string` local holds a script to extract: `function` (exact frame function), `variable`, `kind` (label). |
| `maxScriptBytes` | Upper limit for an extracted script. |
| `luaLibraryRecovery` | Recovery of model library text from memory: `enabled`, `maxTokens` (names searched per library), `maxTokenHits` (names with more hits are not distinctive and are skipped), `maxHits` (memory windows dumped per library), `windowBytes` (bytes read on each side of a hit; libraries larger than 2 x `windowBytes` are not recovered). |
| `debuggerPath` | Explicit `cdb.exe`; empty = auto-detect. |
| `useMicrosoftSymbolServer` | Also load Windows symbols from msdl.microsoft.com (off by default). |
| `buildSourceRoots` | Source root of the build machine as recorded in the PDB (stripped to get repo paths). |
| `git.compareRef` | Fallback compare ref for a product line without `compareRef`. |
| `git.tagPatterns` | Release tags that mark the exact build source (highest confidence). |
| `git.branchPatterns` | Candidates for the version branch of a build. |
| `git.versionCommitMessage` | Message of a version-bump commit that marks the exact build source. |
| `tfs` | Stage 2 search: `url` (collection URL), `project`, `apiVersion`, `workItemTypes`, `titleFields` (substring match), `textFields` (full-text match), `maxFrameTerms` (frame functions per signature), `maxHitsPerTerm` (more hits = too generic), `top` (candidates listed per signature). |

## Limitations

- Older release folders have no `build_info.txt`, and not every release is tagged, so their build commit is often estimated. The agent checks it against the PDB source lines.
- Dev build folders are removed from the dev share after a while. For older dev dumps, pass the PDB with `-PdbPath`, place it next to the dump, or put it into the dump's zip.
- For 32-bit processes dumped by a 64-bit tool, the script switches cdb to the WOW64 view (`!sw`). Stacks can still be less complete than with a native 32-bit dump.
- Windows DLL frames are shown without symbols unless `useMicrosoftSymbolServer` is enabled. Expect `WRONG_SYMBOLS` buckets in `!analyze`.
- The Lua call chain needs the `L` parameter of a frame next to the Lua VM; in heavily optimized frames it can be unavailable. The Lua 5.4/5.5 decoding (OT Data Fabric) follows the upstream structure layout but has not yet been verified on an OT Data Fabric dump.
- Libraries stored in the model (chunk names such as `@/System/...#Library`) are not in the repository. The script recovers their text from process memory when a distinctive name from the function prototype finds a copy that validates against the prototype's lines. Stripped bytecode (no names), libraries larger than 2 x `windowBytes`, or text no longer in memory are reported as "not recovered"; the agent then searches manually.

## Linux core dumps

ELF cores in the input (`wsl-crash-*.dmp`, `core`, `core.<pid>`, `*.core`, also in zips) are analyzed with gdb in WSL;
the result has the same schema in `summary.json` (`dump.platform = linux`), so grouping, report, stage 2 and stage 3 are
shared. Details, prerequisites and the meaning of signals:
[skills/crash-dump-analysis/references/linux-cores.md](../skills/crash-dump-analysis/references/linux-cores.md).

- Symbols: `inmation.dbg` (separate DWARF debug file) matched by GNU build-id; build folders are indexed once in
  `%LOCALAPPDATA%\inmation-crash-analysis\symbols\linux\build-folders.json`. The build folder gives the version and
  `build_info.txt`. Without a matching folder the version is read from the process memory.
- Sysroot: the executable and shared libraries of the product image (`linux.images`, pulled with docker and extracted
  into the WSL file system, cached per build-id) or `-SysrootPath`. Without them gdb cannot unwind: cores carry no
  code pages.
- Signal facts from the core notes: `si_code` <= 0 with a sender PID other than the process itself = signal sent from
  outside (`killed-by-signal`), the glibc abort message (`__abort_msg`) for assertions and heap checks, the throwing
  frames of an unhandled C++ exception (exact on Linux).

## Stage 2 auto mode

`Search-TfsCrashBugs.ps1 -SummaryJson <summary.json> -Auto` runs the search, then for each signature fetches the
strongest candidates (`Select-CandidatesToVerify`) and the items linked to them as duplicates/related, writes
`tfs-<id>.md` with the full text and a match-evidence table, and computes a pre-verdict (`same (to confirm)`,
`likely same`, `related`, `different`) from the frames, exception kind and own-caller match. It fills report section 2
and prints `PRE_VERDICT=`, `CONFIRM_ITEM=<file>` (to be confirmed by the agent) and `REPORT_UPDATED=`.

## Stage 3 evidence pack

`Get-CodeEvidence.ps1 -SummaryJson <summary.json>` writes `code-evidence.md`: build commit and confidence, the faulting
functions at the build commit and on the analysis ref (with a diff and status: unchanged / changed / removed),
`git log -L` commits in between, fixes linked from TFS (incl. PR merge commits), the branches and tags that contain
them (backports/cherry-picks), and the fix diff for the crashing files. Sections 3-5 of the report get the facts and
`_analyst: ..._` placeholders that the agent replaces; `Test-CrashReport.ps1` finds leftovers.

## Configuration additions

| Key | Meaning |
|---|---|
| `sourceRepo.markers` | Paths that identify a clone of the server repository (default `server/inmation`); used to accept the workspace / `-RepoPath` / `CRASH_DUMP_ANALYZER_REPO` as source. |
| `linux.wslDistribution` | WSL distribution with gdb (empty = default). |
| `linux.executables` | Paths of the product executable inside the container. |
| `linux.debugFile` | Path of the debug file inside a build folder (`{arch}` = `amd64` / `arm64`). |
| `linux.images` | Product images per version (`{version}`), used for the sysroot. |
| `linux.maxFoldersScanned` | Upper limit of build folders read per run when looking for a build-id. |

User overrides: `%LOCALAPPDATA%\inmation-crash-analysis\config.json` is merged over the plugin's config (only the keys it
contains), so an update of the plugin keeps local settings.
