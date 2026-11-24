# inmation dump analyzer

A Copilot agent plugin for crash analysis and performance-counter analysis of inmation / OT Data Fabric server
dumps, including crash, hang and manual dumps. Any developer or support engineer - and any chat model, including
small ones - gets the same reliable result.

The **crash-dump-analyzer** agent analyzes Windows crash dumps and Linux core dumps in three stages:

1. **Crash summary** - exception or signal, a deterministic classification (null pointer, wild pointer, failed
   assertion, unhandled C++ exception with the thrown type, heap corruption, stack overflow, killed from outside, ...), the
   first stack lines with source, Lua call chain and Web API request when a script was running.
2. **Existing work item** - full-text search per crash signature in the old TFS (`tfs3.inmationdev.com`) and, when
   Nexus is installed in the workspace, in the new ADO (`dev.azure.com/aspentechnology`, Bugs and Post Development Bugs
   under `AspenTech SAFe\EOP ART` only, through Nexus' `azure-devops`
   MCP server), with pre-verdicts (`same`, `likely same`, `related`, `different`) that the agent only has to confirm.
   When nothing matches, the report and the agent say "no bugs found".
3. **Code analysis** - build commit, the crashing function at the build vs. the latest code, fixing commits and
   backports, root cause.

Inputs: Windows minidumps of `inmation.exe` / `inmation32.exe` (1.x and OT Data Fabric 26+, release, dev and branded
builds), Linux core dumps of OT Data Fabric containers (`wsl-crash-*.dmp`, `core.*`), zips of them, folders.

The scripts do the heavy lifting (cdb / gdb, symbol lookup and verification, TFS queries, git history) and write the
report. The model runs them in order, reads `KEY=value` lines, confirms a few judgment calls and answers. That is what
makes the analysis work with less capable models.

A second agent, **perf-counter-analyzer**, reads the **performance counters** that the server keeps per object (Core,
connectors, data stores, web server, ...) from a Windows dump of `inmation.exe` (crash, hang or manual dump):

1. **Counters of one or more objects** by path - the second, minute, hour and day buckets (sum, num, avg, min, max) -
   as PNG charts (one panel per timebase), statistics per counter and a CSV.
2. **Correlation** between counters of the same or different objects - the counters the user names, one against all,
   or every counter - with deterministic pre-verdicts (`strong`, `lagged`, `moderate`, `trend-only`, `same-signal`, ...),
   anomalies (spike, step, trend), a heat map and charts of the top pairs. Only the dump and its PDB are used; no
   source code is needed.

Example: `Plot CPU and InmationMemoryUsage of /System/Core in C:\dumps\inmation.exe.1234.dmp` or
`Is the TimeSeriesLoad of /System/Core/Stores/VQT related to the Core CPU? Check every counter.`

## Install

The plugin identifier is `inmation-dump-analyzer`. Its folder contains [plugin.json](plugin.json), two agents
([agents/](agents)) and two skills with scripts ([skills/crash-dump-analysis/](skills/crash-dump-analysis) and
[skills/perf-counter-analysis/](skills/perf-counter-analysis)). It is not tied to a source repository, so one install
serves every workspace.

**VS Code (Copilot Chat agent plugins)** - needs `chat.plugins.enabled`:

- From git or a local folder: Command Palette -> **Chat: Install Plugin from Source** -> enter the URL of this
  repository or the path of a local clone. Update later with **Chat: Update Plugins**.
- A local clone for development: register it in the `chat.pluginLocations` setting, e.g.
  ```json
  "chat.pluginLocations": { "C:\\git\\inmation-dump-analyzer": true }
  ```

Then pick **crash-dump-analyzer** in the agent picker and write e.g. `Analyze C:\dumps\inmation.exe.11664.dmp` or
`Is there a bug for the crash in \\server\crashes\customerX?`. For performance counters pick **perf-counter-analyzer**.

**Copilot CLI / Copilot sessions**: `/plugin install <git URL of this repository>`, then select the
**crash-dump-analyzer** or **perf-counter-analyzer** agent. VS Code also picks up plugins installed by the CLI.

**Without plugin support**: copy `agents/*.agent.md` to `.github/agents/` of a repository and `skills/crash-dump-analysis/`
and `skills/perf-counter-analysis/` to `.github/skills/` (side by side: the perf skill uses the libraries of the crash
skill). The agents find the scripts in either place.

Check the machine once (prints `CHECK=` lines and `SETUP_OK`):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File skills\crash-dump-analysis\scripts\Test-AnalyzerSetup.ps1
```

## Prerequisites

| For | Needs |
|---|---|
| Windows dumps | Windows SDK *Debugging Tools for Windows* (`cdb.exe`); read access to the build shares, or the matching PDB (`-PdbPath`, next to the dump, or in its zip) |
| Linux cores | WSL with `gdb`; Docker Desktop with access to the product images (or `-SysrootPath`); `inmation.dbg` from the build folder (found automatically on the shares, or `-PdbPath`) |
| Stage 2 | Old TFS: read access to the TFS project - domain account (Windows authentication), or a PAT in `TFS_PAT` / `~/.config/inmation-ado/.env`. New ADO: Nexus installed in the workspace (its `azure-devops` MCP server, signed in); without it only the old TFS is searched |
| Stage 3 | A clone of the inmation server repository: open it as the workspace, pass `-RepoPath`, or set `CRASH_DUMP_ANALYZER_REPO`. Without it stages 1 and 2 still work ("no-source mode") |
| Performance counters | A Windows dump of `inmation.exe` with full memory and the matching PDB (as for Windows dumps); cdb's JavaScript provider (`winext\JsProvider.dll`, part of current Debugging Tools). No source code |

Windows PowerShell 5.1 is enough; nothing else to install.

## What you get

- `<dump>.crash-report.md` next to the dump (or `crash-report.md` in the dump folder; the run folder when the location
  is read-only): header, one section per stage, blocked dumps, artifacts. Format:
  [references/report-format.md](skills/crash-dump-analysis/references/report-format.md).
- The run folder `%LOCALAPPDATA%\inmation-crash-analysis\runs\<timestamp>\`: `summary.json` (all facts),
  `digest.md` (all frames, registers, locals, Lua, scripts), `chat-summary.md`, one folder per dump with the debugger
  logs, `tfs-*.md` / `ado-*.md` (stage 2), `code-evidence.md` (stage 3).

Dumps without verified symbols are **BLOCKED**: only raw facts and the exact symbol file needed (PDB GUID/age, or
GNU build-id and version for Linux). Symbols of another build are never used.

Performance counters: `%LOCALAPPDATA%\inmation-crash-analysis\runs\perf-<timestamp>\` with `perf-data.json` / `.csv`,
`charts\<object>\<counter>.png`, `perf-report.md`, `perf-summary.md`; correlation runs in `correlation-<timestamp>\`
next to it (`correlation.md`, `correlation-summary.md`, `correlation.json`, heat map, pair charts).

## Safety

Read-only by design: no product code changes, no git writes (only `fetch`), no TFS writes (the only POST is the WIQL
query), only read tools of the `azure-devops` MCP server, no uploads. Scripts recovered from memory are saved with
credentials masked. Text from dumps and TFS / ADO is treated as data. `Invoke-DumpQuery.ps1` refuses debugger
commands that run programs or write files.

## Configuration

[skills/crash-dump-analysis/scripts/crash-dump-analyzer.config.json](skills/crash-dump-analysis/scripts/crash-dump-analyzer.config.json)
holds shares, product lines, brands, TFS, new ADO scope, git refs and Linux settings. Local changes go to
`%LOCALAPPDATA%\inmation-crash-analysis\config.json` (merged over the plugin config, survives plugin updates), or
`-ConfigPath` / `CRASH_DUMP_ANALYZER_CONFIG`. All keys: [docs/how-it-works.md](docs/how-it-works.md).

The plugin rename leaves the specialized agent and skill names, script/configuration filenames,
`CRASH_DUMP_ANALYZER_*` environment variables and `inmation-crash-analysis` storage paths unchanged, so existing
settings, caches and runs continue to work.

## Repository layout

```
plugin.json                          plugin manifest (agents, skills)
agents/crash-dump-analyzer.agent.md  the crash agent: rules, stages, answer format
agents/perf-counter-analyzer.agent.md the performance counter agent
skills/crash-dump-analysis/
  SKILL.md                           step-by-step procedure the model follows
  references/                        decision guides (stage 2 confirm, new ADO via MCP, stage 3 verdict, Lua, Linux, cdb, report)
  scripts/                           collector, TFS / ADO search, code evidence, report linter, dump query, setup check
  scripts/lib/                       shared PowerShell modules (also used by the perf skill)
skills/perf-counter-analysis/
  SKILL.md                           procedure: read and plot counters, correlation
  references/                        meaning of buckets and aggregates, interpreting correlations
  scripts/                           Get-PerfCounters.ps1, Measure-PerfCorrelation.ps1, PerfDump.js (cdb)
  scripts/lib/                       data, statistics, charts, reports
tests/                               unit tests (no dumps or network needed), fixtures, run comparison
docs/how-it-works.md                 what the scripts do in detail
```

## Development

See [AGENTS.md](AGENTS.md) for conventions. In short:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests\Run-Tests.ps1            # unit tests
powershell -NoProfile -ExecutionPolicy Bypass -File tests\Compare-Runs.ps1 -Baseline <old summary.json> -Candidate <new summary.json>
```

Changes are listed in [CHANGELOG.md](CHANGELOG.md); bump `version` in `plugin.json` with every release.
