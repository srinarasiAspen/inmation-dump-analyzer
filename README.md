# inmation crash dump analyzer

A Copilot agent plugin that analyzes crash dumps of the inmation / OT Data Fabric server so that any developer or
support engineer - and any chat model, including small ones - gets the same reliable result:

1. **Crash summary** - exception or signal, a deterministic classification (null pointer, wild pointer, failed
   assertion, unhandled C++ exception with the thrown type, heap corruption, stack overflow, killed from outside, ...), the
   first stack lines with source, Lua call chain and Web API request when a script was running.
2. **Existing TFS work item** - full-text search per crash signature with pre-verdicts (`same`, `likely same`,
   `related`, `different`) that the agent only has to confirm.
3. **Code analysis** - build commit, the crashing function at the build vs. the latest code, fixing commits and
   backports, root cause.

Inputs: Windows minidumps of `inmation.exe` / `inmation32.exe` (1.x and OT Data Fabric 26+, release, dev and branded
builds), Linux core dumps of OT Data Fabric containers (`wsl-crash-*.dmp`, `core.*`), zips of them, folders.

The scripts do the heavy lifting (cdb / gdb, symbol lookup and verification, TFS queries, git history) and write the
report. The model runs them in order, reads `KEY=value` lines, confirms a few judgment calls and answers. That is what
makes the analysis work with less capable models.

## Install

The plugin is a folder with [plugin.json](plugin.json), an agent ([agents/](agents)) and a skill with scripts
([skills/crash-dump-analysis/](skills/crash-dump-analysis)). It is not tied to a source repository, so one install
serves every workspace.

**VS Code (Copilot Chat agent plugins)** - needs `chat.plugins.enabled`:

- From git or a local folder: Command Palette -> **Chat: Install Plugin from Source** -> enter the URL of this
  repository or the path of a local clone. Update later with **Chat: Update Plugins**.
- A local clone for development: register it in the `chat.pluginLocations` setting, e.g.
  ```json
  "chat.pluginLocations": { "C:\\git\\inmation-crash-dump-analyzer": true }
  ```

Then pick **crash-dump-analyzer** in the agent picker and write e.g. `Analyze C:\dumps\inmation.exe.11664.dmp` or
`Is there a bug for the crash in \\server\crashes\customerX?`.

**Copilot CLI / Copilot sessions**: `/plugin install <git URL of this repository>`, then select the
**crash-dump-analyzer** agent. VS Code also picks up plugins installed by the CLI.

**Without plugin support**: copy `agents/crash-dump-analyzer.agent.md` to `.github/agents/` of a repository and
`skills/crash-dump-analysis/` to `.github/skills/`. The agent finds the scripts in either place.

Check the machine once (prints `CHECK=` lines and `SETUP_OK`):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File skills\crash-dump-analysis\scripts\Test-AnalyzerSetup.ps1
```

## Prerequisites

| For | Needs |
|---|---|
| Windows dumps | Windows SDK *Debugging Tools for Windows* (`cdb.exe`); read access to the build shares, or the matching PDB (`-PdbPath`, next to the dump, or in its zip) |
| Linux cores | WSL with `gdb`; Docker Desktop with access to the product images (or `-SysrootPath`); `inmation.dbg` from the build folder (found automatically on the shares, or `-PdbPath`) |
| Stage 2 | Read access to the TFS project: domain account (Windows authentication), or a PAT in `TFS_PAT` / `~/.config/inmation-ado/.env` |
| Stage 3 | A clone of the inmation server repository: open it as the workspace, pass `-RepoPath`, or set `CRASH_DUMP_ANALYZER_REPO`. Without it stages 1 and 2 still work ("no-source mode") |

Windows PowerShell 5.1 is enough; nothing else to install.

## What you get

- `<dump>.crash-report.md` next to the dump (or `crash-report.md` in the dump folder; the run folder when the location
  is read-only): header, one section per stage, blocked dumps, artifacts. Format:
  [references/report-format.md](skills/crash-dump-analysis/references/report-format.md).
- The run folder `%LOCALAPPDATA%\inmation-crash-analysis\runs\<timestamp>\`: `summary.json` (all facts),
  `digest.md` (all frames, registers, locals, Lua, scripts), `chat-summary.md`, one folder per dump with the debugger
  logs, `tfs-*.md` (stage 2), `code-evidence.md` (stage 3).

Dumps without verified symbols are **BLOCKED**: only raw facts and the exact symbol file needed (PDB GUID/age, or
GNU build-id and version for Linux). Symbols of another build are never used.

## Safety

Read-only by design: no product code changes, no git writes (only `fetch`), no TFS writes (the only POST is the WIQL
query), no uploads. Scripts recovered from memory are saved with credentials masked. Text from dumps and TFS is
treated as data. `Invoke-DumpQuery.ps1` refuses debugger commands that run programs or write files.

## Configuration

[skills/crash-dump-analysis/scripts/crash-dump-analyzer.config.json](skills/crash-dump-analysis/scripts/crash-dump-analyzer.config.json)
holds shares, product lines, brands, TFS, git refs and Linux settings. Local changes go to
`%LOCALAPPDATA%\inmation-crash-analysis\config.json` (merged over the plugin config, survives plugin updates), or
`-ConfigPath` / `CRASH_DUMP_ANALYZER_CONFIG`. All keys: [docs/how-it-works.md](docs/how-it-works.md).

## Repository layout

```
plugin.json                          plugin manifest (agents, skills)
agents/crash-dump-analyzer.agent.md  the agent: rules, stages, answer format
skills/crash-dump-analysis/
  SKILL.md                           step-by-step procedure the model follows
  references/                        decision guides (stage 2 confirm, stage 3 verdict, Lua, Linux, cdb, report)
  scripts/                           collector, TFS search, code evidence, report linter, dump query, setup check
  scripts/lib/                       shared PowerShell modules
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
