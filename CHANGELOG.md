# Changelog

## 1.1.0

### Performance counters (new agent `perf-counter-analyzer`, skill `perf-counter-analysis`)
- `Get-PerfCounters.ps1`: reads the performance counters of one or more objects (by path) from a Windows dump of
  `inmation.exe` in one cdb run - all second, minute, hour and day buckets (sum, num, avg, min, max) from
  `CObject::performance_`, found via `inmation::model::_maps`. `PerfDump.js` (cdb JavaScript) walks the path map with
  raw reads and takes every offset from the PDB types. Output: `perf-data.json` / `.csv`, one PNG chart per object and
  counter (panel per timebase, avg line with min-max band, the bucket that is still filling marked), statistics,
  `perf-report.md`, `perf-summary.md`. Counter names, codes, unique name parts, `*`, and `/object/path:Counter`;
  ambiguous, unknown or misplaced counters and unknown paths come back with candidates. `-ListObjects`, `-PerfJson`
  (re-plot without the debugger).
- `Measure-PerfCorrelation.ps1`: correlation between counters of one or several objects (also from several dumps):
  hinted counters, one against all, or every counter. Pearson of levels and of bucket-to-bucket changes, Spearman,
  lags, p-values; deterministic pre-verdicts (`strong`, `lagged`, `moderate`, `inconsistent`, `trend-only`,
  `same-signal`, `none`); anomalies (spike, step, trend); heat map and pair charts. Uses only the dump and its PDB; no
  source code is read.
- Same symbol gate as the crash analysis: no verified private PDB, no data.

### Crash analysis
- `lib/Symbols.ps1`: the PDB lookup of the collector as a function for other scripts; `Read-MinidumpInfo` reports
  `FullMemory`.
- `Test-AnalyzerSetup.ps1` checks the cdb JavaScript provider.
- The crash agent points to `perf-counter-analyzer` for load and performance questions on manual / hang dumps.

## 1.0.0

First release as a standalone agent plugin (previously `tools/crash-dump-analyzer` and
`.github/agents/crash-dump-analyzer.agent.md` in the inmation server repository).

### Packaging
- Agent plugin layout: `plugin.json`, `agents/`, `skills/crash-dump-analysis/` with scripts and references. Installs
  once per user and works in any workspace.
- Repository-agnostic: the source repository is the workspace (when it has `server/inmation`), `-RepoPath` or
  `CRASH_DUMP_ANALYZER_REPO`; without one, stages 1 and 2 run in no-source mode.
- User config override `%LOCALAPPDATA%\inmation-crash-analysis\config.json` (survives plugin updates).
- `Test-AnalyzerSetup.ps1`: one-line-per-check machine diagnosis.

### For less capable models
- Agent and skill rewritten as short, numbered procedures driven by `KEY=value` script output.
- Stage 1 writes the report and a ready chat summary; deterministic crash classification (null pointer, wild pointer,
  failed assertion, unhandled C++ exception, heap / memory corruption, stack overrun, killed by signal, ...).
- Automatic decoding of unhandled C++ exceptions (thrown type, `std::system_error` code, throw site) on Windows.
- Signature families group the same crash across builds.
- Stage 2 `-Auto`: search, candidate fetch, linked duplicates, pre-verdicts and report section in one command.
- Stage 3 `Get-CodeEvidence.ps1`: build vs. latest code of the crashing functions, commits, linked fixes, backports.
- `Test-CrashReport.ps1`: report linter the model runs until `REPORT_OK`.
- `Complete-CrashReport.ps1`: the model answers open items in a separate answers file (`## <key>` + text); the script
  applies them to the report. No direct report edits, so no stale editor buffers or broken tables.
- `Invoke-DumpQuery.ps1`: read-only cdb/gdb queries with the run's symbols; no hand-built debugger command lines.

### Linux core dumps (OT Data Fabric containers)
- ELF cores (`wsl-crash-*.dmp`, `core.*`, in zips too) analyzed with gdb in WSL into the same summary/report.
- Debug file lookup by GNU build-id on the build shares (indexed), version and exact build commit from the build folder;
  version from process memory when no folder matches.
- Sysroot (executable and libraries) extracted from the product image with docker, cached per build-id.
- Signal analysis: sent from outside vs. raised (si_code, sender PID), glibc abort message (assert text, heap check),
  thrown type of unhandled C++ exceptions.

### Tests
- Dependency-free unit tests (no dumps, debugger or network), fixtures for cdb and gdb output, `Compare-Runs.ps1` for
  corpus regression.
