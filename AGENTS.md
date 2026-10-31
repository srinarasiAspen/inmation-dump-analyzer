# Contributor guide (humans and coding agents)

This repository is an agent plugin: [plugin.json](plugin.json), the agent in [agents/](agents), and the
`crash-dump-analysis` skill with its PowerShell scripts in [skills/crash-dump-analysis/](skills/crash-dump-analysis).
The design goal: **the scripts make every decision that can be made deterministically**, so that less capable models
only run commands, read `KEY=value` lines and confirm a few judgment calls. When a model gets something wrong, prefer
moving the decision into a script (with a test) over adding more prose to the skill.

## Layout

| Path | What |
|---|---|
| `skills/crash-dump-analysis/SKILL.md` | The procedure the model follows. Short numbered steps, tables, exact commands. |
| `skills/crash-dump-analysis/references/` | Decision guides loaded on demand (stage 2 confirm, stage 3 verdict, Lua, Linux, cdb, report format). |
| `skills/crash-dump-analysis/scripts/*.ps1` | Entry scripts (one per stage, plus query, linter, setup check). |
| `skills/crash-dump-analysis/scripts/lib/*.ps1` | Shared modules, dot-sourced. No side effects at load time except `$script:` constants. |
| `tests/` | Unit tests (`*.Tests.ps1`), fixtures, `Compare-Runs.ps1` for corpus regression. |
| `docs/how-it-works.md` | What the scripts do, all config keys. |

## Contracts that must not break

- **Console output keys** read by the skill/agent: `REPORT_PATH`, `SUMMARY_JSON`, `DIGEST_MD`, `CHAT_SUMMARY`,
  `SOURCE_AVAILABLE`, `STAGE2_COMMAND`, `STAGE3_COMMAND`, `BLOCKED_DUMP`, `EXTRACTED_DIR`, `PRE_VERDICT`, `CONFIRM_ITEM`,
  `REPORT_UPDATED`, `TFS_ERROR`, `CODE_EVIDENCE_MD`, `NEXT_STEP`, `REPORT_ISSUE`, `REPORT_OK`, `QUERY_*`, `CHECK`,
  `SETUP_OK`. Renaming one means updating SKILL.md, the agent and the references in the same commit.
- **summary.json schema**: Windows and Linux entries share it (`dump.platform` tells them apart). Stage 2/3 scripts and
  `Compare-Runs.ps1` read it. Add fields; do not rename.
- **Report sections** (`$script:ReportSections` in `lib/Report.ps1`) and the `_analyst: ..._` placeholder convention
  used by `Test-CrashReport.ps1`.
- **Read-only**: scripts never modify a repository (only `git fetch`), never write to TFS (only the WIQL POST), never
  upload anything. `Invoke-DumpQuery.ps1` keeps its block lists for commands that run programs or write files.
- **Symbol gate**: no function names, grouping or build commit for a dump without verified symbols (PDB GUID/age or
  GNU build-id). Never relax it.

## PowerShell rules (Windows PowerShell 5.1, `Set-StrictMode -Version 2.0`)

- Files with non-ASCII characters need a UTF-8 BOM; keep sources ASCII where possible.
- `"$var:"` in strings is a scope qualifier - write `"${var}:"`.
- Do not nest backtick-quoted Markdown inside `$(...)` in double-quoted strings; build pieces with `Format-Code` or
  concatenation.
- `.Count` on a scalar fails under strict mode: wrap in `@()`. `$x = if (...) { @() }` gives `$null` - use
  `$x = @(if (...) { ... })`.
- A function returning `, $array` must not be wrapped in `@()` by the caller (double wrap).
- Avoid automatic/param names as locals: `$id` vs. `[string[]]$Id`, `$home`, `$args`, `$input`, `$matches`.
- Hex literals >= `0x80000000` need the `L` suffix; `Measure-Object -Sum` returns double.
- `ConvertFrom-Json` arrays: pipe through `ForEach-Object { $_ }`; JSON numbers become PSObject-wrapped - cast before
  using them as hashtable keys.
- Ordered dictionaries with int keys index positionally - use `@{}` for numeric keys.
- `[IO.File]` resolves relative paths against the process directory, not the PowerShell location - resolve first.
- Scripts are started with `powershell -File`: `[string[]]` parameters receive one string. Accept comma- or
  `;`-separated values, and use `[CmdletBinding(PositionalBinding = $false)]` so a stray value fails loudly.
- Native commands writing to stderr: set `$ErrorActionPreference = 'Continue'` around the call.

## Tests

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests\Run-Tests.ps1              # all unit tests
powershell -NoProfile -ExecutionPolicy Bypass -File tests\Run-Tests.ps1 -Filter Linux* # one file
```

The framework is in `tests/TestFramework.ps1` (Pester 3.4 on stock Windows is too old). Tests need no dumps, debugger,
share or network. Put debugger output samples in `tests/fixtures/` (anonymize customer data).

Every change to parsing, classification, signatures, pre-verdicts or report rendering needs a unit test. Parse-check
all scripts before committing:

```powershell
Get-ChildItem -Recurse -Filter *.ps1 | ForEach-Object { $e = $null; [void][Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$null, [ref]$e); if ($e) { "$($_.Name): $($e[0].Message)" } }
```

## Corpus regression

Changes to the collector are checked against a local corpus of real dumps (not in git):

```powershell
.\skills\crash-dump-analysis\scripts\Invoke-CrashDumpAnalysis.ps1 -DumpPath D:\corpus -Recurse -SkipFetch -OutDir D:\runs\new -ReportDir D:\runs\new\reports
.\tests\Compare-Runs.ps1 -Baseline D:\runs\old\summary.json -Candidate D:\runs\new\summary.json
```

Every difference must be explained (intended improvement) before committing.

## Evaluating with a weaker model

After changing SKILL.md, the agent or a reference, run the agent with a small model on one Windows dump and one Linux
core and compare its answer with a known-good report: right stage order, `KEY=value` lines used, no invented function
names on blocked dumps, report passes `Test-CrashReport.ps1`. Fix the instruction (or move the decision into a
script) where it went wrong.

## Releases

Update [CHANGELOG.md](CHANGELOG.md) and bump `version` in `plugin.json` (semantic versioning). Installed plugins update
with **Chat: Update Plugins**.
