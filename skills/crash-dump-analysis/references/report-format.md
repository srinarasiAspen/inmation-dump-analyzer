# Report format

The collector writes the report (`REPORT_PATH=`): next to the dump (`<dump>.crash-report.md`), or `crash-report.md` in
the dump folder, or the run folder if that is read-only. An existing report is never overwritten (a timestamp is
added). Stages 2 and 3 replace their own sections in the same file. You only edit what the steps tell you to.

```markdown
# Crash analysis: <short title>
| | |
|---|---|
| Dumps | unique dumps; per dump: file (zip), crash time, uptime, PID, identical copies |
| Binary | file version, product line, dev/release build, brand, build time |
| Symbols | PDB GUID verified, load status, source; blocked dumps: "not verified - see Blocked dumps" |
| Stages done | 1 crash summary[, 2 TFS search][, 3 code analysis] |
| Existing work item | A: #<id> <title> (<same/likely same>, <state>/<reason>) / A: none found |
| Build commit | <sha10> (<confidence>, <method>; consistent with the PDB source line) |
| Compared against | <analysis ref> @ <sha10> |
| Verdict | Release: Fixed in <sha10> / Fixed - related risk remains / Still present / Inconclusive. Dev: Root cause identified / Hypothesis (<confidence>). Blocked: pending PDB |

## 1. Crashing call stack        (stage 1, script)
## 2. Existing TFS work items    (stage 2, script + your confirmation)
## 3. Does the problem still exist?   (stage 3, script facts + your verdict)
## 4. Fixing commit              (stage 3, release builds; "n/a - dev build" for dev builds)
## 5. Root cause                 (stage 3, your analysis)
## Blocked dumps                 (only if any)
## Artifacts
```

Editing rules:
- Keep the section headings exactly as they are (`## 2. Existing TFS work items` ...). Scripts find sections by them.
- Header rows: change only the value cell (`| Verdict | <value> |`), one line per row; use `<br>` for line breaks.
- Signatures are called A, B, C in every section and in the chat.
- Replace each `_analyst: ..._` placeholder with your text (no underscores around it).
- Mark hypotheses as such and give a confidence; facts get a source (dump, PDB line, git commit, work item).
- Run `Test-CrashReport.ps1 -ReportPath <report>` at the end of stages 2 and 3 until it prints `REPORT_OK`.
