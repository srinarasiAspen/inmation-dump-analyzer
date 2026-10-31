# Product lines, versions and build folders

Always identify a build by the **file version** of `inmation.exe` / `inmation32.exe` (the collector reads it from the
dump: `Build: file version v...`). The configuration is `scripts/crash-dump-analyzer.config.json`; local overrides go to
`%LOCALAPPDATA%\inmation-crash-analysis\config.json` (merged on top, survives plugin updates).

| Line | File version | Release share | Latest code (analysis ref) |
|---|---|---|---|
| OT Data Fabric ("2.x", "OT DF") | major >= 26 (26.0, 26.1, 27.0 ...); early builds 2.0.x | `\\file2\LatestRelease\OT_DATA_FABRIC` | `origin/main` |
| inmation | 1.x | `\\file2\LatestRelease\RELEASE` | `origin/main-legacy` |

- **Product version** (e.g. 1.3 for OT DF 26.x) is marketing only. Never route by it.
- **User wording**: "2.x", "OT DF", "OT Data Fabric" = file major >= 26; "1.x" or plain "inmation" = file major 1. If the
  user's version contradicts the dump, trust the dump and mention the difference.
- **Dev vs release**: odd minor file version (1.113, 26.1) = dev build (dev build share, cleaned up after a while);
  even minor (1.112, 26.0) = release. Release builds get "is it fixed? which commit? backports?"; dev builds get the
  root cause on the latest code.
- **Branded builds** (AspenTech, PlantWeb installs): same file version, different binary and PDB under
  `BRANDED_RELEASE\<brand>`. The collector picks the folder whose binary GUID matches the dump. Never use the unbranded
  PDB for a branded binary.
- **Symbols**: looked up in the local cache, next to the dump, inside the dump's zip, then the build folders - always
  GUID-verified. If none matches, the dump is BLOCKED; the error lists every folder checked with its binary GUID and
  link time. Same version but linked hours apart and installed under an unknown brand path = branded or hotfix build:
  suggest adding the brand to `brands` in the config. Missing dev folder = cleaned up: ask for the PDB.
- **Build commit**: `build_info.txt` in the build folder (exact) > release tag `v<version>` > version bump commit on the
  version branch > last commit on the version branch before the build time > last commit on the analysis ref before
  the build time (low).
