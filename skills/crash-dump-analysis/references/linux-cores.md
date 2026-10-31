# Linux core dumps (OT Data Fabric containers)

The collector `Invoke-CrashDumpAnalysis.ps1` handles Linux cores itself: any ELF core in the input (WSL / Docker crash
dumps `wsl-crash-<unixtime>-<pid>-<exe>-<signal>.dmp`, `core`, `core.<pid>`, `*.core`, also inside zips) goes through
gdb in WSL instead of cdb. The report, summary.json, stage 2 and stage 3 work the same as for Windows dumps.

## Prerequisites (checked by `Test-AnalyzerSetup.ps1`)

| Need | Why | Setup |
|---|---|---|
| WSL with a Linux distribution | runs gdb | `wsl --install -d Debian` |
| gdb in that distribution | unwinds the stack, reads variables | `sudo apt install gdb` |
| Docker Desktop (or `-SysrootPath`) | the executable and shared libraries of the exact image; the core has no code pages, gdb needs them to unwind | image `harbor.inmationdev.com/aspentech-inmation/inmation:<version>` (config `linux.images`) |
| `inmation.dbg` with the same GNU build-id | function names, source lines, locals | `symbols\linux_amd64\inmation.dbg` in the build folder (config `linux.debugFile`), or `-PdbPath` |

Optional config (`linux` section of `crash-dump-analyzer.config.json` or the user override
`%LOCALAPPDATA%\inmation-crash-analysis\config.json`): `wslDistribution` (empty = default distribution),
`executables`, `debugFile`, `images`, `maxFoldersScanned`.

## What the collector does

1. Reads the core: signal and `si_code` (fault vs. sent by another process, sender PID), crashing thread, mapped files
   and the GNU build-id of `/inmation/bin/inmation`.
2. Finds `inmation.dbg` with that build-id: local cache, next to the core, `-PdbPath`, then the build folders of the
   OT DF release and dev shares (index cached in `%LOCALAPPDATA%\inmation-crash-analysis\symbols\linux`). The build
   folder gives the version and `build_info.txt` (exact build commit).
3. No matching folder: the version is read from the process memory (the version string, e.g. `26.1.0.7608.dev`), and
   the dump is BLOCKED with a hint where to get the debug file.
4. Gets the sysroot: pulls the product image of that version and extracts the executable and libraries into the WSL
   file system (cached per build-id). `-SysrootPath <folder>` uses an existing extraction (needs `inmation/bin/inmation`
   and `lib64`, `usr/lib64`).
5. Runs gdb (`gdb.cmd` / `gdb.log` in the dump folder of the run): siginfo, glibc abort message (`__abort_msg`), stack
   with source lines, registers, disassembly, locals of frames 0-5, shared libraries, all thread stacks.

## Reading the result

| Signal / classification | Meaning |
|---|---|
| `killed-by-signal` | Nothing faulted. Another process sent the signal (`si_code` <= 0, sender PID not the process itself). Sender PID 1 = the container init (dumb-init) forwarding `docker stop` / `docker kill` / orchestrator signals. The stack only shows where the main thread waited. Ask for container logs and who stopped it; do not search for a code defect. |
| SIGSEGV / SIGBUS fault | Same as a Windows access violation: the fault address is in the report (`fault at 0x...`). |
| SIGABRT + `failed-assertion` | glibc `assert()`; expression, file and line come from the abort message. |
| SIGABRT + `unhandled-cpp-exception` | `std::terminate` from `__cxa_throw`: on Linux the throwing frames stay on the stack, so the throw site is exact (not a stack scan as on Windows). The thrown type comes from the libstdc++ helper (`std::__throw_system_error` -> `std::system_error`) or the typeinfo argument. |
| SIGABRT + `memory-corruption-detected` | glibc heap check (`free(): invalid pointer`, `malloc(): corrupted top size`, ...); the message is in the hints. The stack is probably a victim. |
| SIGABRT + `stack-buffer-overrun` | `*** stack smashing detected ***` (stack protector). |
| SIGABRT + `deliberate-abort` | `abort()` called directly by product code; the first own frame says why. |

Frame names are normalized like Windows names: no parameter list, no `[clone .cold]`, `.cold`/`.isra` suffixes or
`@@GLIBC_x` symbol versions, so signatures stay stable across glibc builds.

## More detail with gdb

Use `Invoke-DumpQuery.ps1` (the digest ends each signature with the exact command). It reuses the run's `gdb.cmd`
(sysroot, debug file, core), selects the frame and runs your commands read-only:

```
powershell -NoProfile -ExecutionPolicy Bypass -File "<scripts>\Invoke-DumpQuery.ps1" -SummaryJson "<summary.json>" -Dump "<core path>" -Frame <N> -Command 'info locals; p *this'
```

| Question | `-Command` |
|---|---|
| Arguments and locals of frame N (with `-Frame N`) | `info args; info locals` |
| Members of `this` | `p *this` |
| A `std::string` local `s` (no pretty printers) | `p s._M_dataplus._M_p` and `p s._M_string_length` |
| Registers / faulting instruction | `info registers; x/6i $pc` |
| Memory at an address | `x/16gx <addr>` (pointers), `x/s <addr>` (string) |
| All threads | `thread apply all bt 20` (also in `threads.txt`) |
| Abort message | `x/s *(char**)&__abort_msg + 4` |

Refused: `shell`, `!`, `pipe`, `python`, `source`, `dump`, `run`... (anything that executes programs or writes
files). Blocked cores are refused: without the matching `inmation.dbg` the names would be wrong.

## Limits

- Lua call chains are not decoded for Linux cores yet. If `luaV_execute` / `lua_pcallk` frames are on the stack the
  report says so; use `-Frame <N> -Command 'p *L'` on a frame with a `lua_State *L` and follow `L->ci`.
- No libstdc++ pretty printers: STL containers print as raw members.
- arm64 cores: the debug file path is `symbols\linux_arm64\inmation.dbg`; WSL needs `gdb-multiarch` (untested).
