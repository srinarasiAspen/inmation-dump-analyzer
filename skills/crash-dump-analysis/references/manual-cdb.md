# Manual cdb queries (only when the scripts did not give the fact you need)

Use `Invoke-DumpQuery.ps1` - it takes dump, symbol path and image path from the run, so you only write the debugger
commands (the digest ends each signature with the exact command line):

```
powershell -NoProfile -ExecutionPolicy Bypass -File "<scripts>\Invoke-DumpQuery.ps1" -SummaryJson "<summary.json>" -Dump "<dump path or number>" -Frame <N> -Command 'dx -r2 this; dv /t'
```

- `-Frame <N>`: decimal frame number from the report/digest (the script runs `.ecxr; .frame 0n<N>` first).
- `-Command`: one string; separate several commands with `;`. `-Filter '<regex>'` keeps only matching output lines.
- The output is between `QUERY_OUTPUT_BEGIN` and `QUERY_OUTPUT_END`; the full log path is in `QUERY_LOG=`.
- Refused: blocked dumps (no verified symbols) and commands that run programs or write files (`.shell`, `.writemem`...).

Use only read-only commands. Stop after two runs that do not bring the fact; report the gap.

## Pitfalls

- Frame numbers in `kn` output are **hex**; the digest and `-Frame` use decimal. Inside `-Command` write `.frame 0n27`
  (0x27 would be frame 39).
- `dv` truncates long strings. For a `std::string` read `<var>._Mypair._Myval2._Mysize` and
  `<var>._Mypair._Myval2._Bx._Ptr` (when `_Myres >= 16`, else the inline `_Bx._Buf`), then `db <ptr> L?<size>`.
- `.if` conditions cannot contain `@@c++(...)`; assign first: `r $t0 = @@c++(...)`, then test `@$t0`.
- Every `r` resets the register context of `.ecxr`. Repeat `.ecxr; .frame 0n<N>` before each `r` that reads a local.
- `context.cdb.txt` in a dump's run folder is a working example of a long query (Lua CallInfo walk with `.for`).
- `!analyze` WRONG_SYMBOLS buckets for ntdll/kernel32 are expected (no Microsoft symbols). Ignore them.

## Useful queries

| Question | Invoke-DumpQuery arguments |
|---|---|
| Value of a member of a local in frame N | `-Frame <N> -Command 'dx -r2 <local>.<member>'` |
| All locals with types in frame N | `-Frame <N> -Command 'dv /t /v'` |
| Which register held the bad pointer | `-Command 'r; u @$scopeip L1'` (the faulting instruction; compare with the access address) |
| Other threads using the same object | `-Command '~* kn 30' -Filter 'inmation!|^ *#|Id:'` (also in `threads.txt`) |
| Memory around an address | `-Command 'dps <addr>-0x40 L20'` (pointers with symbols), `-Command 'db <addr> L100'` (bytes) |
| Heap block of an address (full dumps) | `-Command '!heap -p -a <addr>'` (often unavailable in minidumps) |

## Unhandled C++ exception - manual fallback

The collector decodes the thrown C++ exception automatically ("Thrown C++ exception" in the digest, `cxx-scan.log`).
If it reported no record, this is the manual scan as `-Command` (x64; for 32-bit use `@esp`, magic at `+0x14`,
object at `+0x18`):

```
.foreach (rec {s -[1]d @rsp L?0x6000 e06d7363}) { .if (dwo(${rec}+0x20) == 0x19930520) { .echo <<<CXX_RECORD ${rec}>>>; .exr ${rec}; dps poi(${rec}+0x28) L6; .echo <<<THROW_STACK>>>; dps ${rec} L400 } }
```

- The first `dps` line of the object is `inmation!<type>::`vftable'` = the thrown type. For `std::system_error` the
  error value is the low dword at object+0x18 and the category at object+0x20 (`_Generic_error_category`: errno, e.g.
  36 = resource_deadlock_would_occur; `_System_error_category`: Win32 error).
- In the THROW_STACK part keep only `inmation!` code symbols with `+0x` offsets. After `_CxxThrowException` /
  `std::_Throw_Cpp_error` the first application frame is the throw site; the following ones are callers.
- These frames were on the stack; they are not an exact call chain. Say so.
