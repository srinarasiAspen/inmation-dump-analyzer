# Manual cdb queries (only when the scripts did not give the fact you need)

The digest ends each signature with a "Further cdb queries" command line that already has the verified symbol path.
Use only read-only commands. Put all commands for one question in one file and run `cdb ... -cf <file>`; filter the
output in PowerShell (e.g. only `inmation!` lines). Stop after two runs that do not bring the fact; report the gap.

## Pitfalls

- Frame numbers in `kn` output are **hex**; the digest uses decimal. `.frame 27` means 0x27 = 39. Use `.frame 0n27`.
- `dv` truncates long strings. For a `std::string` read `<var>._Mypair._Myval2._Mysize` and
  `<var>._Mypair._Myval2._Bx._Ptr` (when `_Myres >= 16`, else the inline `_Bx._Buf`), then `db <ptr> L?<size>`.
- `.if` conditions cannot contain `@@c++(...)`; assign first: `r $t0 = @@c++(...)`, then test `@$t0`.
- Every `r` resets the register context of `.ecxr`. Repeat `.ecxr; .frame 0n<N>` before each `r` that reads a local.
- Commands with quotes or many steps: write them to a file, run with `-cf <file>` instead of `-c "..."`. The
  `context.cdb.txt` in a dump's run folder is a working example (Lua CallInfo walk with `.for`).
- `!analyze` WRONG_SYMBOLS buckets for ntdll/kernel32 are expected (no Microsoft symbols). Ignore them.

## Useful queries

| Question | Commands |
|---|---|
| Value of a member of a local in frame N | `.ecxr; .frame 0n<N>; dx -r2 <local>.<member>` |
| Which register held the bad pointer | `.ecxr; r; u @$scopeip L1` (the faulting instruction; compare with the access address) |
| Other threads using the same object | `~* kn 30` (also in `threads.txt`), search for the object's functions |
| Memory around an address | `dps <addr>-0x40 L20` (pointers with symbols), `db <addr> L100` (bytes) |
| Heap block of an address (full dumps) | `!heap -p -a <addr>` (often unavailable in minidumps) |

## Unhandled C++ exception - manual fallback

The collector decodes the thrown C++ exception automatically ("Thrown C++ exception" in the digest, `cxx-scan.log`).
If it reported no record, this is the manual scan (x64; for 32-bit use `@esp`, magic at `+0x14`, object at `+0x18`):

```
.ecxr
.foreach (rec {s -[1]d @rsp L?0x6000 e06d7363}) { .if (dwo(${rec}+0x20) == 0x19930520) { .echo <<<CXX_RECORD ${rec}>>>; .exr ${rec}; dps poi(${rec}+0x28) L6; .echo <<<THROW_STACK>>>; dps ${rec} L400 } }
q
```

- The first `dps` line of the object is `inmation!<type>::`vftable'` = the thrown type. For `std::system_error` the
  error value is the low dword at object+0x18 and the category at object+0x20 (`_Generic_error_category`: errno, e.g.
  36 = resource_deadlock_would_occur; `_System_error_category`: Win32 error).
- In the THROW_STACK part keep only `inmation!` code symbols with `+0x` offsets. After `_CxxThrowException` /
  `std::_Throw_Cpp_error` the first application frame is the throw site; the following ones are callers.
- These frames were on the stack; they are not an exact call chain. Say so.
