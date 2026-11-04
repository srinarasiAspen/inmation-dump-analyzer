# Crashes reached from Lua or Web API scripts

When the stack contains the Lua VM (`luaV_execute`, `luaD_precall`, `lua_pcallk`), the digest has a "Lua call chain"
section (innermost first): chunk names, current line, line range of the function, C functions such as `pcall`. For
Web API / SCI requests (`sci::Calls::run_script`) the "Script context" section lists the bundled modules, the request
(method, endpoint, remote address) and the decoded payload. Credentials and tokens are masked in the saved scripts.

## Reading the chunk names

| Chunk | What it is | Where the code is |
|---|---|---|
| `= ...` | The entry script (Web API / SCI wrapper with the request) | `script-frame<N>.lua` in the dump's run folder |
| `@<object path>#<library>` (e.g. `@/System/Core#Lib`) | A library stored in the model | Not in the repository and not in the entry script. Recovered from memory if the digest has a "Recovered model library" section (`library-<name>.lua`). |

Never take lines of a `@...#library` frame from the entry script.

## Model library text

- "Recovered model library" in the digest: the text was found in memory and validated against the Lua function
  prototypes (first/last line, constants). Quote lines from it and say "recovered from process memory".
- "Lua function prototypes" table: upvalue names (locals of the enclosing library), local names and string constants
  (globals, fields, literals) of each frame's function. They narrow the trigger even without the text.
- "NOT recovered": search manually with cdb: pick a distinctive name from the prototype table,
  `s -a 0 L?0x7fffffffffff "<name>"`, then `db <addr>-0x8000 L?0x10000` and look for the NUL-terminated text. Accept it
  only if line `linedefined` starts the function and line `lastlinedefined` holds its `end`. Otherwise say the library
  text is unknown.

## Lua versions

1.x uses Lua 5.3, OT Data Fabric Lua 5.5 (the digest's third-party table shows the `lua` port version). The
collector handles both layouts; for manual reads: 5.3 `ci->func` is a `TValue*`, chunk name `(char*)(p->source+1)`,
line `p->lineinfo[(ci->u.l.savedpc - p->code) - 1]`; 5.4.6+/5.5 `ci->func.p->val`, line from `abslineinfo` + relative
`lineinfo`; 5.5 short strings at `&ts->contents`, long strings at `ts->contents`.

## Trigger vs product defect

- A script error, bad configuration or unexpected input from a customer library is the **trigger**.
- Lua input that terminates the whole process (abort, access violation, assert in a native library) is still a
  **product defect**: native code reachable from Lua must turn invalid input into a Lua error. Report both.
- A `pcall` in the Lua chain does not protect against a native abort or access violation. Say so when present.
- Globals vs locals: a name that is a string constant used with `_ENV` (and not a local/upvalue) is a global. A
  commented-out `-- local NAME = ...` in the library makes it an undefined global = `nil`, which silently switches APIs
  to their defaults. Check the default path of the `syslib` function at the build commit.
- Several dumps with the same signature: the digest's "Per-dump comparison" (endpoint, Lua line, payload per dump)
  shows the common trigger. Uptime of seconds = startup / first request; hours = load or data dependent.
