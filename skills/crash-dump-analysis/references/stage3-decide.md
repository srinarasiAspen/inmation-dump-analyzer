# Stage 3: deciding the verdict and the root cause

Input: `code-evidence.md` (written by `Get-CodeEvidence.ps1`), the digest, and the report sections 1-2.
Output: an answer for every open item that `Complete-CrashReport.ps1` lists for sections 3-5 (keys like
`3A Still failing on the latest code?`, `5A Mechanism`), plus `## Verdict` and, when you checked it, `## Build commit`.

## Step 1 - can the build commit be trusted?

| Build commit confidence (code-evidence.md) | Do |
|---|---|
| `exact` (build_info.txt) | Trust it. Check only that the marked faulting line is real code that can fault (not a blank line or comment). |
| `high` (release tag, version bump commit) | Same as exact. |
| `medium` / `low` (estimated from the build time) | Check the marked faulting line: is it code that can produce the exception (a dereference for an access violation, the asserted call for an assert, a throw for a C++ exception)? If yes, keep it and say "estimated, consistent with the PDB line". If the line is unrelated (blank, comment, a different function), the estimate is wrong: write that, set the verdict to `Inconclusive`, and name what is needed (the build's commit, e.g. from `build_info.txt` of the build folder). |

Answer `## Build commit` with: `<sha10> (<confidence>, <method>; consistent with the PDB source line)`.

## Step 2 - release build or dev build?

The build channel is in the report header (`Binary` row) and in `code-evidence.md` ("dev build" / "release build").

### Release build: does the problem still exist on the analysis ref?

Use the status lines of the faulting function(s) and the linked fixes:

| Evidence | Verdict |
|---|---|
| A linked fix is on the analysis ref, is **not** in the crashed build, touches the crashing files, **and its diff changes the faulting code or the code that produced the bad value** | `Fixed in <sha10>` |
| The function changed after the build, the faulting line changed or was removed, and the change prevents the bad value / the faulting access | `Fixed in <sha10 of that commit>` |
| The dumped trigger is handled, but the same function or a close path can still fail the same way (e.g. another unchecked pointer next to the fix) | `Fixed - related risk remains` |
| Function unchanged (or only unrelated changes), no fix found | `Still present` |
| The function was removed, rewritten, or the build commit is not trustworthy | `Inconclusive` |

"The file changed" is not proof. Read the diff and say in one sentence why it fixes (or does not fix) this crash.

Section 4 (release builds) - fixing commit:
- `Fixed`: sha, date, author, subject (PR / work item), the diff hunk that fixes it (copy from code-evidence.md), and
  where it is available: release branches and tags from code-evidence.md; whether the crashed version's branch has it
  (`version branch ... yes/no`, cherry-pick candidates). If not: "backport to <branch> or upgrade to <version/tag>".
- `Still present`: "n/a - still present".

### Dev build: root cause on the latest code

Skip the fixing-commit hunt. Section 3: "Still failing on the latest code?" - answer with the function status:
unchanged -> "yes, the faulting code is unchanged on <ref>"; changed -> one or two sentences on whether the change
removes the failure (name the commit). A linked fix from stage 2 that is on the ref and changes the crashing code
counts as "no - fixed by <sha10>". Section 4: keep "n/a - dev build".

Header `Verdict` for dev builds: `Root cause identified` when the mechanism below is clear and backed by dump facts,
else `Hypothesis (medium)` or `Hypothesis (low)`.

## Step 3 - root cause (section 5)

Fill the four lines. Use only facts you can point to: the exception and address, the faulting instruction and register
(digest: disassembly, registers), locals (digest / `locals.txt`), the code at the build commit, the call chain.

| Classification | Mechanism to explain | Typical bad value source |
|---|---|---|
| `null-pointer` | Which pointer is null: the register in the faulting instruction, the member offset = the access address. | An object not created / already reset, a failed lookup not checked, a missing input. |
| `wild-pointer` | A pointer to freed or foreign memory was used. Say which object, and who frees it. | Use-after-free (object lifetime), a race (check `threads.txt` for other threads on the same object), a view into a buffer that died. |
| `bad-code-pointer` | A call through a corrupt function pointer / vtable. | Object destroyed while in use; memory corruption. |
| `failed-assertion` | Why the asserted condition was false. | Unvalidated input reaching a library (e.g. an empty collection name from a script). The assert site is the culprit. |
| `unhandled-cpp-exception` | Which call threw (throw site), the error code meaning, why no handler caught it. | Throw from a destructor or noexcept function; a lock/thread misuse (`resource_deadlock_would_occur` = a thread joins/locks itself). |
| `heap-corruption`, `memory-corruption-detected` | Only that corruption was detected here; the stack is likely a victim. | Unknown from this dump: recommend PageHeap / ASan. Confidence low. |
| `stack-buffer-overrun` | Which local buffer in the cookie-owning function overflowed. | Unchecked copy length. |
| `stack-overflow` | The recursion (function repeated in the stack). | Missing recursion limit / cyclic data. |
| crash in an external DLL | Whether inmation passed bad arguments (check the first inmation frame) or the DLL failed by itself. | Version mismatch, invalid handle, unchecked return value. |

**Fix proposal**: a short diff against the latest code (not applied) that turns the bad value into a handled error, or
the fixing commit. **Confidence**: high (dump facts + code agree), medium (one link is inferred), low (several
hypotheses) - and what extra data would decide (another dump, logs, PageHeap, a full dump instead of a minidump).

When a customer script, configuration or input triggered a product defect, write two parts in section 5:
"Workaround (customer)" - what to change in the script/configuration now, and "Product fix" - the code change.
