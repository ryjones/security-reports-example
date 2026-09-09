---
name: reproducing-security-reports
description: Use when a credible report needs hands-on confirmation before status:confirmed, when running or evaluating a reporter's PoC, or when a memory-safety/timing claim can only be settled by building and executing libparse or parse-server — not by reading code alone.
---

# Reproducing security reports

Code-reading verifies *existence* claims (does the symbol exist?). Only building
and running verifies *behavior* claims (does the OOB write actually happen?). Use
this skill when a report survived slop-detection and scope checks and now needs a
run to confirm or to hand a human a clean write-up.

## Safety preamble (do this first)

A PoC is untrusted code. It may be hostile or just buggy.
- READ every line before compiling. Look for network calls, `system()`/`exec`,
  file writes outside cwd, shell-outs, downloads.
- Run only in the scratchpad dir. No credentials, no network, no secrets in env.
- Never commit a PoC or its artifacts to this tracker repo.
- Never paste report/PoC text into a web search or any external service — this
  repo is private and embargo-sensitive. Public-info lookups only.

## When repro IS / ISN'T required

Confirmation requires evidence, not merely a plausible reading. For behavioral
bugs (memory-safety, timing) that means reproduction; for an authentication or
validation flaw it may mean conclusive analysis (PROCESS.md: "reproduce or
otherwise confirm"). Code-reading that only fails to disprove a mechanism never
justifies `status:confirmed`.

- Reproduce before recommending `status:confirmed` for a memory-safety or
  timing claim — that label asserts a confirmed security issue.
- A logic flaw provable by conclusive analysis (e.g. `lp_frame_verify` compares
  a truncated trailer in a code path you can read end to end) may not need a
  run — say so and show the lines. A plausible read that only fails to
  disprove the mechanism is not enough.
- Repro is NOT a triage gate. A report that is out of scope, against an
  unsupported project, or fabricated (symbols don't exist) is dispositioned
  without a build. Do the scope + slop checks first (see REQUIRED SUB-SKILLs).

## Verdict discipline (the load-bearing rule)

**Not reproduced ≠ refuted.** Reading code and failing to trigger a bug does not
disprove a data-dependent flaw; only a run that *should* trigger it and doesn't
is evidence, and even then narrowly. Three outcomes only:

| Outcome | Evidence | Recommendation |
|---|---|---|
| Reproduced | sanitizer trace / vector mismatch / crash, with the exact command | recommend `status:confirmed`; hand to fix coordination |
| Not reproduced | document EXACTLY what was built (flags, tag), what you ran, what happened | do NOT dismiss; escalate to a human VMT member with the write-up |
| Can't build/run it here | what blocked you | escalate; never convert "I couldn't run it" into "invalid" |

If symbols are real but you cannot make the mechanism fire, the verdict stays
**credible — needs reproduction**, never "fabricated." A missed real
vulnerability costs far more than a wasted build.

## Version discipline

Build against the supported release tag AND `main` (supported version = check the
repo's `SECURITY.md`, don't trust memory). If the report targets an old tag,
`git log -p -- <file>` to check whether it was already fixed before you invest.

## Minimal libparse build with a sanitizer

Sanitizers are Clang-only and Debug-only. The two real knobs are
`LP_ENABLE_SANITIZER` (ASan/UBSan/MSan) and `LP_ENABLE_CT_TESTS` (Valgrind
timing) — verify any option in `libparse/cmake/options.cmake` before quoting it.

```sh
cd libparse && mkdir build && cd build
CC=clang cmake -GNinja -DCMAKE_BUILD_TYPE=Debug -DLP_ENABLE_SANITIZER=Address ..
ninja
./tests/test_decode                          # functional tests, decode path
```

For the `LP_ENABLE_SANITIZER` values (`Address`, `Undefined`, `Memory`) see
`cmake/options.cmake`. Parsing limits (`LP_MAX_RECORDS`, `LP_MAX_RECORD`) are
also options and change per release — don't hardcode them.

## Minimal C harness (verified API, from include/libparse/frame.h and key.h)

Drive attacker-controlled input at the API the report blames — e.g. a crafted
frame into `lp_frame_decode`. Signatures are verbatim from the headers.

```c
#include <libparse/frame.h>
#include <libparse/key.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    /* argv[1]: path to a frame file; argv[2]: path to a 32-byte key */
    uint8_t *buf; size_t len;             /* read_file() left to the reader */
    uint8_t keybuf[32];
    lp_key *key = NULL; lp_frame *frame = NULL;
    if (lp_key_load(keybuf, sizeof keybuf, &key) != LP_OK) return 2;
    int rc = lp_frame_decode(buf, len, &frame);      /* ASan reports here if OOB */
    if (rc == LP_OK) rc = lp_frame_verify(frame, key);
    printf("rc=%d\n", rc);
    lp_frame_free(frame); lp_key_free(key);
    return rc == LP_OK ? 0 : 1;
}
```

Compile against the local build from the libparse root (`cd ..` out of `build`):

```sh
cd ..    # from libparse/build back to the libparse root
clang -fsanitize=address harness.c -I build/include build/lib/libparse.a -o harness
./harness crafted.pff key.bin
```

`lp_frame_decode` returns `LP_ERR_*` on malformed input, so a nonzero return is
**expected** for a crafted frame and is not the signal. The signal for a
memory-safety report is the sanitizer trace; for a verification-bypass report it
is `lp_frame_verify` returning `LP_OK` on a frame the key did not produce.

## More recipes

See **repro-reference.md** (same directory) for: known-answer vectors and the
full test suite, Valgrind constant-time testing and checking a claimed leak
against the documented `passes`/`issues` suppression files, fuzz harnesses, and
building parse-server against libparse to exercise the network path.

## Cross-references

- REQUIRED SUB-SKILL before repro: `detecting-report-slop` (grep the symbols),
  `threat-model-and-scope` (is it even in scope?).
- After a clean reproduction: `assessing-severity`, then
  `coordinating-fix-and-disclosure`.
- Deliver a recommendation; apply labels only if the operator asked.
