# libparse component fact pack (example)

**Verified against:** `../libparse` at tag `v2.4.1` (2026-06-30).
**Staleness warning:** everything here is version-dependent. Authoritative
sources: `docs/modules/*.md` (per-module datasheets), `include/libparse/*.h`
(API), `CMakeLists.txt` and `cmake/options.cmake` (build defaults),
`tests/ct/` (constant-time evidence). **All of this is fictional example
content.**

## Repository layout

```
include/libparse/frame.h     public frame API
include/libparse/key.h       key loading
include/libparse/mac.h       MAC primitives (exported for tests only)
src/frame/decode.c           lp_frame_decode, lp_read_header, lp_read_record
src/frame/verify.c           lp_frame_verify, lp_mac_equal
src/codec/varint.c           lp_varint_read (LEB128-style lengths)
src/codec/legacy_v0.c        legacy frame format v0 (OFF by default)
src/mac/hmac.c               lp_hmac_sha256
src/key/key.c                lp_key_load, lp_key_free
src/mem/mem.c                lp_malloc, lp_secure_free
tests/test_decode.c          functional tests
tests/test_verify.c
tests/fuzz_decode.c          libFuzzer harness (LP_BUILD_FUZZERS=ON)
tests/vectors/               known-answer vectors (frames + expected results)
tests/ct/                    Valgrind constant-time harness + suppressions
docs/modules/                per-module datasheets
```

## Public API (verbatim from the headers at v2.4.1)

`include/libparse/frame.h`:

```c
typedef struct lp_frame lp_frame;
int  lp_frame_decode(const uint8_t *buf, size_t len, lp_frame **out);   /* line 41 */
int  lp_frame_verify(const lp_frame *frame, const lp_key *key);         /* line 58 */
void lp_frame_free(lp_frame *frame);                                     /* line 63 */
size_t lp_frame_record_count(const lp_frame *frame);                     /* line 70 */
const lp_record *lp_frame_record(const lp_frame *frame, size_t index);   /* line 77 */
```

`include/libparse/key.h`:

```c
typedef struct lp_key lp_key;
int  lp_key_load(const uint8_t *raw, size_t len, lp_key **out);          /* line 22 */
void lp_key_free(lp_key *key);                                           /* line 27 */
```

Return codes (`include/libparse/errors.h`): `LP_OK` (0), `LP_ERR_TRUNCATED`,
`LP_ERR_BAD_HEADER`, `LP_ERR_BAD_MAC`, `LP_ERR_TOO_LARGE`, `LP_ERR_NOMEM`.

**Contract:** `lp_frame_decode` parses structure only and never touches a key.
`lp_frame_verify` recomputes the HMAC over the decoded bytes and compares it to
the trailer with `lp_mac_equal`. A frame that fails verification must be
discarded; the API does not expose partially verified content.

## Frame format (docs/format.md)

```
+--------+---------+------------+-----------------+-----------+
| magic  | version | rec_count  | records...      | mac[32]   |
| 4 B    | 1 B     | varint     | rec_count × rec | 32 B      |
+--------+---------+------------+-----------------+-----------+
rec := len (varint) || payload[len]
```

Limits enforced in `lp_read_header`: `rec_count <= LP_MAX_RECORDS` (4096),
`len <= LP_MAX_RECORD` (1 MiB). Total frame length is bounded by the caller's
`len` argument — every read is supposed to be checked against it.

## Per-module datasheet summary

| Module | Datasheet | Default build | Constant-time claim | Checked by Valgrind (x86_64) | Notes |
|---|---|---|---|---|---|
| `frame/decode` | `docs/modules/decode.md` | ON | none (data-dependent by design) | n/a | Parsing is expected to be variable-time. |
| `frame/verify` (`lp_mac_equal`) | `docs/modules/verify.md` | ON | **yes** | **yes** | A leak here is a regression of a claimed property. |
| `mac/hmac` | `docs/modules/hmac.md` | ON | yes | yes | Wraps a vendored SHA-256 (see upstream note). |
| `key/key` | `docs/modules/key.md` | ON | yes (no key-dependent branches) | yes | |
| `codec/varint` | `docs/modules/varint.md` | ON | none | n/a | |
| `codec/legacy_v0` | `docs/modules/legacy_v0.md` | **OFF** (`LP_ENABLE_LEGACY_V0`) | **none** — "no constant-time analysis has been done" | no | Kept for migration only; deprecated. |

**How to read the claim columns.** "Constant-time claim: none" means a timing
finding violates no promise — track it, but it is a documented limitation, not
a broken claim. "Claim: yes / Checked: no" (aarch64 builds of `verify` and
`hmac`) means a claim exists that the project has never tested; a leak there is
a claim violation that was never caught.

## Upstream code

- `src/mac/sha256.c` is vendored from an external SHA-256 implementation
  (`third_party/UPSTREAM.md` names the source and pinned commit). A bug there
  is an **upstream** issue: pass it upstream, and if libparse patches locally
  while upstream stays unfixed, the published advisory must say so.
- Everything else is first-party.

## Build defaults that matter for triage

From `cmake/options.cmake` — VOLATILE:

| Option | Default | Meaning |
|---|---|---|
| `LP_ENABLE_LEGACY_V0` | OFF | Compiles the legacy v0 decoder. A report against it only affects users who enabled it. |
| `LP_ENABLE_SANITIZER` | (unset) | `Address`, `Undefined`, `Memory`; Clang, Debug builds only. |
| `LP_BUILD_FUZZERS` | OFF | Builds `tests/fuzz_decode` (needs Clang + libFuzzer). |
| `LP_ENABLE_CT_TESTS` | OFF | Builds the Valgrind harness; forces Debug. |
| `LP_MAX_RECORDS` / `LP_MAX_RECORD` | 4096 / 1 MiB | Parsing limits; a report that assumes other values is against a non-default build. |

## Known / already-rejected timing patterns (docs/modules/README.md)

- Record-count-dependent loop timing in `lp_frame_decode` — rejected: parsing
  is public data.
- Early exit in `lp_read_header` on bad magic — rejected: the magic is public.

A timing report matching one of these is a known limitation, not a new finding.
