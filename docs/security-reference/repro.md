# libparse / parse-server build, test and reproduction recipes (example)

**Fictional example content.** Commands are what the fictional repos'
`README.md`, `BUILDING.md` and `cmake/options.cmake` document; file paths
match `libparse-components.md`. Version-dependent facts name the file to
re-check.

---

## 1. libparse: quickstart build

Dependencies: CMake ≥ 3.20, Ninja, a C11 compiler (Clang for sanitizers and
fuzzing), Python 3 with `pytest` for the test driver, Valgrind ≥ 3.18 for
constant-time tests.

```sh
git clone https://github.com/example-org/libparse.git
cd libparse && mkdir build && cd build
cmake -GNinja ..
ninja
ninja test          # runs tests/run.py against the vectors
```

- Output: static `build/lib/libparse.a` (add `-DBUILD_SHARED_LIBS=ON` for a
  shared library). Headers in `build/include/`.
- Test binaries under `build/tests/`: `test_decode`, `test_verify`,
  `vectors_check`, `fuzz_decode` (only with `LP_BUILD_FUZZERS=ON`).
- All options: `cmake -LAH -N ..`; defaults in `cmake/options.cmake`.

## 2. Security-relevant CMake options (cmake/options.cmake)

| Option | Meaning |
|---|---|
| `CMAKE_BUILD_TYPE=Debug` | Required for sanitizers and constant-time tests |
| `LP_ENABLE_SANITIZER=Address\|Undefined\|Memory` | Clang-only, Debug-only |
| `LP_BUILD_FUZZERS=ON` | Builds `tests/fuzz_decode` with libFuzzer; needs `CC=clang` |
| `LP_ENABLE_CT_TESTS=ON` | Builds the Valgrind harness in `tests/ct/`; forces Debug |
| `LP_ENABLE_LEGACY_V0=ON` | Compiles the deprecated v0 decoder (default OFF) |
| `LP_MAX_RECORDS`, `LP_MAX_RECORD` | Parsing limits (defaults 4096, 1 MiB) |

## 3. Sanitizer build and a minimal harness

```sh
cd libparse && mkdir build && cd build
CC=clang cmake -GNinja -DCMAKE_BUILD_TYPE=Debug -DLP_ENABLE_SANITIZER=Address ..
ninja
```

Minimal harness driving attacker-controlled bytes at the API a report blames
(signatures verbatim from `include/libparse/frame.h`, `key.h`):

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

```sh
cd ..    # back to the libparse root
clang -fsanitize=address harness.c -I build/include build/lib/libparse.a -o harness
./harness crafted.pff key.bin
```

`lp_frame_decode` returns `LP_ERR_*` on malformed input; a nonzero return is
**expected** for a crafted frame. The signal for a memory-safety report is the
sanitizer trace, not the return code.

## 4. Known-answer vectors

`tests/vectors/` holds `<name>.pff` + `<name>.expect` pairs (expected return
code and, for valid frames, the record digests). `ninja test` runs them all;
one at a time:

```sh
./build/tests/vectors_check tests/vectors/basic-3-records
```

A vector mismatch after a change is a correctness break and often
security-relevant (a frame that used to fail verification and now passes).

## 5. Constant-time (Valgrind) testing

```sh
cd libparse && mkdir build && cd build
cmake -GNinja -DCMAKE_BUILD_TYPE=Debug -DLP_ENABLE_CT_TESTS=ON ..
ninja
cd ..
python3 tests/ct/run_ct.py --module verify      # or: --module hmac, key
```

How it works: `tests/ct/ct_harness.c` marks key bytes and the expected MAC as
uninitialised (Valgrind memcheck) and runs `lp_frame_verify`; any branch or
memory index that depends on them is reported. Known findings live in
`tests/ct/passes/` (audited false positives) and `tests/ct/issues/` (known
concerns), indexed by `passes.json` / `issues.json`.

**Triage-critical:** check the suppression files *first* — a claimed leak may
already be documented. And read the module datasheet: `decode` and `varint`
claim nothing, so a timing finding there violates no claim.

## 6. Fuzzing

```sh
cd libparse && mkdir build && cd build
CC=clang cmake -GNinja -DCMAKE_BUILD_TYPE=Debug -DLP_ENABLE_SANITIZER=Address \
  -DLP_BUILD_FUZZERS=ON ..
ninja
./tests/fuzz_decode ../tests/corpus/decode -max_len=65536
```

A reporter's crashing input can be run directly:
`./tests/fuzz_decode crash-input.bin`.

## 7. parse-server: build and exercise the network path

```sh
cd parse-server
cmake -S . -B _build -Dlibparse_DIR=../libparse/build && cmake --build _build
_build/parse-server --listen 127.0.0.1:7700 --keystore test/keys/ &
_build/tools/pff-send 127.0.0.1:7700 crafted.pff
```

`pff-send` writes a 4-byte big-endian length then the frame — exactly what
`conn_read` in `src/net/conn.c` expects — so a libparse crash reproduced this
way proves network reachability before authentication.

## 8. Things to re-check

- Option names and defaults: `cmake/options.cmake`.
- Supported release: `SECURITY.md` in each repo.
- Public API: `include/libparse/*.h`.
- Whether a "fixed" bug is fixed on the tag the report targets:
  `git log -p -- src/frame/decode.c`.
