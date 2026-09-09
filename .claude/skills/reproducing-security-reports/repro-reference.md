# repro-reference — build/test recipes

Companion to `reproducing-security-reports/SKILL.md`. Every command here was
extracted from docs/CMake in the local clones (libparse, parse-server). Version-
dependent facts (option names, limits, supported release) are flagged — re-check
the authoritative file, never hardcode. Confidentiality and safety rules from
the SKILL apply to everything here.

## libparse — full build and test suite

```sh
cd libparse && mkdir build && cd build
cmake -GNinja ..            # default build (Release); static lib -> build/lib/libparse.a
ninja
ninja test                 # runs tests/run.py against the known-answer vectors
```

- Add `-DBUILD_SHARED_LIBS=ON` for a shared lib. Public headers land in
  `build/include/`. Test binaries build under `build/tests/`: `test_decode`,
  `test_verify`, `vectors_check`, and `fuzz_decode` (only with
  `LP_BUILD_FUZZERS=ON`).
- All CMake options: `cmake -LAH -N ..` from the build dir. Defaults live in
  `libparse/cmake/options.cmake`.

## libparse — known-answer vectors

A vector mismatch = a correctness break, often security-relevant (a frame that
used to fail verification and now passes). `tests/vectors/` holds
`<name>.pff` + `<name>.expect` pairs: expected return code and, for valid
frames, the record digests.

```sh
cd libparse                # source root
ninja -C build test                                   # all vectors
./build/tests/vectors_check tests/vectors/basic-3-records   # one vector
```

## libparse — constant-time (Valgrind) testing

For a claimed timing / secret-dependent-branch leak. Requires Valgrind >= 3.18,
`CMAKE_BUILD_TYPE=Debug` AND `LP_ENABLE_CT_TESTS=ON` (the option forces Debug).

```sh
cd libparse && mkdir build && cd build
cmake -GNinja -DCMAKE_BUILD_TYPE=Debug -DLP_ENABLE_CT_TESTS=ON ..
ninja
cd ..
python3 tests/ct/run_ct.py --module verify     # or: --module hmac, --module key
```

How it works: `tests/ct/ct_harness.c` marks the key bytes and the expected MAC
as uninitialized (Valgrind memcheck) and runs `lp_frame_verify`, so Memcheck
flags any branch or memory index that depends on them.

**Triage-critical:** a claimed timing leak may already be documented. Check the
suppression files FIRST:
- `tests/ct/passes/` — audited, judged not a threat (registered in
  `passes.json`, module name -> suppression filenames).
- `tests/ct/issues/` — known concern (`issues.json`).

If the finding is under `passes`, the "leak" is likely a documented pass; if
under `issues`, it may be a known-and-tracked concern, not a new finding.
Cross-check the module datasheet too: `decode` and `varint` claim nothing, so a
timing finding there violates no claim (see `threat-model-and-scope`). This test
runs on fixed inputs, is not coverage-guided, and misses rare paths — a clean
run is not proof of absence.

## libparse — fuzz harnesses

Requires `CC=clang` and libFuzzer. Existing harness: `tests/fuzz_decode.c`.

```sh
cd libparse && mkdir build && cd build
CC=clang cmake -GNinja -DCMAKE_BUILD_TYPE=Debug -DLP_ENABLE_SANITIZER=Address \
  -DLP_BUILD_FUZZERS=ON ..
ninja
./tests/fuzz_decode ../tests/corpus/decode -max_len=65536
```

A reporter's crashing input can be run directly: `./tests/fuzz_decode
crash-input.bin`. See `cmake/options.cmake` -> `LP_BUILD_FUZZERS`.

## libparse — targeted single-path run

```sh
./build/tests/test_decode              # functional test, decode path
./build/tests/test_verify              # verify + MAC comparison
./build/tests/vectors_check tests/vectors/<name>   # one known-answer vector
```

Verify-side API for a harness (verbatim from `include/libparse/frame.h` and
`key.h`): `lp_key_load`, `lp_frame_decode`, `lp_frame_verify`,
`lp_frame_record_count`, `lp_frame_record`, `lp_frame_free`, `lp_key_free`.
Return codes in `include/libparse/errors.h`: `LP_OK`, `LP_ERR_TRUNCATED`,
`LP_ERR_BAD_HEADER`, `LP_ERR_BAD_MAC`, `LP_ERR_TOO_LARGE`, `LP_ERR_NOMEM`.

## parse-server — build against libparse

Reports blaming network behavior exercise parse-server on top of libparse.
Prereqs: a libparse build (or install) to point `libparse_DIR` at.

```sh
cd parse-server
cmake -S . -B _build -Dlibparse_DIR=../libparse/build && cmake --build _build
ctest --test-dir _build
```

- For a debug/sanitizer build add `-DCMAKE_BUILD_TYPE=Debug` and the same
  `LP_ENABLE_SANITIZER` value libparse was built with; parse-server has no
  sanitizer options of its own.
- Daemon binary: `_build/parse-server`; test tooling under `_build/tools/`.

## parse-server — exercise the network path

Run the daemon with a test keystore and send a frame the way a real peer would
(4-byte big-endian length, then the frame — exactly what `conn_read` in
`src/net/conn.c` expects):

```sh
_build/parse-server --listen 127.0.0.1:7700 --keystore test/keys/ &
_build/tools/pff-send 127.0.0.1:7700 crafted.pff
```

A libparse crash reproduced this way proves network reachability.

**Two triage traps (verified):**
- parse-server calls `lp_frame_decode` **before** `lp_frame_verify`, so any
  decode-path bug is reachable by an unauthenticated peer. A report that says
  "requires a valid key" for a decode bug has the exposure backwards — score it
  pre-auth (see `assessing-severity`).
- `LP_ENABLE_LEGACY_V0` is **off by default**: a report against the legacy v0
  decoder only affects users who enabled it. Likewise a report that assumes
  non-default `LP_MAX_RECORDS` / `LP_MAX_RECORD` values is against a
  non-default build — confirm the reporter's configuration before attributing
  the bug to the shipped defaults.

## Authoritative files to re-check (staleness)

- Build options and limits: `libparse/cmake/options.cmake`;
  `parse-server/CMakeLists.txt`.
- Supported release: each repo's `SECURITY.md`.
- Public API: `libparse/include/libparse/*.h`.
- Known-answer vectors: `libparse/tests/vectors/`.
- Whether a "fixed" bug is fixed on the tag the report targets:
  `git log -p -- src/frame/decode.c`.
