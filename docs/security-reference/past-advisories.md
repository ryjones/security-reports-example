# Past advisories (PUBLIC, published only) — example calibration set

**Fictional example content.** These six advisories are invented so the
`assessing-severity` skill has a self-consistent set of anchors. When you adopt
this tracker, replace them with your projects' real *published* advisories,
collected with something like:

```sh
gh api /repos/<owner>/<repo>/security-advisories --paginate \
  | jq '.[] | select(.state == "published")'
```

**Scope / privacy note.** An authenticated caller with repo access also gets
`triage`, `draft` and `closed` advisories back. Those are not public and must
never be copied into this file. Only `published` advisories belong here.

All vectors are CVSS v3.1 as published; severity bands are GitHub's.

---

## libparse advisories (newest first)

### 1. GHSA-exmp-0005-desn — CVE-2025-90005 — LOW (3.7)

- **Title:** "Theoretical weakness in legacy v0 nonce derivation"
- **CVSS:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` = 3.7
- **Affected:** libparse <= 2.4.0 with `LP_ENABLE_LEGACY_V0=ON`. **Patched:**
  none — the v0 format is deprecated and off by default; users are told to
  migrate. Published 2025-11-02.
- **Summary:** Nonces in the legacy v0 format are derived from a 32-bit
  counter, so two frames under one key collide after 2^16 frames in
  expectation. No concrete attack on the MAC was identified.
- **Why Low:** design-level, no known exploit, high attack complexity, at most
  limited confidentiality impact.

### 2. GHSA-exmp-0004-oobr — CVE-2025-90004 — MEDIUM (5.3)

- **Title:** "Out-of-bounds read in record parsing with a short final record"
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L` = 5.3
- **CWE:** CWE-125
- **Affected:** libparse 2.3.0 – 2.4.0. **Patched:** 2.4.1
  (commit `3f1c9ab`). Published 2025-08-19.
- **Summary:** `lp_read_record` checked the declared record length against
  `LP_MAX_RECORD` but not against the bytes remaining in the caller's buffer,
  so a final record whose declared length exceeded the remainder was read past
  the buffer. The over-read bytes feed only the HMAC input.
- **Why Medium:** the bytes are never returned to the caller and cannot make
  `lp_frame_verify` accept a frame (the MAC still has to match), so there is
  no oracle and no forgery path. The worst case is a crash if the read crosses
  into an unmapped page — `A:L` only, despite `AV:N/AC:L`.

### 3. GHSA-exmp-0003-trlr — CVE-2025-90003 — HIGH (7.5)

- **Title:** "lp_frame_verify accepts frames with a truncated MAC trailer"
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` = 7.5
- **CWE:** CWE-347
- **Affected:** libparse < 2.3.0. **Patched:** 2.3.0 (commit `b77d210`).
  Published 2025-03-14.
- **Summary:** When the trailer was shorter than 32 bytes, `lp_mac_equal` was
  called with the *short* length, so an attacker who could truncate a frame
  needed to match only the first byte of the MAC to pass verification.
- **Why High:** a low-complexity, network-reachable authentication bypass —
  full integrity loss (`I:H`) — with no confidentiality or availability impact.
  No proof of concept was required: the code path is conclusive on reading.

### 4. GHSA-exmp-0002-mac0 — CVE-2024-90002 — MEDIUM (5.9)

- **Title:** "Compiler-introduced timing leak in lp_mac_equal with Clang -Os"
- **CVSS:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` = 5.9
- **CWE:** CWE-208
- **Affected:** libparse <= 2.2.1 built with Clang 16–18 at `-Os`.
  **Patched:** 2.2.2 (commit `9e04d5c`). Published 2024-10-07.
- **Summary:** Clang compiled the constant-time comparison loop into an early
  exit under `-Os`. A local proof of concept recovered a full 32-byte MAC — and
  so the ability to forge frames — from end-to-end verify timing in about
  40 minutes.
- **Why Medium:** total loss of the secret (`C:H`) but only through a
  high-complexity timing side channel (`AC:H`), and no direct I/A impact. The
  project's convention is to publish `AV:N` even for locally demonstrated
  timing attacks, because verify timing is remotely measurable in principle.

### 5. GHSA-exmp-0001-frme — CVE-2024-90001 — HIGH (8.2)

- **Title:** "Heap buffer overflow in frame header parsing"
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H` = 8.2
- **CWE:** CWE-787, CWE-190
- **Affected:** libparse < 2.2.0. **Patched:** 2.2.0 (commit `41aa0e7`).
  Published 2024-05-20.
- **Summary:** `lp_read_header` multiplied `rec_count` by the record-pointer
  size in a 32-bit integer before allocating the record table, so a large
  `rec_count` wrapped to a small allocation and the following record writes
  overflowed the heap. Reachable from any `lp_frame_decode` caller, including
  parse-server before authentication.
- **Why High:** classic remotely reachable memory-safety bug: reliable crash
  (`A:H`) with possible information leak (`C:L`), low complexity, no
  privileges.

## parse-server advisories

### 6. GHSA-exmp-0006-conn — CVE-2025-90006 — HIGH (8.2)

- **Title:** "Integer overflow in connection buffer sizing"
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H` = 8.2
- **CWE:** CWE-190, CWE-680
- **Affected:** parse-server <= 1.8.0. **Patched:** 1.8.1. Published
  2025-06-11.
- **Summary:** `conn_buf_reserve` in `src/net/buf.c` added the requested size
  to the current offset without an overflow check; a peer could make the
  buffer smaller than the following read. Crash, possible leak of adjacent
  connection state.

---

## Severity calibration takeaways

1. **High (7.5–8.2)** = either a remotely triggerable memory-safety bug in a
   network-facing parser with crash/leak potential (`AC:L`, `A:H`), or an
   authentication/integrity bypass that lets an attacker pass off content the
   key holder never produced (`I:H`) — even with no demonstrated exploit.
2. **Medium (5.3–5.9)** = two recurring shapes: a timing side channel with a
   working local PoC that recovers the whole secret (still Medium because
   `AC:H` and C-only), and an out-of-bounds *read* whose bytes cannot be
   exfiltrated or flip a verify result (`A:L` only).
3. **Low (3.7)** = theoretical design weakness with no known concrete attack.
4. **Full secret recovery does not imply High/Critical.** The gate is attack
   complexity and whether the vector is a side channel.
5. **"Where do the bytes flow / is there an oracle?"** is load-bearing for any
   read/overflow. Replicate that analysis before scoring.
6. **`AV:N` even for local timing demos** — match the convention.
7. **Check for sibling vectors.** The 2.4.1 fix for CVE-2025-90004 was found
   during review of a 2.3.0 change that fixed the *header* bound but not the
   *record* bound. A "fixed" bug may have relatives.
8. **Critical (9.0+) has no published precedent** in this set. A finding that
   would be Critical needs a low-complexity, network-reachable path to secret
   recovery or forgery. Escalate to a human with the vector and reasoning.

## Staleness warnings

- Re-derive this table from the live advisory pages before relying on it.
- CVE-2025-90005 is unpatched by design; do not report it as fixed.
