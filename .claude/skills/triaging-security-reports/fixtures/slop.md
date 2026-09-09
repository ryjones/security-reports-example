# [libparse] Critical Heap Buffer Overflow in Frame Decoding (CWE-122 / CWE-787) — Remote Code Execution

**Severity: CRITICAL (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8)**

## Summary

Hello libparse Security Team,

During an automated audit of the libparse frame-parsing library, I identified a **critical heap-based buffer overflow** in the fast-path frame decoder that allows a remote unauthenticated attacker to achieve **arbitrary code execution** by submitting a crafted frame. This is a textbook out-of-bounds write (CWE-787) compounded by an unchecked heap reallocation (CWE-122). Given libparse's role as the authentication layer in parse-server, the blast radius is enormous — every parse-server deployment on the internet is exploitable pre-authentication.

I am reporting this responsibly and would appreciate acknowledgement for the CVE.

## Affected Component

- **File:** `src/frame/decode_fast.c`
- **Functions:** `lp_frame_unpack_ext()`, `lp_frame_grow_records()`, and `lp_secure_realloc()`
- **Version:** libparse 2.4.1 (latest) and all prior releases

## Technical Details

The decoding entry point calls `lp_frame_unpack_ext()`, which parses the incoming frame into an intermediate record buffer. The length of this buffer is derived from a **client-controlled** extension field in the frame header rather than from the compile-time `LP_MAX_RECORDS` constant. When the attacker inflates this field, `lp_frame_grow_records()` computes a copy length larger than the destination allocation.

Crucially, the code then calls `lp_secure_realloc()` to grow the buffer, but the return value is never checked and the **old pointer is reused after the realloc**, so the subsequent `memcpy` writes decoded records past the end of the heap chunk. Because the overflow content is directly derived from attacker bytes, this is a fully controlled write primitive — trivially escalated to RCE via heap grooming of the adjacent `lp_frame` vtable.

## Proof of Concept

```c
// PoC — overflow triggered during decoding
#include <libparse/frame.h>
#include <string.h>

int main(void) {
    uint8_t frame[256];
    memset(frame, 0x41, sizeof(frame));
    frame[0] = 'P'; frame[1] = 'F'; frame[2] = 'F'; frame[3] = 0x01;
    frame[5] = 0xFF; frame[6] = 0xFF;  // inflated extension length -> unpack writes OOB

    lp_frame *out = NULL;
    lp_frame_unpack_ext(frame, sizeof(frame), &out, LP_EXT_FAST);  // <-- heap corruption here
    return 0;
}
```

Running under ASan reliably reports a `heap-buffer-overflow WRITE of size 8` originating in `lp_frame_grow_records`.

## Impact

- Remote code execution on any parse-server instance.
- Complete compromise of confidentiality, integrity, and availability.

## Suggested Fix

Validate the extension length against `LP_MAX_RECORDS` before unpacking, and check the `lp_secure_realloc()` return value before dereferencing.

Please confirm receipt and expected CVE timeline. Happy to provide further PoC refinement.

Best regards,
A. Researcher

---

## GROUND TRUTH (do not show to triage agents)

**Verdict: FABRICATED / AI-slop. Close as invalid — `status:wontfix`, close reason *not planned*.**

This is LLM-generated bug-bounty spam. None of the named code exists:

- `src/frame/decode_fast.c` — **does not exist**. The real decoder is `src/frame/decode.c` (`lp_frame_decode`, `lp_read_header`, `lp_read_record`).
- `lp_frame_unpack_ext()`, `lp_frame_grow_records()`, `lp_secure_realloc()`, `LP_EXT_FAST` — **none exist anywhere in the tree** (grep returns nothing). The only allocator helpers are `lp_malloc` / `lp_secure_free` in `src/mem/mem.c`.

The call-flow narrative is incoherent with reality: the frame header has no "extension length" field (magic, version, varint `rec_count`, records, 32-byte MAC — see `docs/format.md`); `rec_count` is bounded by `LP_MAX_RECORDS` in `lp_read_header`; and the real decode path does no per-call realloc of a record buffer. The CVSS 9.8 / RCE / "every parse-server exploitable" framing is unsupported boilerplate.

Correct disposition: reply that the referenced files/functions do not exist and the described mechanism is not how libparse decoding works; close as invalid. `status:wontfix`. Do NOT spend a reproduction cycle building the PoC — it references nonexistent symbols and will not compile.

Verification: `grep -rn` for each symbol in `../libparse/src` and `../libparse/include` returns empty; `test -e src/frame/decode_fast.c` fails.
