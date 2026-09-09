# parse-server attack surface (example)

Snapshot of `../parse-server` at tag `v1.9.0` (2026-06-30). **Fictional
example content.** Authoritative: `parse-server/README.md`, `SECURITY.md`,
`src/net/*.c`.

## What it is

`example-org/parse-server` is a TCP daemon that accepts PFF frames from
clients, verifies them with libparse under a per-client key, and forwards the
verified records to a backend. It is the realistic **worst-case deployment**
for any libparse bug: an unauthenticated network peer chooses every byte
libparse sees.

## How bytes reach libparse

`src/net/conn.c`:

```c
/* conn_read(): read one length-prefixed message from the socket */
n = read_exact(fd, hdr, 4);
msg_len = be32(hdr);                         /* attacker-controlled */
if (msg_len > CONN_MAX_MSG) return CONN_ERR; /* 8 MiB */
buf = conn_buf_reserve(c, msg_len);          /* src/net/buf.c */
n = read_exact(fd, buf, msg_len);
rc = lp_frame_decode(buf, msg_len, &frame);  /* libparse entry point 1 */
if (rc == LP_OK) rc = lp_frame_verify(frame, c->key);  /* entry point 2 */
```

So for any libparse report ask: is the trigger reachable through
`lp_frame_decode` or `lp_frame_verify` with a caller-supplied `len`? If yes,
the exposure context is **network attacker, no authentication** (`AV:N`,
`PR:N`), because parse-server verifies *after* decoding.

## Exposure contexts for scoring

1. **Direct libparse API caller** — an application feeds libparse bytes from
   wherever it got them. Attacker influence is whatever that app accepts.
2. **Network attacker via parse-server** — attacker-supplied frames hit
   `lp_frame_decode` before any authentication. Usually `AV:N/AC:L/PR:N`.
3. **Local / physical** — same-host side channel, power, fault injection.
   Mostly outside the threat model.

Score the library's realistic worst deployment — normally context 2.

## Security support

parse-server is in the security-support set in **lock-step** with libparse:
its `main` tracks libparse `main`, it builds against libparse versions marked
supported, and a same-CVE advisory is published on parse-server whenever a
libparse advisory publishes. Whether parse-server cuts its own *release* is
VMT discretion (see `process.md`).

parse-server also has first-party attack surface — `src/net/conn.c`,
`src/net/buf.c`, the key store in `src/auth/keystore.c` — with its own
advisory history (see `past-advisories.md`).

## Language bindings

`libparse-python` and `libparse-go` wrap the C library and are also in the
lock-step set. `libparse-go` **must** get a new tagged release whenever libparse
publishes a security release, because its build pins a libparse version.

## Not in the support set

`example-org/parse-playground` (a browser demo that uploads frames to a
hosted parse-server) and `example-org/parse-cli` (example tooling) have **no
security support**. Reports against them get a best-effort redirect. A defect
that traces to libparse itself remains in scope regardless of where the report
arrived.
