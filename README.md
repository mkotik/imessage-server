# imessage-server

The VPS side of a personal iMessage archive. It receives message batches and
attachments from the Mac sender ([`imessage-sender`](https://github.com/mkotik/imessage-sender)),
stores them in an **encrypted** SQLite database, encrypts attachments client-side
before putting them in iDrive E2, and exposes the archive to AI agents through a
dedicated **MCP server**.

This is an **archive, not a mirror**. Once a message is ingested it is retained
indefinitely, even if it is later deleted from the Mac, iPhone, or iCloud.

```
Mac Messages → imessage-sender → HTTPS → Cloudflare Access
                                              ↓
                             imessage-ingest.example.com
                                              ↓ (tunnel)
                              ingestion service · 127.0.0.1:3100
                                              ↓
                          encrypted SQLite  +  encrypted blobs → iDrive E2
                                              ↓
                                 MCP server · 127.0.0.1:3200
                                              ↓ (tunnel)
                                  imessage.example.com
                                              ↓
                                    Claude / other MCP clients
```

**No inbound ports are opened on the VPS.** Both services bind to loopback only;
Cloudflare Tunnel makes outbound connections and is the sole external path.

---

## Two services, two trust models

| | Ingestion | MCP |
|---|---|---|
| Hostname | `imessage-ingest.example.com` | `imessage.example.com` |
| Bind | `127.0.0.1:3100` | `127.0.0.1:3200` |
| Caller | the Mac sender (machine-to-machine) | me, through an AI client |
| Edge auth | Access **service token** | Access **Managed OAuth**, owner-only |
| Origin auth | Access JWT (`common_name` pinned) **and** a bearer secret | Access JWT (`sub` required) |
| DB handle | read/write | **read-only** |

Both layers are enforced independently. The origin never assumes that traffic
arriving from the tunnel is trustworthy — it verifies the Cloudflare Access JWT
itself against the account JWKS, checks the audience, and checks the `Host`
header against an explicit allowlist. A valid service token with no bearer
secret is rejected `401`; a valid bearer with no service token never gets past
the edge.

---

## Layout

```
src/
  shared/    access.ts config.ts crypto.ts db.ts e2.ts logger.ts
             otp-filter.ts schema.ts wire.ts
  repo/      messages.ts attachments.ts queries.ts
  ingest/    app.ts (all routing, injectable)  server.ts (bootstrap)
  mcp/       server.ts (five tools)
  tools/     migrate.ts backup.ts restore.ts verify-encryption.ts
test/        78 tests — synthetic data only
deploy/      systemd units
docs/        OPERATIONS.md
```

`src/ingest/app.ts` exports `createIngestApp({cfg, db, store, accessVerifier, log})`
so the whole HTTP surface can be tested against a real socket with injected
dependencies. `server.ts` is a thin bootstrap.

---

## Encryption

**The database.** `better-sqlite3-multiple-ciphers` in SQLCipher mode. The key is
32 random bytes held in `/etc/imessage-server/secrets.env` (`root:imsg 0640`),
which systemd reads as root before dropping to the `imsg` user. The key is never
in Git, never in the database directory, and never logged.

**Attachments.** Encrypted on the VPS *before* upload, so iDrive E2 only ever
holds ciphertext. AES-256-GCM with a per-object key derived by HKDF-SHA256 from
a master secret and the object key itself, which binds the ciphertext to its
location — moving an object to a different key makes it undecryptable. Envelope:

```
"IMS1" | version(1) | salt(16) | nonce(12) | ciphertext | tag(16)
        └──────── 36-byte header, used verbatim as GCM AAD ────────┘
```

E2's own server-side encryption is additive and is not relied upon.

**Object keys leak nothing**: `attachments/YYYY/MM/<message-guid>/<attachment-guid>.enc`
— no phone numbers, names, message text, or original filenames.

`npm run verify-encryption` runs nine checks that *demonstrate* this rather than
asserting it: the raw file header is random, plaintext canaries are absent from
the raw bytes, opening without the key fails with `file is not a database`,
tampered ciphertext is rejected, and a live E2 object round-trips.

---

## OTP protection

The Mac sender filters authentication codes before transmission. The server runs
a **second, independent** filter (`src/shared/otp-filter.ts`, copied verbatim from
the sender) and drops matches *before* persistence. The rejected text is never
logged and never written — logs say only `filtered sensitive authentication message`.

One deliberate divergence: short-code-sender filtering is **off** by default
server-side (`IMSG_FILTER_SHORTCODE_SENDERS=false`). Blanket-dropping every
5–6 digit sender would silently discard legitimate automated mail that the Mac
chose to forward. Content-based OTP detection still applies to everything.

---

## MCP tools

Five, deliberately: `search_messages`, `get_conversation`, `get_recent_messages`,
`get_messages_since`, `get_attachment`.

Search is SQLite FTS5 over an external-content table kept current by triggers,
with user input neutralised so FTS operators cannot be injected. Date filters and
conversation-name resolution are built in, so *"what did Alex say about Yosemite
last month"* is a single call.

`get_attachment` fetches from E2, decrypts **on the VPS**, and returns bytes
inline. It never generates a public E2 URL. Anything over
`IMSG_MAX_INLINE_ATTACHMENT_BYTES` (default 5 MB) returns metadata only.

Outbound sending is not implemented. The `outbox` table exists but is unused.

---

## Quick start

```bash
npm install          # on the target arch — see the lockfile note in docs/OPERATIONS.md
npm run build
npm test             # 78 tests; requires Node >= 22
npm run migrate
```

Requires **Node 22+**. The native SQLite driver segfaults on Node 20.

Configuration is environment-only; see `.env.example` for the variable names.
It contains no values and never should.

Operational runbook — deploy, restart, rotate, back up, restore, troubleshoot —
is in [`docs/OPERATIONS.md`](docs/OPERATIONS.md).
