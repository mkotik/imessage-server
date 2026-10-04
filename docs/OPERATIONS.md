# Operations runbook

Everything here is done over SSH as `ubuntu` on the Oracle VPS. The application
runs as the unprivileged system user `imsg`, which has no login shell.

## Where things live

| Path | Owner / mode | Contents |
|---|---|---|
| `/opt/imessage-server` | `root:root` | source, `dist/`, `node_modules/` |
| `/var/lib/imessage` | `imsg:imsg 0700` | `messages.db`, `tmp/` |
| `/etc/imessage-server` | `root:root 0750` | `secrets.env` (`root:imsg 0640`) |
| `/home/ubuntu/mac-sender-credentials.txt` | `ubuntu 0600` | the Mac's Access service-token pair |

The application directory is deliberately **not** writable by `imsg`. Code cannot
modify itself.

## Units

| Unit | Purpose |
|---|---|
| `imessage-ingest.service` | ingestion API on `127.0.0.1:3100` |
| `imessage-mcp.service` | MCP server on `127.0.0.1:3200` |
| `imessage-backup.service` + `.timer` | nightly `04:30` (+≤15 min jitter) |
| `imessage-restore-check.service` + `.timer` | weekly `Sun 05:30` (+≤30 min) restore drill |

```bash
systemctl status imessage-ingest imessage-mcp
systemctl list-timers 'imessage-*'
journalctl -u imessage-ingest -n 100 --no-pager
```

Logs are structured JSON and are privacy-preserving by construction: a scrubber
caps field sizes so a message body cannot leak, and the authentication vocabulary
is limited to `Authentication succeeded` / `Authentication rejected: missing token`
/ `Authentication rejected: invalid token`. Batch lines look like
`ingested batch: 250 / duplicates: 7 / otp_filtered: 2`.

## Deploy a change

**Push to `main`; the host deploys it within ~3 minutes.** `auto-deploy@imessage-server.timer`
fetches over a read-only deploy key, then as the unprivileged `deploy` user runs
`npm ci --ignore-scripts`, `npm run build` and the full test suite
(`node --test --test-concurrency=1 'dist/test/*.test.js'`) in a scratch directory. Only if all
of that passes does it rsync the build into `/opt/imessage-server` (`root:root`), restart
`imessage-ingest` then `imessage-mcp`, and check `/health` on both. Any failure rolls back to
the previous code and the commit is not retried until a newer one lands.
The pipeline itself is documented in `mkotik/personal-mcp` → `docs/CONVENTIONS.md` → *Deployment*.

```bash
journalctl -u auto-deploy@imessage-server -n 40 --no-pager   # last deploys / failures
sudo cat /var/lib/auto-deploy/imessage-server.deployed       # live commit
sudo FORCE=1 /usr/local/sbin/auto-deploy imessage-server     # deploy now / retry
```

- **Unit files are not installed automatically** (they run as root). A changed unit is logged as
  `NOTE: deploy/<unit> differs from the installed unit`; install it by hand:
  `sudo cp deploy/*.service deploy/*.timer /etc/systemd/system/ && sudo systemctl daemon-reload`.
- **Rollback restores code, not the schema.** `imessage-ingest` applies pending migrations on
  start, so a commit that adds one keeps it even if the deploy is rolled back. Keep migrations
  backward compatible with the previous release.
- `--ignore-scripts` is deliberate: the SQLite driver ships `prebuilds/linux-arm64.node`, but its
  `binding.gyp` makes npm try to compile it, and the box has no toolchain (see below). The test
  suite confirms the prebuilt binary loads before anything goes live.

> **Lockfile trap.** A `package-lock.json` generated on x86 pins arch-specific
> resolution and suppresses the arm64 prebuild, so `npm install` on this VPS
> tries to compile the native SQLite driver and fails with
> `gyp ERR! not found: make`. There is no build toolchain on the box and we do
> not want one. The committed lockfile is **generated on the ARM VPS**. If
> install ever fails that way, delete `package-lock.json` and `node_modules` on
> the VPS and run `npm install` fresh — the prebuilt binary downloads in seconds.

## Run a tool by hand

The secrets file is root-only, so load it as root and then drop privileges the
same way systemd does:

```bash
sudo bash -c 'set -a; . /etc/imessage-server/secrets.env; set +a; \
  export IMSG_DB_PATH=/var/lib/imessage/messages.db IMSG_TMP_DIR=/var/lib/imessage/tmp; \
  exec setpriv --reuid=imsg --regid=imsg --clear-groups \
    /usr/bin/node /opt/imessage-server/dist/src/tools/<tool>.js'
```

`<tool>` is `migrate`, `backup`, `restore`, or `verify-encryption`.

Do **not** use `sudo -u imsg env $(cat secrets.env | xargs)` — the file has
comments and `env` tries to execute them.

## Backups

`backup.ts` does `VACUUM INTO` a temp snapshot (safe on a live WAL database),
seals it with the attachment envelope, PUTs it to `db-backups/<ISO>.db.enc`, and
deletes the temp file. Attachments already live in E2 and are not re-copied.

**Retention is enforced by the bucket, not the client.** The E2 access key
deliberately has no delete permission, so the server *cannot* prune. An iDrive E2
lifecycle rule on the bucket expires objects under the `db-backups/` prefix after
**30 days**. That rule is scoped to that prefix only — a root-scoped rule would
destroy the attachment archive.

### Restore

```bash
... dist/src/tools/restore.js --list          # show available snapshots
... dist/src/tools/restore.js --latest --verify-only
... dist/src/tools/restore.js --key db-backups/<name>.db.enc --out /tmp/restored.db
```

`--verify-only` downloads, decrypts, opens with the key, runs
`PRAGMA integrity_check`, and reports schema version and row counts without
touching the live database. This runs automatically every Sunday. A drill that
passes looks like:

```
{"ok":true,"integrity_check":"ok","schema_version":1,"messages":3,"chats":1,"attachments":1}
```

To actually restore: stop both services, move the current DB aside, restore to
`/var/lib/imessage/messages.db`, `chown imsg:imsg`, start the services.

## Rotating secrets

Edit `/etc/imessage-server/secrets.env` as root, then restart both services.

- **`IMSG_INGEST_TOKEN`** — rotate freely; update the Mac's `IMESSAGE_INGEST_TOKEN`
  to match. Brief 401s in between are retried by the sender.
- **E2 keys** — issue a new key in the E2 console scoped to the one bucket with
  read+write and no delete, swap it in, then revoke the old one.
- **`IMSG_DB_KEY_HEX`** — **destructive if done wrong.** Requires `rekey` on the
  live database plus re-sealing every backup. Do not rotate casually.
- **`IMSG_ATTACHMENT_MASTER_KEY_HEX`** — **effectively unrotatable** once
  attachments exist. Every stored object is derived from it. Changing it makes
  the entire blob archive unreadable.
- **Cloudflare service token** — expires **~2027-08-29**. When it lapses,
  ingestion starts failing at the edge with 403 and the Mac will silently fall
  behind. Regenerate in Zero Trust → Access controls → Service credentials,
  update the pinned client ID in `imessage-mcp`'s sibling unit and on the Mac.

## Adding or retiring a hostname

A hostname must exist in **three** places or it does not work: the tunnel's
published application routes, the Access application's destinations, and the
origin's `IMSG_*_PUBLIC_HOSTNAME` allowlist.

Order matters. **Adding:** Access destination first, then the tunnel route, then
the origin allowlist — otherwise there is a window where the hostname reaches the
origin with no Access in front. **Removing:** tunnel route first, then the Access
destination, then the allowlist.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `Authentication rejected: access invalid token` on every ingest | the verifier is checking the wrong principal. Service-token JWTs carry `common_name`, not `sub`. The ingest verifier must be built with `principal: 'service'`. |
| ingest 403 at the edge | service token expired or the Access policy no longer includes it |
| ingest 401 from the origin | edge auth passed but `IMSG_INGEST_TOKEN` does not match the Mac's |
| any request 403 with a valid identity | `Host` not in the origin allowlist |
| tests SIGSEGV | Node 20. The native driver needs 22+. |
| `sh: tsc: not found` | `npm install` did not complete — see the lockfile trap |
| systemd "Unknown key name StartLimitIntervalSec" | those keys belong in `[Unit]`, not `[Service]` |

## Known limitations

- **iDrive E2 free plan is 10 GB total** and other buckets already use ~950 MB,
  leaving roughly **9 GB** for the entire archive including all attachments. If
  `~/Library/Messages/Attachments/` is larger than that, the plan must be
  upgraded or the archive limited to metadata plus small attachments *before*
  the historical backfill runs.
- **One core, no swap.** Both services carry a hard `MemoryMax`. Ingestion is
  streamed and bounded rather than buffered.
- `src/shared/access.ts` was copied from the Obsidian MCP and has since
  **diverged** — it gained `principal` and `expectedCommonName`. Either back-port
  that to Obsidian or extract a genuinely shared package before a third tenant.
- `_selftest/probe.bin` in the E2 bucket cannot be removed by the service key
  (no delete permission). Clean it up from the console if it bothers you.

## Removing the service

```bash
sudo systemctl disable --now imessage-ingest imessage-mcp \
  imessage-backup.timer imessage-restore-check.timer
sudo rm /etc/systemd/system/imessage-*.service /etc/systemd/system/imessage-*.timer
sudo systemctl daemon-reload
sudo rm -rf /opt/imessage-server /etc/imessage-server
# /var/lib/imessage holds the archive — move it somewhere safe rather than deleting.
```

Then delete the two tunnel routes (DNS is removed automatically), the two Access
applications, and the service token.
