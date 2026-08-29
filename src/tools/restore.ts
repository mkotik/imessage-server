/**
 * Restore a backup from iDrive E2 and prove it is usable.
 *
 *   node dist/tools/restore.js --list
 *   node dist/tools/restore.js --key db-backups/<iso>.db.enc --out /var/lib/imessage/restored.db
 *   node dist/tools/restore.js --latest --verify-only
 *
 * `--verify-only` restores to a temp file, opens it with the database key,
 * checks integrity and row counts, then deletes it. That is the drill to run on
 * a schedule: a backup nobody has restored is a hypothesis, not a backup.
 *
 * This never overwrites an existing file; pick a fresh --out path and swap it in
 * deliberately.
 */
import { createWriteStream, existsSync, mkdirSync, statSync, unlinkSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { pipeline } from 'node:stream/promises';
import { Readable } from 'node:stream';

import { loadAttachmentMasterKey, loadE2Config, loadStorageConfig } from '../shared/config.js';
import { openDatabase, schemaVersion } from '../shared/db.js';
import { createObjectStore } from '../shared/e2.js';
import { createOpenStream } from '../shared/crypto.js';

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : undefined;
}
const flag = (name: string): boolean => process.argv.includes(`--${name}`);

async function main(): Promise<void> {
  const storage = loadStorageConfig();
  const store = createObjectStore(loadE2Config());
  const masterKey = loadAttachmentMasterKey();

  if (flag('list')) {
    const objects = (await store.list('db-backups/', 1000)).sort((a, b) => a.key.localeCompare(b.key));
    process.stdout.write(JSON.stringify({ count: objects.length, backups: objects }, null, 2) + '\n');
    return;
  }

  let key = arg('key');
  if (!key && flag('latest')) {
    const objects = await store.list('db-backups/', 1000);
    if (objects.length === 0) throw new Error('no backups found');
    key = objects.sort((a, b) => a.key.localeCompare(b.key))[objects.length - 1]!.key;
  }
  if (!key) throw new Error('specify --key <objectKey>, or --latest, or --list');

  const verifyOnly = flag('verify-only');
  mkdirSync(storage.tmpDir, { recursive: true });
  const out = verifyOnly ? join(storage.tmpDir, `restore-${randomUUID()}.db`) : arg('out');
  if (!out) throw new Error('specify --out <path> (or use --verify-only)');
  if (!verifyOnly && existsSync(out)) throw new Error(`refusing to overwrite existing file: ${out}`);

  try {
    const sealed = await store.get(key);
    await pipeline(Readable.from(sealed), createOpenStream(masterKey, key), createWriteStream(out, { mode: 0o600 }));

    // Prove the restored file is a working database, not just bytes on disk.
    const db = openDatabase({ path: out, key: storage.dbKey, readonly: true, migrate: false });
    const integrity = db.pragma('integrity_check', { simple: true });
    const version = schemaVersion(db);
    const counts = {
      messages: (db.prepare('SELECT count(*) n FROM messages').get() as { n: number }).n,
      chats: (db.prepare('SELECT count(*) n FROM chats').get() as { n: number }).n,
      attachments: (db.prepare('SELECT count(*) n FROM attachments').get() as { n: number }).n,
    };
    db.close();

    const okIntegrity = integrity === 'ok';
    process.stdout.write(
      JSON.stringify(
        {
          ok: okIntegrity,
          objectKey: key,
          restored_to: verifyOnly ? '(temporary, deleted)' : out,
          bytes: statSync(out).size,
          integrity_check: integrity,
          schema_version: version,
          ...counts,
        },
        null,
        2,
      ) + '\n',
    );
    if (!okIntegrity) process.exitCode = 1;
  } finally {
    if (verifyOnly) {
      try {
        unlinkSync(out);
      } catch {
        /* already gone */
      }
    }
  }
}

main().catch((err) => {
  process.stderr.write(JSON.stringify({ ok: false, error: (err as Error).message }) + '\n');
  process.exit(1);
});
