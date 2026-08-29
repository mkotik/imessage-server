/**
 * Encrypted database backup to iDrive E2.
 *
 *   node dist/tools/backup.js
 *
 * The snapshot is taken with VACUUM INTO, which is consistent under an active
 * WAL writer, so ingestion does not have to be stopped. The snapshot is already
 * SQLCipher-encrypted with the database key; it is then sealed AGAIN with the
 * attachment master key before upload, so a backup object is useless without
 * both keys and E2 never holds anything readable.
 *
 * Retention is enforced by an E2 bucket lifecycle rule on the `db-backups/`
 * prefix, deliberately NOT by this script: the access key has no delete
 * permission, so a bug here cannot destroy backup history.
 */
import { createReadStream, createWriteStream, mkdirSync, statSync, unlinkSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { pipeline } from 'node:stream/promises';

import { loadAttachmentMasterKey, loadE2Config, loadStorageConfig } from '../shared/config.js';
import { backupTo, openDatabase } from '../shared/db.js';
import { backupObjectKey, createObjectStore } from '../shared/e2.js';
import { createSealStream } from '../shared/crypto.js';

async function main(): Promise<void> {
  const storage = loadStorageConfig();
  const masterKey = loadAttachmentMasterKey();
  const store = createObjectStore(loadE2Config());

  mkdirSync(storage.tmpDir, { recursive: true });
  const snapshot = join(storage.tmpDir, `backup-${randomUUID()}.db`);
  const sealedPath = `${snapshot}.enc`;
  const objectKey = backupObjectKey();

  try {
    const db = openDatabase({ path: storage.dbPath, key: storage.dbKey, migrate: false });
    backupTo(db, snapshot);
    db.close();

    const rawBytes = statSync(snapshot).size;
    await pipeline(createReadStream(snapshot), createSealStream(masterKey, objectKey), createWriteStream(sealedPath, { mode: 0o600 }));
    const sealedBytes = statSync(sealedPath).size;

    await store.put(objectKey, createReadStream(sealedPath), sealedBytes, 'application/octet-stream');

    process.stdout.write(
      JSON.stringify({ ok: true, objectKey, snapshot_bytes: rawBytes, uploaded_bytes: sealedBytes, at: new Date().toISOString() }) + '\n',
    );
  } finally {
    for (const f of [snapshot, sealedPath]) {
      try {
        unlinkSync(f);
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
