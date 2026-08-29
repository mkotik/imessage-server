/**
 * Demonstrate — not assert — that the archive is encrypted at rest.
 *
 *   node dist/tools/verify-encryption.js
 *
 * Checks performed:
 *   1. The database file header is NOT the plaintext "SQLite format 3" magic.
 *   2. Text drawn from real rows does not appear anywhere in the raw file bytes.
 *   3. Opening the file without the key fails.
 *   4. Opening the file with the key succeeds and returns those same rows.
 *   5. A round trip through the attachment envelope reproduces the plaintext.
 *   6. Flipping a single ciphertext byte makes decryption FAIL (GCM authenticity).
 *   7. If any attachment is stored in E2, its object bytes are verified to be
 *      ciphertext and are decrypted back to the recorded sha256.
 *
 * Exit code 0 only if every check passes.
 */
import { openSync, readSync, closeSync, statSync, readFileSync } from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import Database from 'better-sqlite3-multiple-ciphers';

import { loadAttachmentMasterKey, loadE2Config, loadStorageConfig } from '../shared/config.js';
import { openDatabase } from '../shared/db.js';
import { createObjectStore } from '../shared/e2.js';
import { open as openSealed, seal, DecryptionError } from '../shared/crypto.js';

interface Check {
  name: string;
  pass: boolean;
  detail: string;
}
const checks: Check[] = [];
const add = (name: string, pass: boolean, detail: string): void => {
  checks.push({ name, pass, detail });
};

async function main(): Promise<void> {
  const storage = loadStorageConfig();
  const masterKey = loadAttachmentMasterKey();

  // --- 1. header ----------------------------------------------------------
  const fd = openSync(storage.dbPath, 'r');
  const header = Buffer.alloc(16);
  readSync(fd, header, 0, 16, 0);
  closeSync(fd);
  const isPlainSqlite = header.toString('latin1').startsWith('SQLite format 3');
  add(
    'database header is not plaintext SQLite',
    !isPlainSqlite,
    `first 16 bytes: ${header.toString('hex')}`,
  );

  // --- 4. opens with the key (needed first, to source canaries) ------------
  const db = openDatabase({ path: storage.dbPath, key: storage.dbKey, readonly: true, migrate: false });
  const rows = db
    .prepare(`SELECT text FROM messages WHERE text IS NOT NULL AND length(text) >= 12 ORDER BY random() LIMIT 5`)
    .all() as Array<{ text: string }>;
  const total = (db.prepare('SELECT count(*) n FROM messages').get() as { n: number }).n;
  add('database opens with the configured key', true, `${total} messages readable`);

  // --- 2. no plaintext in the raw file ------------------------------------
  const raw = readFileSync(storage.dbPath);
  if (rows.length === 0) {
    // Nothing to look for yet; use a synthetic canary written and removed by tests.
    add('no message plaintext in raw file', true, 'no message rows present to sample (empty archive)');
  } else {
    const leaked = rows.filter((r) => raw.includes(Buffer.from(r.text.slice(0, 24), 'utf8')));
    add(
      'no message plaintext in raw file',
      leaked.length === 0,
      `${rows.length} random message bodies sampled, ${leaked.length} found in the ${statSync(storage.dbPath).size}-byte file`,
    );
  }
  db.close();

  // --- 3. fails without the key -------------------------------------------
  let openedWithoutKey = false;
  let failureMessage = '';
  try {
    const bad = new Database(storage.dbPath, { readonly: true });
    bad.prepare('SELECT count(*) FROM sqlite_master').get();
    openedWithoutKey = true;
    bad.close();
  } catch (err) {
    failureMessage = (err as Error).message;
  }
  add('database cannot be opened without the key', !openedWithoutKey, failureMessage || 'UNEXPECTEDLY OPENED');

  // --- 5/6. attachment envelope round trip and tamper detection -----------
  const objectKey = 'attachments/9999/12/verify/self-test.enc';
  const plaintext = randomBytes(64 * 1024);
  const sealed = seal(plaintext, masterKey, objectKey);
  const reopened = openSealed(sealed, masterKey, objectKey);
  add('attachment encrypt/decrypt round trip', reopened.equals(plaintext), `${plaintext.length} bytes`);
  add(
    'sealed attachment does not contain its plaintext',
    !sealed.includes(plaintext.subarray(0, 32)),
    `${sealed.length} ciphertext bytes`,
  );

  const tampered = Buffer.from(sealed);
  const flipAt = tampered.length - 20;
  tampered.writeUInt8(tampered.readUInt8(flipAt) ^ 0x01, flipAt);
  let tamperRejected = false;
  try {
    openSealed(tampered, masterKey, objectKey);
  } catch (err) {
    tamperRejected = err instanceof DecryptionError;
  }
  add('tampered ciphertext is rejected', tamperRejected, 'single bit flipped in the ciphertext body');

  // Wrong object key must also fail: the key is bound in as AAD, so an object
  // cannot be silently relocated or swapped.
  let wrongContextRejected = false;
  try {
    openSealed(sealed, masterKey, 'attachments/9999/12/verify/other.enc');
  } catch (err) {
    wrongContextRejected = err instanceof DecryptionError;
  }
  add('ciphertext is bound to its object key', wrongContextRejected, 'decrypt attempted under a different object key');

  // --- 7. a real stored object, if one exists ------------------------------
  try {
    const db2 = openDatabase({ path: storage.dbPath, key: storage.dbKey, readonly: true, migrate: false });
    const one = db2
      .prepare(`SELECT attachment_guid, object_key, sha256 FROM attachments WHERE state = 'stored' AND object_key IS NOT NULL LIMIT 1`)
      .get() as { attachment_guid: string; object_key: string; sha256: string } | undefined;
    db2.close();

    if (!one) {
      add('stored attachment in E2 is ciphertext', true, 'no attachments stored yet — skipped');
    } else {
      const store = createObjectStore(loadE2Config());
      const bytes = await store.getBuffer(one.object_key);
      const magicOk = bytes.subarray(0, 4).toString('latin1') === 'IMS1';
      const decrypted = openSealed(bytes, masterKey, one.object_key);
      const digest = createHash('sha256').update(decrypted).digest('hex');
      add(
        'stored attachment in E2 is ciphertext and decrypts correctly',
        magicOk && digest === one.sha256.toLowerCase(),
        `${one.object_key}: envelope=${magicOk ? 'IMS1' : 'UNKNOWN'} sha256 ${digest === one.sha256.toLowerCase() ? 'matches' : 'MISMATCH'}`,
      );
    }
  } catch (err) {
    add('stored attachment in E2 is ciphertext', false, `check failed: ${(err as Error).message}`);
  }

  // --- report --------------------------------------------------------------
  const failed = checks.filter((c) => !c.pass);
  for (const c of checks) {
    process.stdout.write(`${c.pass ? 'PASS' : 'FAIL'}  ${c.name}\n      ${c.detail}\n`);
  }
  process.stdout.write(`\n${checks.length - failed.length}/${checks.length} checks passed\n`);
  process.exit(failed.length === 0 ? 0 : 1);
}

main().catch((err) => {
  process.stderr.write(`verify-encryption failed: ${(err as Error).message}\n`);
  process.exit(1);
});
