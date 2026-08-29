/**
 * Encrypted database: the file must be unreadable without the key, and the
 * schema must be idempotently migratable.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import Database from 'better-sqlite3-multiple-ciphers';

import { openDatabase, runMigrations, schemaVersion, DbKeyError } from '../src/shared/db.js';
import { LATEST_VERSION } from '../src/shared/schema.js';
import { applyBatch } from '../src/repo/messages.js';
import { sandbox, makeBatch, makeMessage, TEST_DB_KEY } from './helpers.js';

const CANARY = 'ZQXJV-canary-plaintext-marker-9184';

test('a new database reaches the latest schema version', () => {
  const s = sandbox();
  try {
    assert.equal(schemaVersion(s.db), LATEST_VERSION);
  } finally {
    s.cleanup();
  }
});

test('migrations are idempotent', () => {
  const s = sandbox();
  try {
    assert.equal(runMigrations(s.db), LATEST_VERSION);
    assert.equal(runMigrations(s.db), LATEST_VERSION);
  } finally {
    s.cleanup();
  }
});

test('the raw database file contains no plaintext message text', () => {
  const s = sandbox();
  try {
    applyBatch(
      s.db,
      makeBatch([makeMessage({ text: CANARY })]),
      [makeMessage({ text: CANARY })],
      0,
    );
    s.db.pragma('wal_checkpoint(TRUNCATE)');
    const raw = readFileSync(s.dbPath);
    assert.ok(!raw.includes(Buffer.from(CANARY, 'utf8')), 'canary found in the raw database file');
    // And the header is not the plaintext SQLite magic.
    assert.ok(!raw.subarray(0, 16).toString('latin1').startsWith('SQLite format 3'));
  } finally {
    s.cleanup();
  }
});

test('the database cannot be opened without the key', () => {
  const s = sandbox();
  try {
    s.db.close();
    assert.throws(() => {
      const bad = new Database(s.dbPath, { readonly: true });
      bad.prepare('SELECT count(*) FROM sqlite_master').get();
    });
  } finally {
    s.cleanup();
  }
});

test('the database cannot be opened with the wrong key', () => {
  const s = sandbox();
  try {
    s.db.close();
    assert.throws(
      () => openDatabase({ path: s.dbPath, key: randomBytes(32), migrate: false }),
      DbKeyError,
    );
  } finally {
    s.cleanup();
  }
});

test('the database reopens and reads correctly with the right key', () => {
  const s = sandbox();
  try {
    const m = makeMessage({ text: 'persisted across reopen' });
    applyBatch(s.db, makeBatch([m]), [m], 0);
    s.db.close();

    const again = openDatabase({ path: s.dbPath, key: TEST_DB_KEY, readonly: true, migrate: false });
    const row = again.prepare('SELECT text FROM messages WHERE message_guid = ?').get(m.messageGuid) as { text: string };
    assert.equal(row.text, 'persisted across reopen');
    again.close();
  } finally {
    s.cleanup();
  }
});

test('a short key is refused outright', () => {
  const s = sandbox();
  try {
    assert.throws(() => openDatabase({ path: s.dbPath, key: randomBytes(16) }), DbKeyError);
  } finally {
    s.cleanup();
  }
});

test('foreign keys are enforced', () => {
  const s = sandbox();
  try {
    assert.throws(() =>
      s.db
        .prepare(
          `INSERT INTO attachments (attachment_guid, message_guid, state, first_seen_at)
           VALUES ('orphan', 'no-such-message', 'pending', 0)`,
        )
        .run(),
    );
  } finally {
    s.cleanup();
  }
});
