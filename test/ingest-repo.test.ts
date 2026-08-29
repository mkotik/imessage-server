/**
 * Persistence semantics: dedup, upsert, transactionality, and the `wanted`
 * attachment negotiation the sender depends on.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { applyBatch, findBatch, recordHeartbeat } from '../src/repo/messages.js';
import * as att from '../src/repo/attachments.js';
import { sandbox, makeBatch, makeMessage, makeAttachment } from './helpers.js';

function count(db: ReturnType<typeof sandbox>['db'], table: string): number {
  return (db.prepare(`SELECT count(*) n FROM ${table}`).get() as { n: number }).n;
}

test('a batch inserts messages, chats, handles and participants', () => {
  const s = sandbox();
  try {
    const msgs = [makeMessage({ text: 'one' }), makeMessage({ text: 'two' })];
    const r = applyBatch(s.db, makeBatch(msgs), msgs, 0);
    assert.equal(r.inserted, 2);
    assert.equal(r.updated, 0);
    assert.equal(count(s.db, 'messages'), 2);
    assert.equal(count(s.db, 'chats'), 1);
    assert.equal(count(s.db, 'handles'), 1);
    assert.equal(count(s.db, 'chat_participants'), 1);
  } finally {
    s.cleanup();
  }
});

test('re-delivering the same messages is an upsert, not a duplicate', () => {
  const s = sandbox();
  try {
    const msgs = [makeMessage({ text: 'hello' })];
    applyBatch(s.db, makeBatch(msgs), msgs, 0);
    const second = applyBatch(s.db, makeBatch(msgs), msgs, 0);
    assert.equal(second.inserted, 0);
    assert.equal(second.updated, 1);
    assert.equal(count(s.db, 'messages'), 1);
  } finally {
    s.cleanup();
  }
});

test('a revision batch overwrites the body and bumps the revision counter', () => {
  const s = sandbox();
  try {
    const original = makeMessage({ text: '原 typo' });
    applyBatch(s.db, makeBatch([original]), [original], 0);
    const edited = { ...original, text: 'fixed text', editedAt: new Date().toISOString() };
    applyBatch(s.db, makeBatch([edited], { phase: 'revision' }), [edited], 0);

    const row = s.db
      .prepare('SELECT text, revision, edited_at FROM messages WHERE message_guid = ?')
      .get(original.messageGuid) as { text: string; revision: number; edited_at: number | null };
    assert.equal(row.text, 'fixed text');
    assert.equal(row.revision, 2);
    assert.ok(row.edited_at !== null);
    assert.equal(count(s.db, 'messages'), 1);
  } finally {
    s.cleanup();
  }
});

test('a duplicate batchId is recognised so the batch is not reprocessed', () => {
  const s = sandbox();
  try {
    const msgs = [makeMessage()];
    const batch = makeBatch(msgs);
    assert.equal(findBatch(s.db, batch.batchId), undefined);
    applyBatch(s.db, batch, msgs, 0);
    const seen = findBatch(s.db, batch.batchId);
    assert.ok(seen);
    assert.equal(seen.message_count, 1);
  } finally {
    s.cleanup();
  }
});

test('an empty batch is valid and still records the checkpoint', () => {
  const s = sandbox();
  try {
    const batch = makeBatch([], { range: { firstRowId: 500, lastRowId: 600 } });
    const r = applyBatch(s.db, batch, [], 12);
    assert.equal(r.inserted, 0);
    assert.deepEqual(r.attachmentsWanted, []);
    const seen = findBatch(s.db, batch.batchId);
    assert.equal(seen?.otp_filtered, 12);
    // 0 persisted + 12 filtered = 12 transmitted by the sender.
    assert.equal(seen?.message_count, 12);
    const dev = s.db.prepare('SELECT last_acked_row_id FROM devices WHERE device_id = ?').get(batch.deviceId) as {
      last_acked_row_id: number;
    };
    assert.equal(dev.last_acked_row_id, 600);
  } finally {
    s.cleanup();
  }
});

test('the whole batch is one transaction — a failure rolls everything back', () => {
  const s = sandbox();
  try {
    const good = makeMessage({ text: 'should not persist' });
    // A message whose chat_guid is absurdly typed will violate the STRICT table.
    const bad = makeMessage();
    (bad as unknown as { sourceRowId: unknown }).sourceRowId = { not: 'an integer' };

    assert.throws(() => applyBatch(s.db, makeBatch([good, bad]), [good, bad], 0));
    assert.equal(count(s.db, 'messages'), 0, 'partial batch was persisted');
    assert.equal(count(s.db, 'ingest_batches'), 0);
  } finally {
    s.cleanup();
  }
});

test('attachments are requested once and not re-requested after storage', () => {
  const s = sandbox();
  try {
    const m = makeMessage();
    const a = makeAttachment(m.messageGuid);
    m.attachments = [a];

    const first = applyBatch(s.db, makeBatch([m]), [m], 0);
    assert.deepEqual(first.attachmentsWanted, [a.attachmentGuid]);

    att.markStored(s.db, a.attachmentGuid, {
      objectKey: 'attachments/2026/07/x/y.enc',
      encVersion: 1,
      storedBytes: 2048,
      sha256: 'b'.repeat(64),
      sizeBytes: 1024,
    });

    const second = applyBatch(s.db, makeBatch([m]), [m], 0);
    assert.deepEqual(second.attachmentsWanted, [], 'a stored attachment was requested again');
    assert.ok(att.isStored(s.db, a.attachmentGuid));
  } finally {
    s.cleanup();
  }
});

test('a stored attachment is never downgraded back to pending', () => {
  const s = sandbox();
  try {
    const m = makeMessage();
    const a = makeAttachment(m.messageGuid);
    m.attachments = [a];
    applyBatch(s.db, makeBatch([m]), [m], 0);
    att.markStored(s.db, a.attachmentGuid, {
      objectKey: 'k',
      encVersion: 1,
      storedBytes: 10,
      sha256: 'c'.repeat(64),
      sizeBytes: 5,
    });
    applyBatch(s.db, makeBatch([m]), [m], 0);
    assert.equal(att.getAttachment(s.db, a.attachmentGuid)?.state, 'stored');
  } finally {
    s.cleanup();
  }
});

test('an attachment the sender will not upload is recorded as skipped', () => {
  const s = sandbox();
  try {
    const m = makeMessage();
    const a = makeAttachment(m.messageGuid, { willUpload: false, available: false, skippedReason: 'too_large' });
    m.attachments = [a];
    const r = applyBatch(s.db, makeBatch([m]), [m], 0);
    assert.deepEqual(r.attachmentsWanted, []);
    const row = att.getAttachment(s.db, a.attachmentGuid);
    assert.equal(row?.state, 'skipped');
  } finally {
    s.cleanup();
  }
});

test('attachment bytes are refused until their message has been ingested', () => {
  const s = sandbox();
  try {
    const ok = att.ensureRow(s.db, {
      attachmentGuid: 'a1',
      messageGuid: 'never-seen',
      sizeBytes: 10,
      sha256: 'd'.repeat(64),
      isSticker: false,
      isHidden: false,
    });
    assert.equal(ok, false);
  } finally {
    s.cleanup();
  }
});

test('heartbeats advance the device watermark monotonically', () => {
  const s = sandbox();
  try {
    const hb = {
      deviceId: 'device-test-0001',
      version: '1.0.0',
      phase: 'incremental',
      lastAckedRowId: 900,
      pendingAttachments: 3,
      backfillComplete: true,
    };
    recordHeartbeat(s.db, hb);
    recordHeartbeat(s.db, { ...hb, lastAckedRowId: 100, backfillComplete: false });
    const row = s.db
      .prepare('SELECT last_acked_row_id, backfill_complete FROM devices WHERE device_id = ?')
      .get('device-test-0001') as { last_acked_row_id: number; backfill_complete: number };
    assert.equal(row.last_acked_row_id, 900, 'watermark went backwards');
    assert.equal(row.backfill_complete, 1, 'backfill_complete was unset');
  } finally {
    s.cleanup();
  }
});

test('an interrupted backfill can always be restarted safely', () => {
  const s = sandbox();
  try {
    const all = Array.from({ length: 30 }, (_, i) => makeMessage({ text: `history ${i}` }));
    // First pass delivers 20 and "crashes".
    applyBatch(s.db, makeBatch(all.slice(0, 20)), all.slice(0, 20), 0);
    // Restart re-sends from the beginning.
    applyBatch(s.db, makeBatch(all.slice(0, 15)), all.slice(0, 15), 0);
    applyBatch(s.db, makeBatch(all.slice(15)), all.slice(15), 0);
    assert.equal(count(s.db, 'messages'), 30);
  } finally {
    s.cleanup();
  }
});
