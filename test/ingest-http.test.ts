/**
 * Ingestion service at the HTTP layer: authentication, host validation, payload
 * validation, size limits, the attachment upload path, and idempotent retries.
 *
 * A real node:http server is started on an ephemeral loopback port with a temp
 * encrypted database and an in-memory object store. Cloudflare Access is
 * represented by a stub verifier — the real one is exercised separately against
 * the live endpoint, since a genuine Access assertion cannot be forged locally.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request as httpRequest, type Server } from 'node:http';
import { createHash, randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';

import { createIngestApp } from '../src/ingest/app.js';
import { createLogger } from '../src/shared/logger.js';
import { open as openSealed } from '../src/shared/crypto.js';
import type { IngestConfig } from '../src/shared/config.js';
import type { AccessVerifier } from '../src/shared/access.js';
import { sandbox, makeBatch, makeMessage, makeAttachment, mockStore, TEST_DB_KEY, TEST_MASTER_KEY } from './helpers.js';

const TOKEN = 'test-ingest-token-0123456789abcdef';

function stubVerifier(ok = true, reason: 'missing token' | 'invalid token' = 'missing token'): AccessVerifier {
  return {
    issuer: 'https://example.cloudflareaccess.com',
    jwksUrl: 'https://example.cloudflareaccess.com/cdn-cgi/access/certs',
    async verify() {
      return ok ? { ok: true } : { ok: false, reason };
    },
  } as AccessVerifier;
}

interface Harness {
  url: string;
  db: ReturnType<typeof sandbox>['db'];
  objects: Map<string, Buffer>;
  close(): Promise<void>;
}

async function harness(opts: { accessOk?: boolean } = {}): Promise<Harness> {
  const s = sandbox();
  const tmpDir = join(s.dir, 'tmp');
  mkdirSync(tmpDir, { recursive: true });
  const ms = mockStore();

  const cfg: IngestConfig = {
    storage: { dbPath: s.dbPath, dbKey: TEST_DB_KEY, tmpDir },
    e2: { endpoint: 'http://unused', region: 'x', bucket: 'b', accessKeyId: 'k', secretAccessKey: 's' },
    attachmentMasterKey: TEST_MASTER_KEY,
    logLevel: 'error',
    maxAttachmentBytes: 1024 * 1024,
    host: '127.0.0.1',
    port: 0,
    publicHostnames: ['imessage-ingest.example.com'],
    ingestToken: TOKEN,
    cfTeamDomain: 'https://example.cloudflareaccess.com',
    cfAud: 'aud',
    maxBatchBytes: 256 * 1024,
    maxMessagesPerBatch: 50,
    filterShortcodeSenders: false,
    ingestClientId: undefined,
  };

  const route = createIngestApp({
    cfg,
    db: s.db,
    store: ms.store as never,
    accessVerifier: stubVerifier(opts.accessOk ?? true),
    log: createLogger('test', 'error'),
  });

  const server: Server = createServer((req, res) => {
    void route(req, res).catch(() => {
      if (!res.headersSent) res.writeHead(500).end();
      else res.end();
    });
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const addr = server.address() as { port: number };

  return {
    url: `http://127.0.0.1:${addr.port}`,
    db: s.db,
    objects: ms.objects,
    async close() {
      server.close();
      await once(server, 'close');
      s.cleanup();
    },
  };
}

/** fetch().json() is typed unknown; tests only ever poke at a few known fields. */
type Json = Record<string, any>;
const asJson = async (r: Response): Promise<Json> => (await r.json()) as Json;

const authHeaders = (extra: Record<string, string> = {}): Record<string, string> => ({
  authorization: `Bearer ${TOKEN}`,
  'content-type': 'application/json',
  host: 'imessage-ingest.example.com',
  ...extra,
});

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

test('a batch with no bearer token is rejected', async () => {
  const h = await harness();
  try {
    const r = await fetch(`${h.url}/v1/messages/batch`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', host: 'imessage-ingest.example.com' },
      body: JSON.stringify(makeBatch([])),
    });
    assert.equal(r.status, 401);
    assert.match(r.headers.get('www-authenticate') ?? '', /Bearer/);
  } finally {
    await h.close();
  }
});

test('a wrong bearer token is rejected with 403', async () => {
  const h = await harness();
  try {
    const r = await fetch(`${h.url}/v1/messages/batch`, {
      method: 'POST',
      headers: authHeaders({ authorization: 'Bearer wrong-token-of-the-same-length-xxxx' }),
      body: JSON.stringify(makeBatch([])),
    });
    assert.equal(r.status, 403);
  } finally {
    await h.close();
  }
});

test('a valid token without a Cloudflare Access assertion is rejected', async () => {
  const h = await harness({ accessOk: false });
  try {
    const r = await fetch(`${h.url}/v1/messages/batch`, {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify(makeBatch([])),
    });
    assert.equal(r.status, 401, 'the bearer token alone must not be sufficient');
  } finally {
    await h.close();
  }
});

/**
 * `fetch` refuses to set a Host header, so this uses node:http directly —
 * otherwise the assertion would silently pass against the loopback Host and
 * prove nothing.
 */
function rawRequest(port: number, host: string, body: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        host: '127.0.0.1',
        port,
        path: '/v1/messages/batch',
        method: 'POST',
        headers: {
          host,
          authorization: `Bearer ${TOKEN}`,
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(body),
        },
      },
      (res) => {
        let out = '';
        res.setEncoding('utf8');
        res.on('data', (c) => (out += c));
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body: out }));
      },
    );
    req.on('error', reject);
    req.end(body);
  });
}

test('an unknown Host header is rejected before authentication', async () => {
  const h = await harness();
  try {
    const port = Number(new URL(h.url).port);
    const payload = JSON.stringify(makeBatch([]));

    const evil = await rawRequest(port, 'evil.example.com', payload);
    assert.equal(evil.status, 403);
    assert.match(evil.body, /invalid host/);

    // The published hostname is accepted.
    const good = await rawRequest(port, 'imessage-ingest.example.com', payload);
    assert.equal(good.status, 200);
  } finally {
    await h.close();
  }
});

test('/health answers on loopback without credentials and leaks nothing', async () => {
  const h = await harness();
  try {
    const r = await fetch(`${h.url}/health`);
    assert.equal(r.status, 200);
    const body = await asJson(r);
    assert.equal(body.ok, true);
    assert.ok(!JSON.stringify(body).includes(TOKEN));
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// Batch ingestion
// ---------------------------------------------------------------------------

async function postBatch(h: Harness, batch: unknown, headers: Record<string, string> = {}) {
  return fetch(`${h.url}/v1/messages/batch`, {
    method: 'POST',
    headers: authHeaders(headers),
    body: typeof batch === 'string' ? batch : JSON.stringify(batch),
  });
}

test('a well-formed batch is accepted and persisted', async () => {
  const h = await harness();
  try {
    const msgs = [makeMessage({ text: 'hello there' }), makeMessage({ text: 'second' })];
    const r = await postBatch(h, makeBatch(msgs));
    assert.equal(r.status, 200);
    const body = await asJson(r);
    assert.equal(body.ok, true);
    assert.equal(body.received, 2);
    assert.deepEqual(body.attachments.wanted, []);
    assert.equal((h.db.prepare('SELECT count(*) n FROM messages').get() as { n: number }).n, 2);
  } finally {
    await h.close();
  }
});

test('an empty batch still returns ok so the sender can advance', async () => {
  const h = await harness();
  try {
    const r = await postBatch(h, makeBatch([]));
    assert.equal(r.status, 200);
    assert.equal((await asJson(r)).ok, true);
  } finally {
    await h.close();
  }
});

test('the response always carries an explicit wanted array', async () => {
  const h = await harness();
  try {
    const m = makeMessage();
    m.attachments = [makeAttachment(m.messageGuid)];
    const body = await asJson(await postBatch(h, makeBatch([m])));
    assert.ok(Array.isArray(body.attachments?.wanted), 'omitting wanted makes the sender upload everything');
    assert.deepEqual(body.attachments.wanted, [m.attachments[0]!.attachmentGuid]);
  } finally {
    await h.close();
  }
});

test('re-posting the same batchId is idempotent', async () => {
  const h = await harness();
  try {
    const msgs = [makeMessage({ text: 'retry me' })];
    const batch = makeBatch(msgs);
    const a = await asJson(await postBatch(h, batch));
    const b = await asJson(await postBatch(h, batch));
    assert.equal(a.ok, true);
    assert.equal(b.ok, true);
    assert.equal(b.received, a.received, 'a replay must acknowledge the same count as the original');
    assert.equal((h.db.prepare('SELECT count(*) n FROM messages').get() as { n: number }).n, 1);
  } finally {
    await h.close();
  }
});

test('malformed JSON is rejected with 400', async () => {
  const h = await harness();
  try {
    const r = await postBatch(h, '{not json');
    assert.equal(r.status, 400);
  } finally {
    await h.close();
  }
});

test('a schema-invalid batch is rejected with 400', async () => {
  const h = await harness();
  try {
    for (const bad of [
      {},
      { schemaVersion: 2, batchId: 'b', deviceId: 'd', phase: 'backfill', sentAt: 'x', range: { firstRowId: 1, lastRowId: 2 }, messages: [] },
      { ...makeBatch([]), phase: 'nonsense' },
      { ...makeBatch([]), messages: [{ messageGuid: 'only-a-guid' }] },
      { ...makeBatch([]), range: 'not an object' },
    ]) {
      const r = await postBatch(h, bad);
      assert.equal(r.status, 400, `accepted an invalid batch: ${JSON.stringify(bad).slice(0, 60)}`);
    }
  } finally {
    await h.close();
  }
});

test('an oversized body is rejected with 413 and nothing is persisted', async () => {
  const h = await harness();
  try {
    const huge = makeBatch([makeMessage({ text: 'x'.repeat(150_000) }), makeMessage({ text: 'y'.repeat(150_000) })]);
    const r = await postBatch(h, huge);
    assert.equal(r.status, 413);
    assert.equal((h.db.prepare('SELECT count(*) n FROM messages').get() as { n: number }).n, 0);
  } finally {
    await h.close();
  }
});

test('too many messages in one batch is rejected with 413', async () => {
  const h = await harness();
  try {
    const msgs = Array.from({ length: 60 }, (_, i) => makeMessage({ text: `m${i}` }));
    const r = await postBatch(h, makeBatch(msgs));
    assert.equal(r.status, 413);
  } finally {
    await h.close();
  }
});

test('an OTP message is dropped by the server before persistence', async () => {
  const h = await harness();
  try {
    const good = makeMessage({ text: 'see you at the trailhead' });
    const otp = makeMessage({ text: 'Your verification code is 883122. Do not share this code.' });
    const r = await postBatch(h, makeBatch([good, otp]));
    assert.equal(r.status, 200);

    const rows = h.db.prepare('SELECT text FROM messages').all() as Array<{ text: string }>;
    assert.equal(rows.length, 1);
    assert.equal(rows[0]!.text, 'see you at the trailhead');

    // And the code appears nowhere in the database at all.
    const all = JSON.stringify(h.db.prepare('SELECT * FROM messages').all());
    assert.ok(!all.includes('883122'), 'the OTP leaked into the archive');

    const batch = h.db.prepare('SELECT otp_filtered, message_count FROM ingest_batches').get() as {
      otp_filtered: number;
      message_count: number;
    };
    assert.equal(batch.otp_filtered, 1);
    assert.equal(batch.message_count, 2, 'the acknowledged count must match what the sender transmitted');
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// Attachments
// ---------------------------------------------------------------------------

function metaHeader(o: Record<string, unknown>): string {
  return Buffer.from(JSON.stringify(o), 'utf8').toString('base64');
}

async function ingestOneWithAttachment(h: Harness, bytes: Buffer) {
  const m = makeMessage({ text: 'photo incoming' });
  const a = makeAttachment(m.messageGuid, {
    sizeBytes: bytes.length,
    sha256: createHash('sha256').update(bytes).digest('hex'),
  });
  m.attachments = [a];
  await postBatch(h, makeBatch([m]));
  return { m, a };
}

test('an attachment is stored encrypted and decrypts back to the original bytes', async () => {
  const h = await harness();
  try {
    const bytes = randomBytes(40_000);
    const { m, a } = await ingestOneWithAttachment(h, bytes);

    const r = await fetch(`${h.url}/v1/attachments/${a.attachmentGuid}`, {
      method: 'PUT',
      headers: {
        authorization: `Bearer ${TOKEN}`,
        host: 'imessage-ingest.example.com',
        'x-attachment-meta': metaHeader({
          attachmentGuid: a.attachmentGuid,
          messageGuid: m.messageGuid,
          filename: 'photo.jpg',
          mimeType: 'image/jpeg',
          sizeBytes: bytes.length,
          sha256: a.sha256,
          isSticker: false,
          isHidden: false,
        }),
      },
      body: bytes,
    });
    assert.equal(r.status, 201);

    const row = h.db.prepare('SELECT state, object_key FROM attachments WHERE attachment_guid = ?').get(a.attachmentGuid) as {
      state: string;
      object_key: string;
    };
    assert.equal(row.state, 'stored');
    assert.match(row.object_key, /^attachments\/\d{4}\/\d{2}\/.+\.enc$/);
    assert.ok(!row.object_key.includes('photo.jpg'), 'the original filename leaked into the object key');
    assert.ok(!row.object_key.includes('15550001111'), 'a phone number leaked into the object key');

    const stored = h.objects.get(row.object_key)!;
    assert.ok(stored, 'nothing was uploaded');
    assert.equal(stored.subarray(0, 4).toString('latin1'), 'IMS1');
    assert.ok(!stored.includes(bytes.subarray(0, 64)), 'plaintext found in the stored object');
    assert.deepEqual(openSealed(stored, TEST_MASTER_KEY, row.object_key), bytes);
  } finally {
    await h.close();
  }
});

test('an attachment whose bytes do not match its sha256 is rejected and not stored', async () => {
  const h = await harness();
  try {
    const bytes = randomBytes(4096);
    const { m, a } = await ingestOneWithAttachment(h, bytes);
    const r = await fetch(`${h.url}/v1/attachments/${a.attachmentGuid}`, {
      method: 'PUT',
      headers: {
        authorization: `Bearer ${TOKEN}`,
        host: 'imessage-ingest.example.com',
        'x-attachment-meta': metaHeader({
          attachmentGuid: a.attachmentGuid,
          messageGuid: m.messageGuid,
          sizeBytes: bytes.length,
          sha256: a.sha256,
          isSticker: false,
          isHidden: false,
        }),
      },
      body: randomBytes(4096), // different bytes
    });
    assert.equal(r.status, 400);
    assert.notEqual(
      (h.db.prepare('SELECT state FROM attachments WHERE attachment_guid = ?').get(a.attachmentGuid) as { state: string }).state,
      'stored',
    );
  } finally {
    await h.close();
  }
});

test('re-uploading a stored attachment returns 409, which the sender treats as success', async () => {
  const h = await harness();
  try {
    const bytes = randomBytes(2048);
    const { m, a } = await ingestOneWithAttachment(h, bytes);
    const headers = {
      authorization: `Bearer ${TOKEN}`,
      host: 'imessage-ingest.example.com',
      'x-attachment-meta': metaHeader({
        attachmentGuid: a.attachmentGuid,
        messageGuid: m.messageGuid,
        sizeBytes: bytes.length,
        sha256: a.sha256,
        isSticker: false,
        isHidden: false,
      }),
    };
    assert.equal((await fetch(`${h.url}/v1/attachments/${a.attachmentGuid}`, { method: 'PUT', headers, body: bytes })).status, 201);
    const second = await fetch(`${h.url}/v1/attachments/${a.attachmentGuid}`, { method: 'PUT', headers, body: bytes });
    assert.equal(second.status, 409);
    assert.equal(h.objects.size, 1, 'the object was uploaded twice');
  } finally {
    await h.close();
  }
});

test('an attachment for an unknown message is deferred with 409, not lost', async () => {
  const h = await harness();
  try {
    const bytes = randomBytes(512);
    const r = await fetch(`${h.url}/v1/attachments/orphan-guid`, {
      method: 'PUT',
      headers: {
        authorization: `Bearer ${TOKEN}`,
        host: 'imessage-ingest.example.com',
        'x-attachment-meta': metaHeader({
          attachmentGuid: 'orphan-guid',
          messageGuid: 'never-ingested',
          sizeBytes: bytes.length,
          sha256: createHash('sha256').update(bytes).digest('hex'),
          isSticker: false,
          isHidden: false,
        }),
      },
      body: bytes,
    });
    assert.equal(r.status, 409);
    assert.equal(h.objects.size, 0);
  } finally {
    await h.close();
  }
});

test('an oversized attachment is rejected with 413', async () => {
  const h = await harness();
  try {
    const bytes = randomBytes(2 * 1024 * 1024); // limit is 1 MB in the harness
    const { m, a } = await ingestOneWithAttachment(h, bytes);
    const r = await fetch(`${h.url}/v1/attachments/${a.attachmentGuid}`, {
      method: 'PUT',
      headers: {
        authorization: `Bearer ${TOKEN}`,
        host: 'imessage-ingest.example.com',
        'x-attachment-meta': metaHeader({
          attachmentGuid: a.attachmentGuid,
          messageGuid: m.messageGuid,
          sizeBytes: bytes.length,
          sha256: a.sha256,
          isSticker: false,
          isHidden: false,
        }),
      },
      body: bytes,
    });
    assert.equal(r.status, 413);
    assert.equal(h.objects.size, 0);
  } finally {
    await h.close();
  }
});

test('a missing or malformed X-Attachment-Meta is rejected', async () => {
  const h = await harness();
  try {
    const base = { authorization: `Bearer ${TOKEN}`, host: 'imessage-ingest.example.com' };
    assert.equal((await fetch(`${h.url}/v1/attachments/x`, { method: 'PUT', headers: base, body: 'x' })).status, 400);
    assert.equal(
      (await fetch(`${h.url}/v1/attachments/x`, { method: 'PUT', headers: { ...base, 'x-attachment-meta': 'not-base64-json' }, body: 'x' }))
        .status,
      400,
    );
    // guid in the path must match the metadata
    assert.equal(
      (
        await fetch(`${h.url}/v1/attachments/path-guid`, {
          method: 'PUT',
          headers: {
            ...base,
            'x-attachment-meta': metaHeader({
              attachmentGuid: 'different-guid',
              messageGuid: 'm',
              sizeBytes: 1,
              sha256: 'a'.repeat(64),
              isSticker: false,
              isHidden: false,
            }),
          },
          body: 'x',
        })
      ).status,
      400,
    );
  } finally {
    await h.close();
  }
});

test('HEAD reports whether an attachment is already stored', async () => {
  const h = await harness();
  try {
    const bytes = randomBytes(1024);
    const { m, a } = await ingestOneWithAttachment(h, bytes);
    const head = () =>
      fetch(`${h.url}/v1/attachments/${a.attachmentGuid}`, {
        method: 'HEAD',
        headers: { authorization: `Bearer ${TOKEN}`, host: 'imessage-ingest.example.com' },
      });
    assert.equal((await head()).status, 404);
    await fetch(`${h.url}/v1/attachments/${a.attachmentGuid}`, {
      method: 'PUT',
      headers: {
        authorization: `Bearer ${TOKEN}`,
        host: 'imessage-ingest.example.com',
        'x-attachment-meta': metaHeader({
          attachmentGuid: a.attachmentGuid,
          messageGuid: m.messageGuid,
          sizeBytes: bytes.length,
          sha256: a.sha256,
          isSticker: false,
          isHidden: false,
        }),
      },
      body: bytes,
    });
    assert.equal((await head()).status, 200);
  } finally {
    await h.close();
  }
});

test('heartbeats are accepted and recorded', async () => {
  const h = await harness();
  try {
    const r = await fetch(`${h.url}/v1/heartbeat`, {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify({
        deviceId: 'device-test-0001',
        version: '1.0.0',
        at: new Date().toISOString(),
        phase: 'incremental',
        lastAckedRowId: 4242,
        pendingAttachments: 0,
        backfillComplete: true,
      }),
    });
    assert.equal(r.status, 200);
    const row = h.db.prepare('SELECT last_acked_row_id FROM devices WHERE device_id = ?').get('device-test-0001') as {
      last_acked_row_id: number;
    };
    assert.equal(row.last_acked_row_id, 4242);
  } finally {
    await h.close();
  }
});

test('unknown routes return 404', async () => {
  const h = await harness();
  try {
    assert.equal((await fetch(`${h.url}/v1/nope`, { headers: authHeaders() })).status, 404);
    assert.equal((await fetch(`${h.url}/`, { headers: authHeaders() })).status, 404);
  } finally {
    await h.close();
  }
});
