/**
 * Ingestion request handling, with all external dependencies injected.
 *
 * Split out from server.ts so the routing, authentication, validation and
 * persistence paths can be exercised directly in tests against a real HTTP
 * server with a temp database and an in-memory object store — no Cloudflare, no
 * network, no credentials.
 */
import type { IncomingMessage, ServerResponse } from 'node:http';
import { createHash, timingSafeEqual } from 'node:crypto';
import { createReadStream, createWriteStream, statSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { pipeline } from 'node:stream/promises';
import { randomUUID } from 'node:crypto';
import { Transform } from 'node:stream';

import type { AccessVerifier } from '../shared/access.js';
import type { IngestConfig } from '../shared/config.js';
import type { Logger } from '../shared/logger.js';
import type { Db } from '../shared/db.js';
import { attachmentObjectKey, type ObjectStore } from '../shared/e2.js';
import { createSealStream, FORMAT_VERSION, sealedSize } from '../shared/crypto.js';
import { checkOtp } from '../shared/otp-filter.js';
import { batchRequestSchema, attachmentUploadMetaSchema, heartbeatSchema, type NormalizedMessage } from '../shared/wire.js';
import { applyBatch, findBatch, recordHeartbeat } from '../repo/messages.js';
import * as att from '../repo/attachments.js';

export const SERVICE = 'imessage-ingest';
export const VERSION = '0.1.0';

export interface IngestDeps {
  cfg: IngestConfig;
  db: Db;
  store: ObjectStore;
  accessVerifier: AccessVerifier;
  log: Logger;
}

export type IngestHandler = (req: IncomingMessage, res: ServerResponse) => Promise<void>;

export function createIngestApp(deps: IngestDeps): IngestHandler {
  const { cfg, db, store, accessVerifier, log } = deps;

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  function json(res: ServerResponse, status: number, body: unknown): void {
    const data = JSON.stringify(body);
    res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(data) });
    res.end(data);
  }

  function constantTimeEquals(a: string, b: string): boolean {
    const ab = Buffer.from(a, 'utf8');
    const bb = Buffer.from(b, 'utf8');
    if (ab.length !== bb.length) return false;
    return timingSafeEqual(ab, bb);
  }

  /** Reject a Host header we do not serve. Mirrors the Obsidian MCP's posture. */
  function hostAllowed(req: IncomingMessage): boolean {
    const raw = (req.headers.host ?? '').toLowerCase();
    if (!raw) return false;
    const host = raw.replace(/:\d+$/, '');
    if (host === '127.0.0.1' || host === 'localhost' || host === '[::1]') return true;
    return cfg.publicHostnames.includes(host);
  }

  /**
   * Two independent checks, both required:
   *   1. a valid Cloudflare Access JWT (proves it came through Access)
   *   2. the shared ingestion bearer token (proves it is our sender)
   *
   * Permitted log vocabulary only — never the token, never the claims.
   */
  async function authenticate(req: IncomingMessage): Promise<{ ok: true } | { ok: false; status: number; reason: string }> {
    const verdict = await accessVerifier.verify(req);
    if (!verdict.ok) return { ok: false, status: 401, reason: `access ${verdict.reason}` };

    const header = req.headers.authorization;
    if (!header || !header.startsWith('Bearer ')) return { ok: false, status: 401, reason: 'missing bearer token' };
    if (!constantTimeEquals(header.slice(7).trim(), cfg.ingestToken)) {
      return { ok: false, status: 403, reason: 'invalid bearer token' };
    }
    return { ok: true };
  }

  async function readBody(req: IncomingMessage, maxBytes: number): Promise<Buffer | null> {
    const chunks: Buffer[] = [];
    let total = 0;
    for await (const c of req) {
      total += (c as Buffer).length;
      if (total > maxBytes) return null;
      chunks.push(c as Buffer);
    }
    return Buffer.concat(chunks);
  }

  // ---------------------------------------------------------------------------
  // POST /v1/messages/batch
  // ---------------------------------------------------------------------------

  async function handleBatch(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const started = Date.now();
    const raw = await readBody(req, cfg.maxBatchBytes);
    if (raw === null) return json(res, 413, { ok: false, error: 'batch too large' });

    let parsedJson: unknown;
    try {
      parsedJson = JSON.parse(raw.toString('utf8'));
    } catch {
      return json(res, 400, { ok: false, error: 'invalid json' });
    }

    const parsed = batchRequestSchema.safeParse(parsedJson);
    if (!parsed.success) {
      log.warn('batch_rejected', { reason: 'schema', issues: parsed.error.issues.length });
      return json(res, 400, { ok: false, error: 'invalid batch' });
    }
    const batch = parsed.data;

    if (batch.messages.length > cfg.maxMessagesPerBatch) {
      return json(res, 413, { ok: false, error: 'too many messages' });
    }

    // Re-delivery of an already-applied batch: acknowledge without redoing work.
    const seen = findBatch(db, batch.batchId);
    if (seen) {
      const wanted = batch.messages
        .flatMap((m) => m.attachments.filter((a) => a.willUpload).map((a) => a.attachmentGuid))
        .filter((g) => !att.isStored(db, g));
      log.info('batch_duplicate', { batchId: batch.batchId, phase: batch.phase, messages: batch.messages.length, wanted: wanted.length });
      return json(res, 200, { ok: true, received: seen.message_count, attachments: { wanted } });
    }

    // Server-side OTP filter — second, independent layer. The sender already
    // filtered; this exists so a stale or modified sender cannot persist a code.
    const keep: NormalizedMessage[] = [];
    let otpFiltered = 0;
    for (const m of batch.messages) {
      const verdict = checkOtp(
        {
          text: m.text,
          subject: m.subject,
          senderHandle: m.sender.handle,
          counterpartHandles: m.participants.map((p) => p.handle),
          isFromMe: m.isFromMe,
        },
        { filterShortcodeSenders: cfg.filterShortcodeSenders },
      );
      if (verdict.filtered) {
        otpFiltered++;
        continue; // never persisted, never logged
      }
      keep.push(m);
    }
    if (otpFiltered > 0) log.warn('filtered sensitive authentication message', { count: otpFiltered });

    let result;
    try {
      result = applyBatch(db, batch, keep, otpFiltered);
    } catch (err) {
      log.error('batch_persist_failed', { batchId: batch.batchId, error: (err as Error).name });
      return json(res, 500, { ok: false, error: 'persist failed' });
    }

    log.info('batch_ingested', {
      batchId: batch.batchId,
      deviceId: batch.deviceId,
      phase: batch.phase,
      received: batch.messages.length,
      inserted: result.inserted,
      updated: result.updated,
      otp_filtered: otpFiltered,
      attachments_wanted: result.attachmentsWanted.length,
      duration_ms: Date.now() - started,
    });

    json(res, 200, { ok: true, received: batch.messages.length, attachments: { wanted: result.attachmentsWanted } });
  }

  // ---------------------------------------------------------------------------
  // PUT /v1/attachments/{guid}
  // ---------------------------------------------------------------------------

  async function handleAttachmentPut(req: IncomingMessage, res: ServerResponse, guid: string): Promise<void> {
    const started = Date.now();
    const metaHeader = req.headers['x-attachment-meta'];
    if (typeof metaHeader !== 'string') return json(res, 400, { error: 'missing X-Attachment-Meta' });

    let metaJson: unknown;
    try {
      metaJson = JSON.parse(Buffer.from(metaHeader, 'base64').toString('utf8'));
    } catch {
      return json(res, 400, { error: 'invalid X-Attachment-Meta' });
    }
    const parsed = attachmentUploadMetaSchema.safeParse(metaJson);
    if (!parsed.success) return json(res, 400, { error: 'invalid attachment metadata' });
    const meta = parsed.data;

    if (meta.attachmentGuid !== guid) return json(res, 400, { error: 'guid mismatch' });
    if (meta.sizeBytes > cfg.maxAttachmentBytes) return json(res, 413, { error: 'attachment too large' });

    // Already have it → 409, which the sender treats as success.
    if (att.isStored(db, guid)) {
      req.resume();
      return json(res, 409, { error: 'exists' });
    }

    if (!att.ensureRow(db, meta)) {
      // Message not ingested yet. Retryable: the sender will re-offer after the
      // batch lands.
      req.resume();
      log.warn('attachment_orphan', { attachmentGuid: guid, messageGuid: meta.messageGuid });
      return json(res, 409, { error: 'message not yet ingested' });
    }

    const sentAt = att.messageSentAt(db, meta.messageGuid);
    const objectKey = attachmentObjectKey(meta.messageGuid, guid, sentAt);
    const tmpPath = join(cfg.storage.tmpDir, `${randomUUID()}.enc`);

    // The request body is hashed as plaintext in flight and encrypted straight to
    // a temp file. Plaintext is never written to disk.
    const hasher = createHash('sha256');
    let plaintextBytes = 0;
    let tooLarge = false;

    try {
      const counting = new Transform({
        transform(chunk: Buffer, _e, cb) {
          plaintextBytes += chunk.length;
          if (plaintextBytes > cfg.maxAttachmentBytes) {
            tooLarge = true;
            return cb(new Error('too large'));
          }
          hasher.update(chunk);
          cb(null, chunk);
        },
      });

      await pipeline(req, counting, createSealStream(cfg.attachmentMasterKey, objectKey), createWriteStream(tmpPath, { mode: 0o600 }));

      const digest = hasher.digest('hex');
      if (digest.toLowerCase() !== meta.sha256.toLowerCase()) {
        log.warn('attachment_checksum_mismatch', { attachmentGuid: guid });
        return json(res, 400, { error: 'sha256 mismatch' });
      }

      const onDisk = statSync(tmpPath).size;
      const expected = sealedSize(plaintextBytes);
      if (onDisk !== expected) {
        log.error('attachment_size_anomaly', { attachmentGuid: guid, onDisk, expected });
        return json(res, 500, { error: 'internal size mismatch' });
      }

      await store.put(objectKey, createReadStream(tmpPath), onDisk, 'application/octet-stream');
      att.markStored(db, guid, { objectKey, encVersion: FORMAT_VERSION, storedBytes: onDisk, sha256: digest, sizeBytes: plaintextBytes });

      log.info('attachment_stored', {
        attachmentGuid: guid,
        objectKey,
        plaintext_bytes: plaintextBytes,
        stored_bytes: onDisk,
        duration_ms: Date.now() - started,
      });
      json(res, 201, { ok: true });
    } catch (err) {
      if (tooLarge) return json(res, 413, { error: 'attachment too large' });
      att.markFailed(db, guid);
      log.error('attachment_failed', { attachmentGuid: guid, error: (err as Error).name });
      if (!res.headersSent) json(res, 503, { error: 'storage failed' });
    } finally {
      try {
        unlinkSync(tmpPath);
      } catch {
        /* already gone */
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Router
  // ---------------------------------------------------------------------------

  async function route(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', 'http://localhost');
    const path = url.pathname;

    // /health is loopback-only and unauthenticated by design: it is used by
    // systemd and local operators and reveals nothing but liveness.
    if (path === '/health') {
      const localOnly = req.socket.remoteAddress === '127.0.0.1' || req.socket.remoteAddress === '::1';
      if (!localOnly) return json(res, 404, { error: 'not found' });
      return json(res, 200, { ok: true, service: SERVICE, version: VERSION, schema: db.pragma('user_version', { simple: true }) });
    }

    if (!hostAllowed(req)) {
      req.resume();
      return json(res, 403, { error: 'invalid host' });
    }

    const auth = await authenticate(req);
    if (!auth.ok) {
      req.resume();
      log.warn(`Authentication rejected: ${auth.reason}`);
      res.setHeader('www-authenticate', 'Bearer realm="imessage-ingest"');
      return json(res, auth.status, { error: 'unauthorized' });
    }

    if (path === '/v1/messages/batch' && req.method === 'POST') return handleBatch(req, res);

    const m = /^\/v1\/attachments\/([^/]+)$/.exec(path);
    if (m) {
      const guid = decodeURIComponent(m[1]!);
      if (req.method === 'PUT') return handleAttachmentPut(req, res, guid);
      if (req.method === 'HEAD') {
        res.writeHead(att.isStored(db, guid) ? 200 : 404);
        return void res.end();
      }
    }

    if (path === '/v1/heartbeat' && req.method === 'POST') {
      const raw = await readBody(req, 64 * 1024);
      if (raw === null) return json(res, 413, { error: 'too large' });
      let body: unknown;
      try {
        body = JSON.parse(raw.toString('utf8'));
      } catch {
        return json(res, 400, { error: 'invalid json' });
      }
      const hb = heartbeatSchema.safeParse(body);
      if (!hb.success) return json(res, 400, { error: 'invalid heartbeat' });
      recordHeartbeat(db, hb.data);
      log.debug('heartbeat', { deviceId: hb.data.deviceId, phase: hb.data.phase, lastAckedRowId: hb.data.lastAckedRowId });
      return json(res, 200, { ok: true });
    }

    req.resume();
    json(res, 404, { error: 'not found' });
  }


  return route;
}
