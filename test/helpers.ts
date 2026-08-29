/**
 * Test helpers.
 *
 * Every message used in the suite is SYNTHETIC. No real iMessage content is
 * committed to this repository, ever.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';

import { openDatabase, type Db } from '../src/shared/db.js';
import { resetStatementCache } from '../src/repo/messages.js';
import type { BatchRequest, NormalizedMessage, AttachmentMetadata } from '../src/shared/wire.js';

export const TEST_DB_KEY = Buffer.from('a'.repeat(64), 'hex');
export const TEST_MASTER_KEY = randomBytes(32);

export interface Sandbox {
  dir: string;
  dbPath: string;
  db: Db;
  cleanup(): void;
}

export function sandbox(): Sandbox {
  const dir = mkdtempSync(join(tmpdir(), 'imsg-test-'));
  const dbPath = join(dir, 'messages.db');
  const db = openDatabase({ path: dbPath, key: TEST_DB_KEY });
  return {
    dir,
    dbPath,
    db,
    cleanup() {
      try {
        db.close();
      } catch {
        /* already closed */
      }
      resetStatementCache();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

let rowId = 1000;

export function makeAttachment(messageGuid: string, over: Partial<AttachmentMetadata> = {}): AttachmentMetadata {
  return {
    attachmentGuid: `att-${randomUUID()}`,
    sourceRowId: rowId++,
    messageGuid,
    filename: 'photo.jpg',
    mimeType: 'image/jpeg',
    uti: 'public.jpeg',
    sizeBytes: 1024,
    sha256: 'a'.repeat(64),
    isSticker: false,
    isHidden: false,
    available: true,
    willUpload: true,
    ...over,
  };
}

export function makeMessage(over: Partial<NormalizedMessage> = {}): NormalizedMessage {
  const guid = over.messageGuid ?? `msg-${randomUUID()}`;
  return {
    schemaVersion: 1,
    source: 'apple_messages',
    messageGuid: guid,
    sourceRowId: rowId++,
    kind: 'message',
    chat: {
      chatGuid: 'chat-alex',
      chatRowId: 1,
      identifier: '+15550001111',
      isGroup: false,
      displayName: 'Alex Rivera',
      service: 'iMessage',
    },
    sender: { handle: '+15550001111', displayName: 'Alex Rivera', isMe: false },
    participants: [{ handle: '+15550001111', displayName: 'Alex Rivera' }],
    sentAt: new Date('2026-07-15T18:30:00Z').toISOString(),
    text: 'Synthetic test message',
    isFromMe: false,
    service: 'iMessage',
    isAudioMessage: false,
    attachments: [],
    flags: {},
    ...over,
  };
}

export function makeBatch(messages: NormalizedMessage[], over: Partial<BatchRequest> = {}): BatchRequest {
  const ids = messages.map((m) => m.sourceRowId);
  return {
    schemaVersion: 1,
    batchId: `batch-${randomUUID()}`,
    deviceId: 'device-test-0001',
    phase: 'backfill',
    sentAt: new Date().toISOString(),
    range: { firstRowId: Math.min(...ids, 0), lastRowId: Math.max(...ids, 0) },
    messages,
    ...over,
  };
}

/** Minimal in-memory ObjectStore for tests — no network, no credentials. */
export function mockStore() {
  const objects = new Map<string, Buffer>();
  let putCalls = 0;
  return {
    objects,
    get putCalls() {
      return putCalls;
    },
    store: {
      async put(key: string, body: Buffer | NodeJS.ReadableStream, _len: number): Promise<void> {
        putCalls++;
        if (Buffer.isBuffer(body)) {
          objects.set(key, body);
          return;
        }
        const chunks: Buffer[] = [];
        for await (const c of body as AsyncIterable<Buffer>) chunks.push(c);
        objects.set(key, Buffer.concat(chunks));
      },
      async get(key: string) {
        const b = objects.get(key);
        if (!b) throw Object.assign(new Error('NoSuchKey'), { name: 'NoSuchKey' });
        const { Readable } = await import('node:stream');
        return Readable.from(b);
      },
      async getBuffer(key: string): Promise<Buffer> {
        const b = objects.get(key);
        if (!b) throw Object.assign(new Error('NoSuchKey'), { name: 'NoSuchKey' });
        return b;
      },
      async head(key: string) {
        const b = objects.get(key);
        return b ? { size: b.length } : null;
      },
      async list(prefix: string) {
        return [...objects.entries()]
          .filter(([k]) => k.startsWith(prefix))
          .map(([key, v]) => ({ key, size: v.length }));
      },
    },
  };
}
