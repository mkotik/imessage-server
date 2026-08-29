/**
 * iDrive E2 (S3-compatible) object storage.
 *
 * Everything written here is already sealed by src/shared/crypto.ts, so E2 only
 * ever holds ciphertext. Bucket default encryption is enabled as a second,
 * independent layer, but it is not what protects the data — the master key never
 * leaves the VPS.
 *
 * The access key is scoped to one bucket and deliberately has NO delete
 * permission, so retention is enforced by bucket lifecycle rules rather than by
 * this process. A bug here cannot destroy the archive.
 */
import {
  GetObjectCommand,
  HeadObjectCommand,
  ListObjectsV2Command,
  PutObjectCommand,
  S3Client,
} from '@aws-sdk/client-s3';
import type { Readable } from 'node:stream';
import type { E2Config } from './config.js';

export interface ObjectStore {
  put(key: string, body: Buffer | Readable, contentLength: number, contentType?: string): Promise<void>;
  get(key: string): Promise<Readable>;
  getBuffer(key: string): Promise<Buffer>;
  head(key: string): Promise<{ size: number } | null>;
  list(prefix: string, max?: number): Promise<Array<{ key: string; size: number; modified?: Date }>>;
}

export function createObjectStore(cfg: E2Config): ObjectStore {
  const s3 = new S3Client({
    endpoint: cfg.endpoint,
    region: cfg.region,
    forcePathStyle: true,
    credentials: { accessKeyId: cfg.accessKeyId, secretAccessKey: cfg.secretAccessKey },
  });

  return {
    async put(key, body, contentLength, contentType) {
      await s3.send(
        new PutObjectCommand({
          Bucket: cfg.bucket,
          Key: key,
          Body: body as never,
          ContentLength: contentLength,
          // Always opaque: the plaintext type is recorded in the database, not here.
          ContentType: contentType ?? 'application/octet-stream',
        }),
      );
    },

    async get(key) {
      const r = await s3.send(new GetObjectCommand({ Bucket: cfg.bucket, Key: key }));
      return r.Body as Readable;
    },

    async getBuffer(key) {
      const r = await s3.send(new GetObjectCommand({ Bucket: cfg.bucket, Key: key }));
      return Buffer.from(await (r.Body as { transformToByteArray(): Promise<Uint8Array> }).transformToByteArray());
    },

    async head(key) {
      try {
        const r = await s3.send(new HeadObjectCommand({ Bucket: cfg.bucket, Key: key }));
        return { size: r.ContentLength ?? 0 };
      } catch (err) {
        const name = (err as { name?: string }).name;
        if (name === 'NotFound' || name === 'NoSuchKey') return null;
        throw err;
      }
    },

    async list(prefix, max = 1000) {
      const r = await s3.send(new ListObjectsV2Command({ Bucket: cfg.bucket, Prefix: prefix, MaxKeys: max }));
      return (r.Contents ?? []).map((o) => ({
        key: o.Key ?? '',
        size: o.Size ?? 0,
        ...(o.LastModified ? { modified: o.LastModified } : {}),
      }));
    },
  };
}

/**
 * Deterministic object key for an attachment.
 *
 *   attachments/YYYY/MM/<messageGuid>/<attachmentGuid>.enc
 *
 * Deliberately contains no phone number, contact name, message text or original
 * filename — those are in the encrypted database, not in the object namespace,
 * which E2 can see. GUIDs are opaque Apple identifiers.
 *
 * Being deterministic makes re-upload idempotent: the same attachment always
 * lands on the same key.
 */
export function attachmentObjectKey(messageGuid: string, attachmentGuid: string, sentAtMs: number | null): string {
  const d = sentAtMs && Number.isFinite(sentAtMs) ? new Date(sentAtMs) : new Date(0);
  const yyyy = String(d.getUTCFullYear()).padStart(4, '0');
  const mm = String(d.getUTCMonth() + 1).padStart(2, '0');
  return `attachments/${yyyy}/${mm}/${safeSegment(messageGuid)}/${safeSegment(attachmentGuid)}.enc`;
}

/** Backups live under a separate prefix so lifecycle rules can differ. */
export function backupObjectKey(at: Date = new Date()): string {
  const iso = at.toISOString().replace(/[:.]/g, '-');
  return `db-backups/${iso}.db.enc`;
}

/** Apple GUIDs are UUID-ish, but never trust input that becomes a path. */
function safeSegment(s: string): string {
  const cleaned = s.replace(/[^A-Za-z0-9._-]/g, '_');
  return cleaned.slice(0, 128) || '_';
}
