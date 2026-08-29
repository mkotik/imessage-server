/**
 * Attachment persistence: the database row is metadata only. The bytes go to
 * iDrive E2, sealed, and the row records where and how.
 */
import type { Db } from '../shared/db.js';

export interface AttachmentRow {
  attachment_guid: string;
  message_guid: string;
  filename: string | null;
  mime_type: string | null;
  size_bytes: number | null;
  sha256: string | null;
  state: string;
  object_key: string | null;
  enc_version: number | null;
  stored_bytes: number | null;
}

export function getAttachment(db: Db, guid: string): AttachmentRow | undefined {
  return db
    .prepare(
      `SELECT attachment_guid, message_guid, filename, mime_type, size_bytes, sha256,
              state, object_key, enc_version, stored_bytes
         FROM attachments WHERE attachment_guid = ?`,
    )
    .get(guid) as AttachmentRow | undefined;
}

export function isStored(db: Db, guid: string): boolean {
  const r = db.prepare(`SELECT state FROM attachments WHERE attachment_guid = ?`).get(guid) as { state: string } | undefined;
  return r?.state === 'stored';
}

/** Sent time of the owning message; used to build the dated object key. */
export function messageSentAt(db: Db, messageGuid: string): number | null {
  const r = db.prepare(`SELECT sent_at FROM messages WHERE message_guid = ?`).get(messageGuid) as { sent_at: number | null } | undefined;
  return r?.sent_at ?? null;
}

/**
 * Record an attachment that has not been seen in any batch yet. The contract
 * says bytes always arrive after their message, but a sender restart could
 * reorder that; accepting the upload and backfilling metadata is safer than
 * rejecting bytes we will never be offered again.
 */
export function ensureRow(
  db: Db,
  meta: {
    attachmentGuid: string;
    messageGuid: string;
    filename?: string | undefined;
    mimeType?: string | undefined;
    uti?: string | undefined;
    sizeBytes: number;
    sha256: string;
    isSticker: boolean;
    isHidden: boolean;
  },
): boolean {
  const messageExists = db.prepare(`SELECT 1 FROM messages WHERE message_guid = ?`).get(meta.messageGuid);
  if (!messageExists) return false;
  db.prepare(
    `INSERT INTO attachments (attachment_guid, message_guid, filename, mime_type, uti, size_bytes,
        sha256, is_sticker, is_hidden, state, first_seen_at)
     VALUES (@guid, @msg, @filename, @mime, @uti, @size, @sha, @sticker, @hidden, 'pending', @now)
     ON CONFLICT(attachment_guid) DO UPDATE SET
       size_bytes = COALESCE(excluded.size_bytes, attachments.size_bytes),
       sha256     = COALESCE(excluded.sha256, attachments.sha256)`,
  ).run({
    guid: meta.attachmentGuid,
    msg: meta.messageGuid,
    filename: meta.filename ?? null,
    mime: meta.mimeType ?? null,
    uti: meta.uti ?? null,
    size: meta.sizeBytes,
    sha: meta.sha256,
    sticker: meta.isSticker ? 1 : 0,
    hidden: meta.isHidden ? 1 : 0,
    now: Date.now(),
  });
  return true;
}

export function markStored(
  db: Db,
  guid: string,
  info: { objectKey: string; encVersion: number; storedBytes: number; sha256: string; sizeBytes: number },
): void {
  db.prepare(
    `UPDATE attachments
        SET state = 'stored', object_key = @key, enc_version = @ver, stored_bytes = @stored,
            sha256 = @sha, size_bytes = @size, stored_at = @now
      WHERE attachment_guid = @guid`,
  ).run({
    guid,
    key: info.objectKey,
    ver: info.encVersion,
    stored: info.storedBytes,
    sha: info.sha256,
    size: info.sizeBytes,
    now: Date.now(),
  });
}

export function markFailed(db: Db, guid: string): void {
  db.prepare(`UPDATE attachments SET state = 'failed', error_count = error_count + 1 WHERE attachment_guid = ?`).run(guid);
}

export function counts(db: Db): Record<string, number> {
  const rows = db.prepare(`SELECT state, count(*) n FROM attachments GROUP BY state`).all() as Array<{ state: string; n: number }>;
  return Object.fromEntries(rows.map((r) => [r.state, r.n]));
}
