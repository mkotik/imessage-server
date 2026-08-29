/**
 * Message persistence.
 *
 * The whole batch is applied inside ONE transaction: either every message in it
 * lands or none does. That is what lets the sender treat a 2xx as durable and
 * advance its checkpoint, and lets an interrupted backfill simply resend.
 *
 * Idempotency comes from `messages.message_guid` being the primary key and every
 * write being an upsert. A message re-delivered unchanged updates nothing
 * meaningful; a `revision` batch carrying an edit overwrites the body and bumps
 * `revision`.
 */
import type { Db } from '../shared/db.js';
import { isoToEpochMs, type NormalizedMessage } from '../shared/wire.js';

export interface ApplyResult {
  inserted: number;
  updated: number;
  attachmentsWanted: string[];
}

export interface ApplyOptions {
  deviceId: string;
  /** Attachment guids already stored, so they are not requested again. */
  now?: number;
}

interface Stmts {
  upsertChat: ReturnType<Db['prepare']>;
  touchChatLast: ReturnType<Db['prepare']>;
  upsertHandle: ReturnType<Db['prepare']>;
  upsertParticipant: ReturnType<Db['prepare']>;
  existsMessage: ReturnType<Db['prepare']>;
  insertMessage: ReturnType<Db['prepare']>;
  updateMessage: ReturnType<Db['prepare']>;
  upsertAttachment: ReturnType<Db['prepare']>;
  attachmentState: ReturnType<Db['prepare']>;
  recordBatch: ReturnType<Db['prepare']>;
  batchSeen: ReturnType<Db['prepare']>;
  upsertDevice: ReturnType<Db['prepare']>;
}

let cache: WeakMap<Db, Stmts> = new WeakMap();

function stmts(db: Db): Stmts {
  const hit = cache.get(db);
  if (hit) return hit;
  const s: Stmts = {
    upsertChat: db.prepare(`
      INSERT INTO chats (chat_guid, identifier, service, is_group, display_name, source_row_id, first_seen_at)
      VALUES (@chat_guid, @identifier, @service, @is_group, @display_name, @source_row_id, @now)
      ON CONFLICT(chat_guid) DO UPDATE SET
        identifier   = excluded.identifier,
        service      = excluded.service,
        is_group     = excluded.is_group,
        display_name = COALESCE(excluded.display_name, chats.display_name)`),
    touchChatLast: db.prepare(`
      UPDATE chats SET last_message_at = MAX(COALESCE(last_message_at, 0), @sent_at) WHERE chat_guid = @chat_guid`),
    upsertHandle: db.prepare(`
      INSERT INTO handles (handle, display_name, first_seen_at, updated_at)
      VALUES (@handle, @display_name, @now, @now)
      ON CONFLICT(handle) DO UPDATE SET
        display_name = COALESCE(excluded.display_name, handles.display_name),
        updated_at   = @now`),
    upsertParticipant: db.prepare(`
      INSERT INTO chat_participants (chat_guid, handle) VALUES (@chat_guid, @handle)
      ON CONFLICT(chat_guid, handle) DO NOTHING`),
    existsMessage: db.prepare(`SELECT revision, text FROM messages WHERE message_guid = ?`),
    insertMessage: db.prepare(`
      INSERT INTO messages (
        message_guid, chat_guid, source_row_id, kind, sender_handle, sender_name, is_from_me,
        service, sent_at, delivered_at, read_at, edited_at, text, subject, is_audio,
        has_attachments, balloon_bundle, reply_to_guid, reaction_type, reaction_action,
        reaction_target, group_event, flags, device_id, ingested_at, updated_at, revision
      ) VALUES (
        @message_guid, @chat_guid, @source_row_id, @kind, @sender_handle, @sender_name, @is_from_me,
        @service, @sent_at, @delivered_at, @read_at, @edited_at, @text, @subject, @is_audio,
        @has_attachments, @balloon_bundle, @reply_to_guid, @reaction_type, @reaction_action,
        @reaction_target, @group_event, @flags, @device_id, @now, @now, 1
      )`),
    updateMessage: db.prepare(`
      UPDATE messages SET
        chat_guid = @chat_guid, source_row_id = @source_row_id, kind = @kind,
        sender_handle = @sender_handle,
        sender_name = COALESCE(@sender_name, sender_name),
        is_from_me = @is_from_me, service = @service, sent_at = @sent_at,
        delivered_at = COALESCE(@delivered_at, delivered_at),
        read_at = COALESCE(@read_at, read_at),
        edited_at = COALESCE(@edited_at, edited_at),
        text = @text, subject = @subject, is_audio = @is_audio,
        has_attachments = @has_attachments, balloon_bundle = @balloon_bundle,
        reply_to_guid = @reply_to_guid, reaction_type = @reaction_type,
        reaction_action = @reaction_action, reaction_target = @reaction_target,
        group_event = @group_event, flags = @flags, device_id = @device_id,
        updated_at = @now, revision = revision + 1
      WHERE message_guid = @message_guid`),
    upsertAttachment: db.prepare(`
      INSERT INTO attachments (
        attachment_guid, message_guid, source_row_id, filename, mime_type, uti, size_bytes,
        sha256, is_sticker, is_hidden, state, skipped_reason, first_seen_at
      ) VALUES (
        @attachment_guid, @message_guid, @source_row_id, @filename, @mime_type, @uti, @size_bytes,
        @sha256, @is_sticker, @is_hidden, @state, @skipped_reason, @now
      )
      ON CONFLICT(attachment_guid) DO UPDATE SET
        filename   = COALESCE(excluded.filename, attachments.filename),
        mime_type  = COALESCE(excluded.mime_type, attachments.mime_type),
        uti        = COALESCE(excluded.uti, attachments.uti),
        size_bytes = COALESCE(excluded.size_bytes, attachments.size_bytes),
        sha256     = COALESCE(excluded.sha256, attachments.sha256),
        skipped_reason = excluded.skipped_reason,
        -- never downgrade a stored attachment back to pending
        state = CASE WHEN attachments.state = 'stored' THEN 'stored' ELSE excluded.state END`),
    attachmentState: db.prepare(`SELECT state FROM attachments WHERE attachment_guid = ?`),
    recordBatch: db.prepare(`
      INSERT INTO ingest_batches (batch_id, device_id, phase, first_row_id, last_row_id,
        message_count, inserted, updated, otp_filtered, received_at)
      VALUES (@batch_id, @device_id, @phase, @first_row_id, @last_row_id, @message_count,
        @inserted, @updated, @otp_filtered, @now)
      ON CONFLICT(batch_id) DO NOTHING`),
    batchSeen: db.prepare(`SELECT message_count, inserted, updated, otp_filtered FROM ingest_batches WHERE batch_id = ?`),
    upsertDevice: db.prepare(`
      INSERT INTO devices (device_id, version, last_seen_at, last_phase, last_acked_row_id, backfill_complete, pending_attachments)
      VALUES (@device_id, @version, @now, @phase, @last_row_id, @backfill_complete, @pending)
      ON CONFLICT(device_id) DO UPDATE SET
        version = COALESCE(excluded.version, devices.version),
        last_seen_at = @now,
        last_phase = excluded.last_phase,
        last_acked_row_id = MAX(COALESCE(devices.last_acked_row_id, 0), COALESCE(excluded.last_acked_row_id, 0)),
        backfill_complete = MAX(devices.backfill_complete, excluded.backfill_complete),
        pending_attachments = COALESCE(excluded.pending_attachments, devices.pending_attachments)`),
  };
  cache.set(db, s);
  return s;
}

function jsonOrNull(v: unknown): string | null {
  if (v === undefined || v === null) return null;
  const s = JSON.stringify(v);
  return s && s !== '{}' ? s.slice(0, 4000) : null;
}

/** Look up a previously processed batch. Present ⇒ this is a re-delivery. */
export function findBatch(db: Db, batchId: string): { message_count: number; inserted: number; updated: number; otp_filtered: number } | undefined {
  return stmts(db).batchSeen.get(batchId) as never;
}

/**
 * Apply one batch atomically.
 *
 * `wantedFilter` decides which attachment guids to ask the sender to upload:
 * anything not already in state 'stored'.
 */
export function applyBatch(
  db: Db,
  batch: { batchId: string; deviceId: string; phase: string; range: { firstRowId: number; lastRowId: number } },
  messages: NormalizedMessage[],
  otpFiltered: number,
): ApplyResult {
  // Messages the sender transmitted, including any the OTP filter removed. The
  // sender is acknowledged for what it sent, so a replayed batch reports the
  // same `received` count as the first delivery.
  const receivedCount = messages.length + otpFiltered;
  const s = stmts(db);
  const now = Date.now();
  const result: ApplyResult = { inserted: 0, updated: 0, attachmentsWanted: [] };

  const tx = db.transaction(() => {
    for (const m of messages) {
      const sentAt = isoToEpochMs(m.sentAt);

      s.upsertChat.run({
        chat_guid: m.chat.chatGuid,
        identifier: m.chat.identifier,
        service: m.chat.service,
        is_group: m.chat.isGroup ? 1 : 0,
        display_name: m.chat.displayName ?? null,
        source_row_id: m.chat.chatRowId,
        now,
      });

      if (m.sender.handle) {
        s.upsertHandle.run({ handle: m.sender.handle, display_name: m.sender.displayName ?? null, now });
      }
      for (const p of m.participants) {
        s.upsertHandle.run({ handle: p.handle, display_name: p.displayName ?? null, now });
        s.upsertParticipant.run({ chat_guid: m.chat.chatGuid, handle: p.handle });
      }

      const row = {
        message_guid: m.messageGuid,
        chat_guid: m.chat.chatGuid,
        source_row_id: m.sourceRowId,
        kind: m.kind,
        sender_handle: m.sender.handle ?? null,
        sender_name: m.sender.displayName ?? null,
        is_from_me: m.isFromMe ? 1 : 0,
        service: m.service,
        sent_at: sentAt,
        delivered_at: isoToEpochMs(m.deliveredAt),
        read_at: isoToEpochMs(m.readAt),
        edited_at: isoToEpochMs(m.editedAt),
        text: m.text ?? null,
        subject: m.subject ?? null,
        is_audio: m.isAudioMessage ? 1 : 0,
        has_attachments: m.attachments.length > 0 ? 1 : 0,
        balloon_bundle: m.balloonBundleId ?? null,
        reply_to_guid: m.reply?.threadOriginatorGuid ?? null,
        reaction_type: m.reaction?.type ?? null,
        reaction_action: m.reaction?.action ?? null,
        reaction_target: m.reaction?.targetMessageGuid ?? null,
        group_event: jsonOrNull(m.groupEvent),
        flags: jsonOrNull(m.flags),
        device_id: batch.deviceId,
        now,
      };

      const existing = s.existsMessage.get(m.messageGuid) as { revision: number } | undefined;
      if (existing) {
        s.updateMessage.run(row);
        result.updated++;
      } else {
        s.insertMessage.run(row);
        result.inserted++;
      }

      if (sentAt !== null) s.touchChatLast.run({ chat_guid: m.chat.chatGuid, sent_at: sentAt });

      for (const a of m.attachments) {
        // An attachment the sender will not upload is recorded as skipped so the
        // archive still knows it existed.
        const state = a.willUpload ? 'pending' : 'skipped';
        s.upsertAttachment.run({
          attachment_guid: a.attachmentGuid,
          message_guid: m.messageGuid,
          source_row_id: a.sourceRowId,
          filename: a.filename ?? null,
          mime_type: a.mimeType ?? null,
          uti: a.uti ?? null,
          size_bytes: a.sizeBytes ?? null,
          sha256: a.sha256 ?? null,
          is_sticker: a.isSticker ? 1 : 0,
          is_hidden: a.isHidden ? 1 : 0,
          state,
          skipped_reason: a.skippedReason ?? null,
          now,
        });
        if (a.willUpload) {
          const cur = s.attachmentState.get(a.attachmentGuid) as { state: string } | undefined;
          if (!cur || cur.state !== 'stored') result.attachmentsWanted.push(a.attachmentGuid);
        }
      }
    }

    s.recordBatch.run({
      batch_id: batch.batchId,
      device_id: batch.deviceId,
      phase: batch.phase,
      first_row_id: batch.range.firstRowId,
      last_row_id: batch.range.lastRowId,
      message_count: receivedCount,
      inserted: result.inserted,
      updated: result.updated,
      otp_filtered: otpFiltered,
      now,
    });

    s.upsertDevice.run({
      device_id: batch.deviceId,
      version: null,
      phase: batch.phase,
      last_row_id: batch.range.lastRowId,
      backfill_complete: 0,
      pending: null,
      now,
    });
  });

  tx();
  return result;
}

export function recordHeartbeat(
  db: Db,
  hb: { deviceId: string; version: string; phase: string; lastAckedRowId: number; pendingAttachments: number; backfillComplete: boolean },
): void {
  stmts(db).upsertDevice.run({
    device_id: hb.deviceId,
    version: hb.version,
    phase: hb.phase,
    last_row_id: hb.lastAckedRowId,
    backfill_complete: hb.backfillComplete ? 1 : 0,
    pending: hb.pendingAttachments,
    now: Date.now(),
  });
}

/** Test seam: prepared statements are cached per Db handle. */
export function resetStatementCache(): void {
  cache = new WeakMap();
}
