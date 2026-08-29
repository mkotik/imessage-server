/**
 * Wire types and validation for the ingestion contract.
 *
 * These MUST stay byte-compatible with `docs/receiver-api.md` in
 * github.com/mkotik/imessage-sender — that repo is the source of truth. The
 * types below are copied from the sender's `src/transport/types.ts`; the zod
 * schemas exist because the sender is a client and every field it sends is
 * untrusted input here.
 */
import { z } from 'zod';

export const SCHEMA_VERSION = 1 as const;

/** Reasonable upper bounds so a malformed payload cannot exhaust memory. */
const GUID = z.string().min(1).max(256);
const SHORT = z.string().max(512);
const TEXT = z.string().max(200_000);

export const attachmentMetadataSchema = z.object({
  attachmentGuid: GUID,
  sourceRowId: z.number().int(),
  messageGuid: GUID,
  filename: SHORT.optional(),
  mimeType: SHORT.optional(),
  uti: SHORT.optional(),
  sizeBytes: z.number().int().nonnegative().optional(),
  sha256: z.string().regex(/^[0-9a-f]{64}$/i).optional(),
  isSticker: z.boolean(),
  isHidden: z.boolean(),
  available: z.boolean(),
  willUpload: z.boolean(),
  skippedReason: z.enum(['missing', 'too_large', 'hidden', 'temp_file', 'sticker']).optional(),
  createdAt: SHORT.optional(),
});

export const normalizedMessageSchema = z.object({
  schemaVersion: z.literal(1),
  source: z.literal('apple_messages'),
  messageGuid: GUID,
  sourceRowId: z.number().int(),
  kind: z.enum(['message', 'reaction', 'group_event', 'system']),
  chat: z.object({
    chatGuid: GUID,
    chatRowId: z.number().int(),
    identifier: SHORT,
    isGroup: z.boolean(),
    displayName: SHORT.optional(),
    service: SHORT,
  }),
  sender: z.object({
    handle: SHORT.optional(),
    displayName: SHORT.optional(),
    isMe: z.boolean(),
  }),
  participants: z.array(z.object({ handle: SHORT, displayName: SHORT.optional() })).max(1000),
  sentAt: SHORT,
  deliveredAt: SHORT.optional(),
  readAt: SHORT.optional(),
  editedAt: SHORT.optional(),
  text: TEXT.optional(),
  subject: TEXT.optional(),
  isFromMe: z.boolean(),
  service: SHORT,
  isAudioMessage: z.boolean(),
  attachments: z.array(attachmentMetadataSchema).max(100),
  reaction: z
    .object({
      type: SHORT,
      action: z.enum(['add', 'remove']),
      targetMessageGuid: GUID,
      targetPart: z.number().int().optional(),
    })
    .optional(),
  reply: z.object({ threadOriginatorGuid: GUID, part: SHORT.optional() }).optional(),
  groupEvent: z
    .object({
      itemType: z.number().int(),
      actionType: z.number().int(),
      title: SHORT.optional(),
      otherHandle: SHORT.optional(),
    })
    .optional(),
  balloonBundleId: SHORT.optional(),
  flags: z.object({
    bodyDecodeFailed: z.boolean().optional(),
    isSpam: z.boolean().optional(),
    error: z.number().int().optional(),
  }),
});

export const batchRequestSchema = z.object({
  schemaVersion: z.literal(1),
  batchId: GUID,
  deviceId: GUID,
  phase: z.enum(['backfill', 'incremental', 'revision']),
  sentAt: SHORT,
  range: z.object({ firstRowId: z.number().int(), lastRowId: z.number().int() }),
  messages: z.array(normalizedMessageSchema),
});

export const attachmentUploadMetaSchema = z.object({
  attachmentGuid: GUID,
  messageGuid: GUID,
  filename: SHORT.optional(),
  mimeType: SHORT.optional(),
  uti: SHORT.optional(),
  sizeBytes: z.number().int().nonnegative(),
  sha256: z.string().regex(/^[0-9a-f]{64}$/i),
  isSticker: z.boolean(),
  isHidden: z.boolean(),
});

export const heartbeatSchema = z.object({
  deviceId: GUID,
  version: SHORT,
  at: SHORT,
  phase: z.enum(['backfill', 'incremental', 'revision', 'idle']),
  lastAckedRowId: z.number().int(),
  pendingAttachments: z.number().int().nonnegative(),
  backfillComplete: z.boolean(),
});

export type AttachmentMetadata = z.infer<typeof attachmentMetadataSchema>;
export type NormalizedMessage = z.infer<typeof normalizedMessageSchema>;
export type BatchRequest = z.infer<typeof batchRequestSchema>;
export type AttachmentUploadMeta = z.infer<typeof attachmentUploadMetaSchema>;
export type HeartbeatPayload = z.infer<typeof heartbeatSchema>;

export interface BatchResponse {
  ok: true;
  received: number;
  attachments: { wanted: string[] };
}

/**
 * Apple timestamps arrive as ISO-8601 strings from the sender. Store epoch
 * milliseconds so range queries and ordering are cheap and unambiguous.
 * Returns null for anything unparseable rather than throwing — a single bad
 * timestamp must not fail an entire batch.
 */
export function isoToEpochMs(iso: string | undefined): number | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  return Number.isFinite(t) ? t : null;
}
