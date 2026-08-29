/**
 * Read-side queries for the MCP tools.
 *
 * All of these run against the encrypted database through a read-only handle.
 * Every query is bounded by an explicit LIMIT so no tool can produce an
 * unbounded response.
 */
import type { Db } from '../shared/db.js';

export interface MessageView {
  messageGuid: string;
  chatGuid: string;
  chatName: string | null;
  isGroup: boolean;
  sender: string | null;
  senderHandle: string | null;
  isFromMe: boolean;
  service: string;
  sentAt: string | null;
  text: string | null;
  subject: string | null;
  kind: string;
  hasAttachments: boolean;
  attachments?: Array<{ attachmentGuid: string; filename: string | null; mimeType: string | null; sizeBytes: number | null; state: string }>;
}

const BASE_SELECT = `
  SELECT m.message_guid, m.chat_guid, m.sender_handle, m.sender_name, m.is_from_me,
         m.service, m.sent_at, m.text, m.subject, m.kind, m.has_attachments,
         c.display_name AS chat_display_name, c.identifier AS chat_identifier, c.is_group
    FROM messages m JOIN chats c ON c.chat_guid = m.chat_guid`;

interface RawRow {
  message_guid: string;
  chat_guid: string;
  sender_handle: string | null;
  sender_name: string | null;
  is_from_me: number;
  service: string;
  sent_at: number | null;
  text: string | null;
  subject: string | null;
  kind: string;
  has_attachments: number;
  chat_display_name: string | null;
  chat_identifier: string;
  is_group: number;
}

function toView(r: RawRow): MessageView {
  return {
    messageGuid: r.message_guid,
    chatGuid: r.chat_guid,
    chatName: r.chat_display_name ?? r.chat_identifier,
    isGroup: r.is_group === 1,
    sender: r.is_from_me === 1 ? 'me' : (r.sender_name ?? r.sender_handle),
    senderHandle: r.sender_handle,
    isFromMe: r.is_from_me === 1,
    service: r.service,
    sentAt: r.sent_at === null ? null : new Date(r.sent_at).toISOString(),
    text: r.text,
    subject: r.subject,
    kind: r.kind,
    hasAttachments: r.has_attachments === 1,
  };
}

export function attachAttachments(db: Db, views: MessageView[]): void {
  const withAtt = views.filter((v) => v.hasAttachments);
  if (withAtt.length === 0) return;
  const stmt = db.prepare(
    `SELECT attachment_guid, filename, mime_type, size_bytes, state FROM attachments WHERE message_guid = ?`,
  );
  for (const v of withAtt) {
    const rows = stmt.all(v.messageGuid) as Array<{
      attachment_guid: string;
      filename: string | null;
      mime_type: string | null;
      size_bytes: number | null;
      state: string;
    }>;
    v.attachments = rows.map((a) => ({
      attachmentGuid: a.attachment_guid,
      filename: a.filename,
      mimeType: a.mime_type,
      sizeBytes: a.size_bytes,
      state: a.state,
    }));
  }
}

export interface SearchArgs {
  query?: string | undefined;
  contact?: string | undefined;
  chatGuid?: string | undefined;
  after?: number | undefined;
  before?: number | undefined;
  fromMe?: boolean | undefined;
  hasAttachments?: boolean | undefined;
  service?: string | undefined;
  limit: number;
}

/**
 * Free-text search over message bodies, with optional structured filters.
 *
 * When `query` is present this goes through FTS5 (ranked, indexed). When it is
 * absent the same filters run as a plain indexed scan, so the tool doubles as a
 * structured browse.
 */
export function searchMessages(db: Db, a: SearchArgs): MessageView[] {
  const where: string[] = [];
  const params: Record<string, unknown> = { limit: a.limit };

  let from = BASE_SELECT;
  if (a.query && a.query.trim()) {
    from = `
      SELECT m.message_guid, m.chat_guid, m.sender_handle, m.sender_name, m.is_from_me,
             m.service, m.sent_at, m.text, m.subject, m.kind, m.has_attachments,
             c.display_name AS chat_display_name, c.identifier AS chat_identifier, c.is_group
        FROM messages_fts f
        JOIN messages m ON m.rowid = f.rowid
        JOIN chats c ON c.chat_guid = m.chat_guid`;
    where.push(`messages_fts MATCH @q`);
    params.q = toFtsQuery(a.query);
  }

  if (a.chatGuid) {
    where.push(`m.chat_guid = @chatGuid`);
    params.chatGuid = a.chatGuid;
  }
  if (a.contact) {
    where.push(`(m.sender_handle = @contactExact
                 OR m.sender_name LIKE @contactLike
                 OR EXISTS (SELECT 1 FROM handles h WHERE h.handle = m.sender_handle AND h.display_name LIKE @contactLike)
                 OR m.chat_guid IN (
                      SELECT cp.chat_guid FROM chat_participants cp
                        JOIN handles h2 ON h2.handle = cp.handle
                       WHERE cp.handle = @contactExact OR h2.display_name LIKE @contactLike))`);
    params.contactExact = a.contact;
    params.contactLike = `%${a.contact}%`;
  }
  if (a.after !== undefined) {
    where.push(`m.sent_at >= @after`);
    params.after = a.after;
  }
  if (a.before !== undefined) {
    where.push(`m.sent_at <= @before`);
    params.before = a.before;
  }
  if (a.fromMe !== undefined) {
    where.push(`m.is_from_me = @fromMe`);
    params.fromMe = a.fromMe ? 1 : 0;
  }
  if (a.hasAttachments !== undefined) {
    where.push(`m.has_attachments = @hasAtt`);
    params.hasAtt = a.hasAttachments ? 1 : 0;
  }
  if (a.service) {
    where.push(`m.service = @service`);
    params.service = a.service;
  }

  const sql = `${from}${where.length ? ' WHERE ' + where.join(' AND ') : ''}
               ORDER BY m.sent_at DESC LIMIT @limit`;
  const rows = db.prepare(sql).all(params) as RawRow[];
  return rows.map(toView);
}

/**
 * Turn user text into a safe FTS5 MATCH expression.
 *
 * FTS5 has its own query syntax; passing raw user input through would let a
 * stray quote or `NEAR(` become a syntax error (or worse, change the query).
 * Every token is quoted as a literal phrase and ANDed.
 */
export function toFtsQuery(input: string): string {
  const tokens = input
    .replace(/["]/g, ' ')
    .split(/\s+/)
    .map((t) => t.trim())
    .filter((t) => t.length > 0)
    .slice(0, 20);
  if (tokens.length === 0) return '""';
  return tokens.map((t) => `"${t}"`).join(' AND ');
}

/** Messages in one conversation, oldest-first, with keyset pagination. */
export function conversation(db: Db, chatGuid: string, opts: { before?: number | undefined; after?: number | undefined; limit: number }): MessageView[] {
  const where = ['m.chat_guid = @chatGuid'];
  const params: Record<string, unknown> = { chatGuid, limit: opts.limit };
  if (opts.before !== undefined) {
    where.push('m.sent_at <= @before');
    params.before = opts.before;
  }
  if (opts.after !== undefined) {
    where.push('m.sent_at >= @after');
    params.after = opts.after;
  }
  // Take the newest slice, then present chronologically.
  const rows = db
    .prepare(`${BASE_SELECT} WHERE ${where.join(' AND ')} ORDER BY m.sent_at DESC LIMIT @limit`)
    .all(params) as RawRow[];
  return rows.map(toView).reverse();
}

export interface ChatMatch {
  chatGuid: string;
  name: string;
  identifier: string;
  isGroup: boolean;
  lastMessageAt: string | null;
  messageCount: number;
  participants: string[];
}

/**
 * Resolve a human reference ("Alex", "+15551234567", a chat guid) to candidate
 * conversations, best match first. Returning candidates rather than guessing
 * lets the model disambiguate when a name is ambiguous.
 */
export function resolveChats(db: Db, ref: string, limit = 10): ChatMatch[] {
  const like = `%${ref}%`;
  const rows = db
    .prepare(
      `SELECT c.chat_guid, c.display_name, c.identifier, c.is_group, c.last_message_at,
              (SELECT count(*) FROM messages m WHERE m.chat_guid = c.chat_guid) AS n
         FROM chats c
        WHERE c.chat_guid = @exact
           OR c.identifier = @exact
           OR c.display_name LIKE @like
           OR c.identifier LIKE @like
           OR EXISTS (SELECT 1 FROM chat_participants cp JOIN handles h ON h.handle = cp.handle
                       WHERE cp.chat_guid = c.chat_guid
                         AND (cp.handle = @exact OR cp.handle LIKE @like OR h.display_name LIKE @like))
        ORDER BY (c.chat_guid = @exact OR c.identifier = @exact) DESC, c.last_message_at DESC
        LIMIT @limit`,
    )
    .all({ exact: ref, like, limit }) as Array<{
    chat_guid: string;
    display_name: string | null;
    identifier: string;
    is_group: number;
    last_message_at: number | null;
    n: number;
  }>;

  const pstmt = db.prepare(
    `SELECT COALESCE(h.display_name, cp.handle) AS who
       FROM chat_participants cp LEFT JOIN handles h ON h.handle = cp.handle
      WHERE cp.chat_guid = ? LIMIT 25`,
  );
  return rows.map((r) => ({
    chatGuid: r.chat_guid,
    name: r.display_name ?? r.identifier,
    identifier: r.identifier,
    isGroup: r.is_group === 1,
    lastMessageAt: r.last_message_at === null ? null : new Date(r.last_message_at).toISOString(),
    messageCount: r.n,
    participants: (pstmt.all(r.chat_guid) as Array<{ who: string }>).map((p) => p.who),
  }));
}

export function recentMessages(db: Db, opts: { limit: number; since?: number | undefined; contact?: string | undefined }): MessageView[] {
  return searchMessages(db, {
    limit: opts.limit,
    ...(opts.since !== undefined ? { after: opts.since } : {}),
    ...(opts.contact !== undefined ? { contact: opts.contact } : {}),
  });
}

/** Everything ingested or sent after a watermark — for agent checkpoint workflows. */
export function messagesSince(db: Db, sinceMs: number, limit: number, byIngestion: boolean): MessageView[] {
  const col = byIngestion ? 'm.ingested_at' : 'm.sent_at';
  const rows = db
    .prepare(`${BASE_SELECT} WHERE ${col} >= @since ORDER BY ${col} ASC LIMIT @limit`)
    .all({ since: sinceMs, limit }) as RawRow[];
  return rows.map(toView);
}

export function stats(db: Db): Record<string, unknown> {
  const one = (sql: string): number => Number((db.prepare(sql).get() as { n: number } | undefined)?.n ?? 0);
  const range = db.prepare(`SELECT MIN(sent_at) a, MAX(sent_at) b FROM messages`).get() as { a: number | null; b: number | null };
  return {
    messages: one('SELECT count(*) n FROM messages'),
    chats: one('SELECT count(*) n FROM chats'),
    handles: one('SELECT count(*) n FROM handles'),
    attachments: one('SELECT count(*) n FROM attachments'),
    attachments_stored: one("SELECT count(*) n FROM attachments WHERE state = 'stored'"),
    earliest: range.a ? new Date(range.a).toISOString() : null,
    latest: range.b ? new Date(range.b).toISOString() : null,
  };
}
