/**
 * Schema and forward-only migrations.
 *
 * Design notes:
 *  - This is an ARCHIVE. Nothing is ever deleted because it vanished upstream;
 *    `source_deleted_at` records the observation instead.
 *  - Apple's schema is not copied. The sender's normalized model is the input and
 *    this is a clean server-side shape built for retrieval.
 *  - Timestamps are epoch milliseconds (INTEGER) so range scans use the index.
 *  - `messages.message_guid` is the identity key and is UNIQUE; re-delivery is an
 *    upsert, which is what makes sender retries idempotent.
 *  - FTS5 is an external-content table over `messages.text`, kept in sync by
 *    triggers, so search never duplicates the body.
 *  - `outbox` exists (unused) so that adding outbound sending later is a feature,
 *    not a migration of everything else.
 */

export interface Migration {
  version: number;
  name: string;
  sql: string;
}

export const MIGRATIONS: Migration[] = [
  {
    version: 1,
    name: 'initial',
    sql: `
CREATE TABLE chats (
  chat_guid       TEXT PRIMARY KEY,
  identifier      TEXT NOT NULL,
  service         TEXT NOT NULL,
  is_group        INTEGER NOT NULL DEFAULT 0,
  display_name    TEXT,
  source_row_id   INTEGER,
  first_seen_at   INTEGER NOT NULL,
  last_message_at INTEGER
) STRICT;
CREATE INDEX idx_chats_last_message ON chats(last_message_at DESC);
CREATE INDEX idx_chats_identifier   ON chats(identifier);

-- One row per distinct handle (phone number / email). display_name is the best
-- name the sender has resolved so far and may improve over time.
CREATE TABLE handles (
  handle        TEXT PRIMARY KEY,
  display_name  TEXT,
  first_seen_at INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL
) STRICT;
CREATE INDEX idx_handles_display_name ON handles(display_name);

CREATE TABLE chat_participants (
  chat_guid TEXT NOT NULL REFERENCES chats(chat_guid) ON DELETE CASCADE,
  handle    TEXT NOT NULL REFERENCES handles(handle)  ON DELETE CASCADE,
  PRIMARY KEY (chat_guid, handle)
) STRICT;
CREATE INDEX idx_participants_handle ON chat_participants(handle);

CREATE TABLE messages (
  message_guid    TEXT PRIMARY KEY,
  chat_guid       TEXT NOT NULL REFERENCES chats(chat_guid) ON DELETE RESTRICT,
  source_row_id   INTEGER,
  kind            TEXT NOT NULL,           -- message | reaction | group_event | system
  sender_handle   TEXT,                    -- NULL when from me
  sender_name     TEXT,
  is_from_me      INTEGER NOT NULL,
  service         TEXT NOT NULL,           -- iMessage | SMS | …
  sent_at         INTEGER,                 -- epoch ms, NULL only if unparseable
  delivered_at    INTEGER,
  read_at         INTEGER,
  edited_at       INTEGER,
  text            TEXT,
  subject         TEXT,
  is_audio        INTEGER NOT NULL DEFAULT 0,
  has_attachments INTEGER NOT NULL DEFAULT 0,
  balloon_bundle  TEXT,
  reply_to_guid   TEXT,
  reaction_type   TEXT,
  reaction_action TEXT,
  reaction_target TEXT,
  group_event     TEXT,                    -- JSON blob, small
  flags           TEXT,                    -- JSON blob, small
  -- provenance
  device_id       TEXT,
  ingested_at     INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL,
  revision        INTEGER NOT NULL DEFAULT 1,
  source_deleted_at INTEGER                -- archive marker; row is never removed
) STRICT;
CREATE INDEX idx_messages_sent_at        ON messages(sent_at DESC);
CREATE INDEX idx_messages_chat_sent      ON messages(chat_guid, sent_at DESC);
CREATE INDEX idx_messages_sender_sent    ON messages(sender_handle, sent_at DESC);
CREATE INDEX idx_messages_from_me_sent   ON messages(is_from_me, sent_at DESC);
CREATE INDEX idx_messages_has_attach     ON messages(has_attachments, sent_at DESC);
CREATE INDEX idx_messages_ingested       ON messages(ingested_at DESC);
CREATE INDEX idx_messages_reaction_target ON messages(reaction_target);

CREATE TABLE attachments (
  attachment_guid TEXT PRIMARY KEY,
  message_guid    TEXT NOT NULL REFERENCES messages(message_guid) ON DELETE RESTRICT,
  source_row_id   INTEGER,
  filename        TEXT,
  mime_type       TEXT,
  uti             TEXT,
  size_bytes      INTEGER,
  sha256          TEXT,
  is_sticker      INTEGER NOT NULL DEFAULT 0,
  is_hidden       INTEGER NOT NULL DEFAULT 0,
  -- object storage
  state           TEXT NOT NULL DEFAULT 'pending',  -- pending | stored | skipped | failed
  object_key      TEXT,
  enc_version     INTEGER,
  stored_bytes    INTEGER,
  skipped_reason  TEXT,
  error_count     INTEGER NOT NULL DEFAULT 0,
  first_seen_at   INTEGER NOT NULL,
  stored_at       INTEGER
) STRICT;
CREATE INDEX idx_attachments_message ON attachments(message_guid);
CREATE INDEX idx_attachments_state   ON attachments(state);
CREATE UNIQUE INDEX idx_attachments_object_key ON attachments(object_key) WHERE object_key IS NOT NULL;

-- Full-text search over message bodies. External content: the text lives once,
-- in messages; fts stores only the index.
CREATE VIRTUAL TABLE messages_fts USING fts5(
  text,
  subject,
  content='messages',
  content_rowid='rowid',
  tokenize='unicode61 remove_diacritics 2'
);
CREATE TRIGGER messages_ai AFTER INSERT ON messages BEGIN
  INSERT INTO messages_fts(rowid, text, subject) VALUES (new.rowid, new.text, new.subject);
END;
CREATE TRIGGER messages_ad AFTER DELETE ON messages BEGIN
  INSERT INTO messages_fts(messages_fts, rowid, text, subject) VALUES('delete', old.rowid, old.text, old.subject);
END;
CREATE TRIGGER messages_au AFTER UPDATE ON messages BEGIN
  INSERT INTO messages_fts(messages_fts, rowid, text, subject) VALUES('delete', old.rowid, old.text, old.subject);
  INSERT INTO messages_fts(rowid, text, subject) VALUES (new.rowid, new.text, new.subject);
END;

-- Idempotency: remembering a batch lets a duplicate delivery be acknowledged
-- without redoing the work, and gives an audit trail of ingestion.
CREATE TABLE ingest_batches (
  batch_id      TEXT PRIMARY KEY,
  device_id     TEXT NOT NULL,
  phase         TEXT NOT NULL,
  first_row_id  INTEGER,
  last_row_id   INTEGER,
  message_count INTEGER NOT NULL,
  inserted      INTEGER NOT NULL,
  updated       INTEGER NOT NULL,
  otp_filtered  INTEGER NOT NULL,
  received_at   INTEGER NOT NULL
) STRICT;
CREATE INDEX idx_batches_device ON ingest_batches(device_id, received_at DESC);

CREATE TABLE devices (
  device_id          TEXT PRIMARY KEY,
  version            TEXT,
  last_seen_at       INTEGER NOT NULL,
  last_phase         TEXT,
  last_acked_row_id  INTEGER,
  backfill_complete  INTEGER NOT NULL DEFAULT 0,
  pending_attachments INTEGER
) STRICT;

-- Reserved for outbound sending (not implemented). Present so that adding it
-- later is additive rather than a schema rewrite.
CREATE TABLE outbox (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  chat_guid     TEXT,
  target_handle TEXT,
  body          TEXT,
  state         TEXT NOT NULL DEFAULT 'draft',  -- draft | approved | sent | failed
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL,
  sent_at       INTEGER,
  error         TEXT
) STRICT;
CREATE INDEX idx_outbox_state ON outbox(state, created_at);
`,
  },
];

export const LATEST_VERSION = MIGRATIONS[MIGRATIONS.length - 1]!.version;
