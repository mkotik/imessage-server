/**
 * iMessage MCP server.
 *
 * Deliberately five tools, not twenty. Every tool schema is injected into the
 * model's context on every request, so each one has to earn its place.
 *
 * Same security posture as the Obsidian MCP on this host: loopback bind,
 * Cloudflare Access in front, origin-side JWT verification with no localhost
 * bypass, and its own Access application (a distinct AUD) so iMessage and
 * Obsidian permissions are not coupled.
 *
 * Read-only by design: this server never writes to the archive. Ingestion is a
 * separate process with separate credentials.
 */
import { createServer } from 'node:http';
import { createMcpHandler, McpServer } from '@modelcontextprotocol/server';
import { hostHeaderValidation, originValidation, toNodeHandler } from '@modelcontextprotocol/node';
import * as z from 'zod';

import { createAccessVerifier, AccessConfigError, type AccessVerifier } from '../shared/access.js';
import { ConfigError, describe, loadMcpConfig, type McpConfig } from '../shared/config.js';
import { createLogger } from '../shared/logger.js';
import { openDatabase, type Db } from '../shared/db.js';
import { createObjectStore, type ObjectStore } from '../shared/e2.js';
import { open as openSealed, DecryptionError } from '../shared/crypto.js';
import * as q from '../repo/queries.js';
import { getAttachment } from '../repo/attachments.js';

const SERVER_NAME = 'imessage-archive';
const SERVER_VERSION = '0.1.0';
const MCP_PATH = '/mcp';

const LIMITS = {
  searchDefault: 25,
  searchMax: 200,
  conversationDefault: 50,
  conversationMax: 500,
  recentDefault: 25,
  recentMax: 200,
  sinceDefault: 100,
  sinceMax: 500,
  chatCandidates: 10,
} as const;

let cfg: McpConfig;
try {
  cfg = loadMcpConfig();
} catch (err) {
  if (err instanceof ConfigError) {
    process.stderr.write(JSON.stringify({ level: 'error', service: SERVER_NAME, event: 'fatal', reason: err.message }) + '\n');
    process.exit(78);
  }
  throw err;
}

const log = createLogger('imessage-mcp', cfg.logLevel);

let accessVerifier: AccessVerifier;
try {
  accessVerifier = createAccessVerifier({ teamDomain: cfg.cfTeamDomain, aud: cfg.cfAud });
} catch (err) {
  if (err instanceof AccessConfigError) {
    log.error('fatal', { reason: 'access configuration invalid', detail: err.message });
    process.exit(78);
  }
  throw err;
}

// Read-only handle: the query surface cannot mutate the archive even if a tool
// had a bug.
const db: Db = openDatabase({ path: cfg.storage.dbPath, key: cfg.storage.dbKey, readonly: true, migrate: false });
const store: ObjectStore = createObjectStore(cfg.e2);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function ok(payload: unknown) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(payload, null, 2) }] };
}
function fail(message: string) {
  return { isError: true, content: [{ type: 'text' as const, text: message }] };
}

/** Accepts an ISO date, a date-time, or a relative shorthand like "30d" / "12h". */
function parseWhen(input: string | undefined): number | undefined {
  if (!input) return undefined;
  const s = input.trim();
  const rel = /^(\d+)\s*([dhwm])$/i.exec(s);
  if (rel) {
    const n = Number(rel[1]);
    const unit = rel[2]!.toLowerCase();
    const ms = unit === 'h' ? 3600e3 : unit === 'd' ? 86400e3 : unit === 'w' ? 7 * 86400e3 : 30 * 86400e3;
    return Date.now() - n * ms;
  }
  const t = Date.parse(s);
  return Number.isFinite(t) ? t : undefined;
}

function clamp(n: number | undefined, def: number, max: number): number {
  if (n === undefined || !Number.isFinite(n)) return def;
  return Math.max(1, Math.min(Math.floor(n), max));
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

function buildServer(): McpServer {
  const server = new McpServer({ name: SERVER_NAME, version: SERVER_VERSION });

  server.registerTool(
    'search_messages',
    {
      description:
        'Search the iMessage/SMS archive by free text and/or structured filters. ' +
        'Use this to answer questions like "what did Alex say about Yosemite last month". ' +
        'Returns newest matches first. Dates accept ISO-8601 or shorthand like "30d", "12h", "2w".',
      inputSchema: z.object({
        query: z.string().max(500).optional().describe('Free-text search over message bodies. Omit to browse by filter alone.'),
        contact: z.string().max(200).optional().describe('Person: contact name, phone number, or email.'),
        chat_guid: z.string().max(256).optional().describe('Restrict to one conversation (from get_conversation).'),
        after: z.string().max(64).optional().describe('Only messages at or after this time.'),
        before: z.string().max(64).optional().describe('Only messages at or before this time.'),
        from_me: z.boolean().optional().describe('true = only my messages, false = only theirs.'),
        has_attachments: z.boolean().optional(),
        service: z.string().max(32).optional().describe('iMessage or SMS.'),
        limit: z.number().int().optional(),
      }),
    },
    async (args) => {
      const limit = clamp(args.limit, LIMITS.searchDefault, LIMITS.searchMax);
      const results = q.searchMessages(db, {
        query: args.query,
        contact: args.contact,
        chatGuid: args.chat_guid,
        after: parseWhen(args.after),
        before: parseWhen(args.before),
        fromMe: args.from_me,
        hasAttachments: args.has_attachments,
        service: args.service,
        limit,
      });
      q.attachAttachments(db, results);
      log.info('tool', { tool: 'search_messages', results: results.length, limit });
      return ok({ count: results.length, truncated: results.length === limit, messages: results });
    },
  );

  server.registerTool(
    'get_conversation',
    {
      description:
        'Retrieve one conversation in chronological order. Resolve it by contact name, phone/email handle, ' +
        'or chat_guid. If the reference matches several conversations, the candidates are returned instead ' +
        'so you can pick one. Handles group chats.',
      inputSchema: z.object({
        conversation: z.string().min(1).max(256).describe('Contact name, phone number, email, or chat_guid.'),
        before: z.string().max(64).optional().describe('Page backwards: return messages at or before this time.'),
        after: z.string().max(64).optional(),
        limit: z.number().int().optional(),
      }),
    },
    async (args) => {
      const limit = clamp(args.limit, LIMITS.conversationDefault, LIMITS.conversationMax);
      const candidates = q.resolveChats(db, args.conversation, LIMITS.chatCandidates);
      if (candidates.length === 0) return fail(`No conversation matches "${args.conversation}".`);

      const exact = candidates.find((c) => c.chatGuid === args.conversation || c.identifier === args.conversation);
      const chosen = exact ?? (candidates.length === 1 ? candidates[0]! : null);
      if (!chosen) {
        log.info('tool', { tool: 'get_conversation', candidates: candidates.length });
        return ok({
          ambiguous: true,
          hint: 'Several conversations match. Call again with one of these chat_guid values.',
          candidates,
        });
      }

      const messages = q.conversation(db, chosen.chatGuid, {
        before: parseWhen(args.before),
        after: parseWhen(args.after),
        limit,
      });
      q.attachAttachments(db, messages);
      log.info('tool', { tool: 'get_conversation', chatGuid: chosen.chatGuid, results: messages.length });
      return ok({
        conversation: { chatGuid: chosen.chatGuid, name: chosen.name, isGroup: chosen.isGroup, participants: chosen.participants, messageCount: chosen.messageCount },
        count: messages.length,
        truncated: messages.length === limit,
        oldestReturned: messages[0]?.sentAt ?? null,
        messages,
      });
    },
  );

  server.registerTool(
    'get_recent_messages',
    {
      description:
        'The most recent messages across all conversations, newest first. Optionally narrow to one person. ' +
        'Use for "what have people texted me recently" or "what did John say today".',
      inputSchema: z.object({
        contact: z.string().max(200).optional().describe('Limit to one person by name, phone, or email.'),
        since: z.string().max(64).optional().describe('Only messages after this time. Defaults to no lower bound.'),
        limit: z.number().int().optional(),
      }),
    },
    async (args) => {
      const limit = clamp(args.limit, LIMITS.recentDefault, LIMITS.recentMax);
      const results = q.recentMessages(db, { limit, since: parseWhen(args.since), contact: args.contact });
      q.attachAttachments(db, results);
      log.info('tool', { tool: 'get_recent_messages', results: results.length });
      return ok({ count: results.length, truncated: results.length === limit, messages: results });
    },
  );

  server.registerTool(
    'get_messages_since',
    {
      description:
        'Everything after a timestamp, oldest first — for checkpointed workflows that poll for new activity. ' +
        'Set by="ingested" to page by arrival at the archive rather than by when the message was sent, which ' +
        'is what you want if the Mac was offline and backfilled later.',
      inputSchema: z.object({
        since: z.string().min(1).max(64).describe('ISO-8601 timestamp, or shorthand like "24h".'),
        by: z.enum(['sent', 'ingested']).optional(),
        limit: z.number().int().optional(),
      }),
    },
    async (args) => {
      const since = parseWhen(args.since);
      if (since === undefined) return fail(`Could not parse "since": ${args.since}`);
      const limit = clamp(args.limit, LIMITS.sinceDefault, LIMITS.sinceMax);
      const results = q.messagesSince(db, since, limit, args.by === 'ingested');
      q.attachAttachments(db, results);
      const last = results[results.length - 1];
      log.info('tool', { tool: 'get_messages_since', results: results.length });
      return ok({
        count: results.length,
        truncated: results.length === limit,
        nextCursor: last?.sentAt ?? null,
        messages: results,
      });
    },
  );

  server.registerTool(
    'get_attachment',
    {
      description:
        'Fetch one attachment by attachment_guid. The bytes are pulled from object storage and decrypted here; ' +
        'no public URL is ever produced. Images and small files are returned inline and are directly viewable. ' +
        'Anything above the inline size limit returns metadata only — ask for a smaller file rather than retrying.',
      inputSchema: z.object({
        attachment_guid: z.string().min(1).max(256),
        metadata_only: z.boolean().optional().describe('Skip the download and return only stored metadata.'),
      }),
    },
    async (args) => {
      const row = getAttachment(db, args.attachment_guid);
      if (!row) return fail(`No attachment ${args.attachment_guid}.`);

      const meta = {
        attachmentGuid: row.attachment_guid,
        messageGuid: row.message_guid,
        filename: row.filename,
        mimeType: row.mime_type,
        sizeBytes: row.size_bytes,
        sha256: row.sha256,
        state: row.state,
      };

      if (args.metadata_only) return ok(meta);
      if (row.state !== 'stored' || !row.object_key) {
        return ok({ ...meta, note: `Bytes are not in object storage (state=${row.state}).` });
      }
      if ((row.size_bytes ?? 0) > cfg.maxInlineAttachmentBytes) {
        return ok({
          ...meta,
          note: `Too large to return inline (${row.size_bytes} bytes, limit ${cfg.maxInlineAttachmentBytes}). Metadata only.`,
        });
      }

      let plaintext: Buffer;
      try {
        const sealed = await store.getBuffer(row.object_key);
        plaintext = openSealed(sealed, cfg.attachmentMasterKey, row.object_key);
      } catch (err) {
        const why = err instanceof DecryptionError ? 'decryption failed' : 'object storage unavailable';
        log.error('attachment_fetch_failed', { attachmentGuid: row.attachment_guid, error: (err as Error).name });
        return fail(`Could not retrieve attachment: ${why}.`);
      }

      log.info('tool', { tool: 'get_attachment', attachmentGuid: row.attachment_guid, bytes: plaintext.length });

      const mime = row.mime_type ?? 'application/octet-stream';
      if (mime.startsWith('image/')) {
        return {
          content: [
            { type: 'text' as const, text: JSON.stringify(meta, null, 2) },
            { type: 'image' as const, data: plaintext.toString('base64'), mimeType: mime },
          ],
        };
      }
      return ok({ ...meta, encoding: 'base64', data: plaintext.toString('base64') });
    },
  );

  return server;
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

const handler = createMcpHandler(() => buildServer());
const nodeHandler = toNodeHandler(handler);
const allowedHostnames = ['127.0.0.1', 'localhost', ...cfg.publicHostnames];
const validateHost = hostHeaderValidation(allowedHostnames);
const validateOrigin = originValidation(allowedHostnames);

function rejectUnauthenticated(res: import('node:http').ServerResponse, reason: string): void {
  res.statusCode = 401;
  res.setHeader('www-authenticate', `Bearer realm="${SERVER_NAME}", error="invalid_token"`);
  res.setHeader('content-type', 'application/json');
  res.end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32001, message: 'unauthorized' }, id: null }));
  log.warn(`Authentication rejected: ${reason}`);
}

async function handleRequest(req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse): Promise<void> {
  if (!validateHost(req, res) || !validateOrigin(req, res)) return;

  const url = req.url ?? '';
  if (url === '/health') {
    const local = req.socket.remoteAddress === '127.0.0.1' || req.socket.remoteAddress === '::1';
    res.statusCode = local ? 200 : 404;
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify(local ? { ok: true, service: SERVER_NAME, version: SERVER_VERSION, ...q.stats(db) } : { error: 'not found' }));
    return;
  }

  if (!(url === MCP_PATH || url.startsWith(`${MCP_PATH}?`))) {
    res.statusCode = 404;
    res.setHeader('content-type', 'text/plain');
    res.end('not found\n');
    return;
  }

  // No localhost exemption, by design.
  const auth = await accessVerifier.verify(req);
  if (!auth.ok) return rejectUnauthenticated(res, auth.reason);
  log.info('Authentication succeeded');

  // The SDK's request type declares `method`/`url` as required; node's
  // IncomingMessage types them as optional. Structurally identical at runtime.
  await nodeHandler(req as Parameters<typeof nodeHandler>[0], res);
}

const http = createServer((req, res) => {
  void handleRequest(req, res).catch(() => {
    if (!res.headersSent) {
      res.statusCode = 500;
      res.setHeader('content-type', 'text/plain');
      res.end('internal error\n');
    } else res.end();
  });
});

http.listen(cfg.port, cfg.host, () => {
  log.info('startup', {
    server: SERVER_NAME,
    version: SERVER_VERSION,
    ...describe(cfg),
    tools: 'search_messages,get_conversation,get_recent_messages,get_messages_since,get_attachment',
  });
});

function shutdown(signal: string): void {
  log.info('shutdown', { reason: signal });
  http.close(() => {
    try {
      db.close();
    } catch {
      /* ignore */
    }
    process.exit(0);
  });
  setTimeout(() => process.exit(0), 10_000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
