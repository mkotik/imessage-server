/**
 * Privacy-preserving structured logging.
 *
 * The hard rule for this project: message bodies, attachment bytes, contact
 * names, handles, tokens and JWT contents NEVER reach the log. Callers pass
 * counts and identifiers only. To make accidents unlikely rather than merely
 * forbidden, `emit` runs a shape check over every field it is given and
 * replaces anything that looks like free text with a redaction marker.
 */

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 } as const;
export type Level = keyof typeof LEVELS;

/**
 * Field names that are allowed to carry a longer opaque string (identifiers,
 * hashes, object keys). Everything else is length-capped.
 */
const OPAQUE_FIELDS = new Set([
  'batchId',
  'deviceId',
  'messageGuid',
  'attachmentGuid',
  'chatGuid',
  'objectKey',
  'sha256',
  'event',
  'service',
  'phase',
  'reason',
  'error',
  'tool',
  'db',
  'tmp',
  'bind',
  'endpoint',
  'e2_endpoint',
  'e2_bucket',
  'public_hostnames',
  'log_level',
  'version',
  'server',
]);

const MAX_OPAQUE = 200;
const MAX_OTHER = 40;

function scrub(key: string, value: unknown): unknown {
  if (value === null || value === undefined) return value;
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (Array.isArray(value)) return value.length <= 20 ? value.map((v, i) => scrub(`${key}[${i}]`, v)) : `[${value.length} items]`;
  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) out[k] = scrub(k, v);
    return out;
  }
  const s = String(value);
  const limit = OPAQUE_FIELDS.has(key) ? MAX_OPAQUE : MAX_OTHER;
  if (s.length > limit) return `[redacted:${s.length}chars]`;
  return s;
}

export interface Logger {
  debug(event: string, fields?: Record<string, unknown>): void;
  info(event: string, fields?: Record<string, unknown>): void;
  warn(event: string, fields?: Record<string, unknown>): void;
  error(event: string, fields?: Record<string, unknown>): void;
}

export function createLogger(service: string, level: string = 'info'): Logger {
  const min = LEVELS[(level as Level) in LEVELS ? (level as Level) : 'info'];
  const emit = (lvl: Level, event: string, fields?: Record<string, unknown>): void => {
    if (LEVELS[lvl] < min) return;
    const rec: Record<string, unknown> = {
      ts: new Date().toISOString(),
      level: lvl,
      service,
      event: String(event).slice(0, MAX_OPAQUE),
    };
    if (fields) for (const [k, v] of Object.entries(fields)) rec[k] = scrub(k, v);
    const line = JSON.stringify(rec);
    if (lvl === 'error' || lvl === 'warn') process.stderr.write(line + '\n');
    else process.stdout.write(line + '\n');
  };
  return {
    debug: (e, f) => emit('debug', e, f),
    info: (e, f) => emit('info', e, f),
    warn: (e, f) => emit('warn', e, f),
    error: (e, f) => emit('error', e, f),
  };
}
