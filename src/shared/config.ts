/**
 * Environment-driven configuration.
 *
 * Every secret arrives through the process environment (systemd EnvironmentFile,
 * read by root before privileges are dropped). Nothing is read from disk here and
 * no secret is ever returned by `describe()`.
 */

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigError';
  }
}

function req(name: string, env: NodeJS.ProcessEnv): string {
  const v = env[name]?.trim();
  if (!v) throw new ConfigError(`${name} is required`);
  return v;
}

function hexKey(name: string, env: NodeJS.ProcessEnv): Buffer {
  const v = req(name, env);
  if (!/^[0-9a-fA-F]{64}$/.test(v)) {
    throw new ConfigError(`${name} must be exactly 64 hex characters (32 bytes)`);
  }
  return Buffer.from(v, 'hex');
}

function int(name: string, env: NodeJS.ProcessEnv, def: number, min = 1): number {
  const raw = env[name]?.trim();
  if (!raw) return def;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < min) throw new ConfigError(`${name} must be an integer >= ${min}`);
  return n;
}

function hostList(name: string, env: NodeJS.ProcessEnv): string[] {
  return (env[name] ?? '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

/** Refuse to bind anywhere but loopback. This is a hard invariant of the deployment. */
function loopback(name: string, env: NodeJS.ProcessEnv, def: string): string {
  const v = (env[name] ?? def).trim();
  if (v !== '127.0.0.1' && v !== '::1' && v !== 'localhost') {
    throw new ConfigError(`${name} must be a loopback address; refusing to bind ${v}`);
  }
  return v;
}

export interface StorageConfig {
  dbPath: string;
  dbKey: Buffer;
  tmpDir: string;
}

export interface E2Config {
  endpoint: string;
  region: string;
  bucket: string;
  accessKeyId: string;
  secretAccessKey: string;
}

export interface CommonConfig {
  storage: StorageConfig;
  e2: E2Config;
  attachmentMasterKey: Buffer;
  logLevel: string;
  maxAttachmentBytes: number;
}

export interface IngestConfig extends CommonConfig {
  host: string;
  port: number;
  publicHostnames: string[];
  ingestToken: string;
  cfTeamDomain: string;
  cfAud: string;
  maxBatchBytes: number;
  maxMessagesPerBatch: number;
  /**
   * Also drop everything from numeric/alphanumeric short-code senders, not just
   * OTP-shaped content. The Mac sender applies this policy already (its own
   * IMESSAGE_FILTER_SHORTCODE_SENDERS); the server defaults it OFF so this
   * layer only ever removes authentication codes and never silently discards
   * legitimate automated mail the sender deliberately forwarded.
   */
  filterShortcodeSenders: boolean;
  /**
   * Client ID of the Cloudflare Access service token the Mac sender uses. The
   * origin pins the JWT's `common_name` to this value. Public, not a secret.
   */
  ingestClientId: string | undefined;
}

export interface McpConfig extends CommonConfig {
  host: string;
  port: number;
  publicHostnames: string[];
  cfTeamDomain: string;
  cfAud: string;
  maxInlineAttachmentBytes: number;
  /** Access service-token client IDs allowed through the MCP origin check (optional). */
  allowedServiceTokenIds: string[];
}

function common(env: NodeJS.ProcessEnv): CommonConfig {
  return {
    storage: {
      dbPath: env.IMSG_DB_PATH?.trim() || '/var/lib/imessage/messages.db',
      dbKey: hexKey('IMSG_DB_KEY_HEX', env),
      tmpDir: env.IMSG_TMP_DIR?.trim() || '/var/lib/imessage/tmp',
    },
    e2: {
      endpoint: req('E2_ENDPOINT', env),
      region: req('E2_REGION', env),
      bucket: req('E2_BUCKET', env),
      accessKeyId: req('E2_ACCESS_KEY_ID', env),
      secretAccessKey: req('E2_SECRET_ACCESS_KEY', env),
    },
    attachmentMasterKey: hexKey('IMSG_ATTACHMENT_MASTER_KEY_HEX', env),
    logLevel: env.IMSG_LOG_LEVEL?.trim() || 'info',
    maxAttachmentBytes: int('IMSG_MAX_ATTACHMENT_BYTES', env, 100 * 1024 * 1024),
  };
}

export function loadIngestConfig(env: NodeJS.ProcessEnv = process.env): IngestConfig {
  return {
    ...common(env),
    host: loopback('IMSG_INGEST_HOST', env, '127.0.0.1'),
    port: int('IMSG_INGEST_PORT', env, 3100),
    publicHostnames: hostList('IMSG_INGEST_PUBLIC_HOSTNAME', env),
    ingestToken: req('IMSG_INGEST_TOKEN', env),
    cfTeamDomain: req('CF_ACCESS_TEAM_DOMAIN', env),
    cfAud: req('IMSG_INGEST_CF_ACCESS_AUD', env),
    maxBatchBytes: int('IMSG_MAX_BATCH_BYTES', env, 32 * 1024 * 1024),
    maxMessagesPerBatch: int('IMSG_MAX_MESSAGES_PER_BATCH', env, 1000),
    filterShortcodeSenders: (env.IMSG_FILTER_SHORTCODE_SENDERS ?? '').trim().toLowerCase() === 'true',
    ingestClientId: env.IMSG_INGEST_CF_ACCESS_CLIENT_ID?.trim() || undefined,
  };
}

export function loadMcpConfig(env: NodeJS.ProcessEnv = process.env): McpConfig {
  return {
    ...common(env),
    host: loopback('IMSG_MCP_HOST', env, '127.0.0.1'),
    port: int('IMSG_MCP_PORT', env, 3200),
    publicHostnames: hostList('IMSG_MCP_PUBLIC_HOSTNAME', env),
    cfTeamDomain: req('CF_ACCESS_TEAM_DOMAIN', env),
    cfAud: req('IMSG_MCP_CF_ACCESS_AUD', env),
    maxInlineAttachmentBytes: int('IMSG_MAX_INLINE_ATTACHMENT_BYTES', env, 5 * 1024 * 1024),
    allowedServiceTokenIds: (env.IMSG_MCP_ALLOWED_SERVICE_TOKEN_IDS ?? '').split(',').map((v) => v.trim()).filter((v) => v.length > 0),
  };
}

/**
 * Minimal config for the operational CLI tools (migrate/backup/restore/verify),
 * which need the database and object storage but no HTTP or Access settings.
 */
export function loadStorageConfig(env: NodeJS.ProcessEnv = process.env): StorageConfig {
  return {
    dbPath: env.IMSG_DB_PATH?.trim() || '/var/lib/imessage/messages.db',
    dbKey: hexKey('IMSG_DB_KEY_HEX', env),
    tmpDir: env.IMSG_TMP_DIR?.trim() || '/var/lib/imessage/tmp',
  };
}

export function loadE2Config(env: NodeJS.ProcessEnv = process.env): E2Config {
  return {
    endpoint: req('E2_ENDPOINT', env),
    region: req('E2_REGION', env),
    bucket: req('E2_BUCKET', env),
    accessKeyId: req('E2_ACCESS_KEY_ID', env),
    secretAccessKey: req('E2_SECRET_ACCESS_KEY', env),
  };
}

export function loadAttachmentMasterKey(env: NodeJS.ProcessEnv = process.env): Buffer {
  return hexKey('IMSG_ATTACHMENT_MASTER_KEY_HEX', env);
}

/** Safe to log: no keys, no tokens, no credentials. */
export function describe(cfg: IngestConfig | McpConfig): Record<string, unknown> {
  return {
    bind: `${cfg.host}:${cfg.port}`,
    db: cfg.storage.dbPath,
    tmp: cfg.storage.tmpDir,
    e2_endpoint: cfg.e2.endpoint,
    e2_bucket: cfg.e2.bucket,
    public_hostnames: cfg.publicHostnames.join(',') || '(none)',
    log_level: cfg.logLevel,
  };
}
