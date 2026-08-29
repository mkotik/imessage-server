/**
 * Ingestion service bootstrap.
 *
 * Binds to loopback only. Cloudflare Tunnel is the sole external path, and
 * Cloudflare Access (service-token policy) authenticates the Mac at the edge.
 * The origin does NOT trust that: it independently verifies the
 * Cf-Access-Jwt-Assertion signature AND a shared bearer token, so a request that
 * somehow reaches 127.0.0.1:3100 by another route is still rejected.
 *
 * All request handling lives in app.ts; this file only wires real dependencies
 * and manages the process lifecycle.
 */
import { createServer } from 'node:http';
import { mkdirSync } from 'node:fs';

import { createAccessVerifier, AccessConfigError, type AccessVerifier } from '../shared/access.js';
import { loadIngestConfig, ConfigError, describe, type IngestConfig } from '../shared/config.js';
import { createLogger } from '../shared/logger.js';
import { openDatabase, type Db } from '../shared/db.js';
import { createObjectStore, type ObjectStore } from '../shared/e2.js';
import { createIngestApp, SERVICE, VERSION } from './app.js';

let cfg: IngestConfig;
try {
  cfg = loadIngestConfig();
} catch (err) {
  if (err instanceof ConfigError) {
    process.stderr.write(JSON.stringify({ level: 'error', service: SERVICE, event: 'fatal', reason: err.message }) + '\n');
    process.exit(78); // EX_CONFIG
  }
  throw err;
}

const log = createLogger(SERVICE, cfg.logLevel);

let accessVerifier: AccessVerifier;
try {
  accessVerifier = createAccessVerifier({
    teamDomain: cfg.cfTeamDomain,
    aud: cfg.cfAud,
    principal: 'service',
    expectedCommonName: cfg.ingestClientId,
  });
} catch (err) {
  if (err instanceof AccessConfigError) {
    log.error('fatal', { reason: 'access configuration invalid', detail: err.message });
    process.exit(78);
  }
  throw err;
}

mkdirSync(cfg.storage.tmpDir, { recursive: true });
const db: Db = openDatabase({ path: cfg.storage.dbPath, key: cfg.storage.dbKey });
const store: ObjectStore = createObjectStore(cfg.e2);

const route = createIngestApp({ cfg, db, store, accessVerifier, log });

const server = createServer((req, res) => {
  void route(req, res).catch((err) => {
    log.error('unhandled', { error: (err as Error).name });
    if (!res.headersSent) {
      res.writeHead(500, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'internal error' }));
    } else res.end();
  });
});

// Backfill batches and large attachments can be slow; keep generous timeouts.
server.requestTimeout = 15 * 60 * 1000;
server.headersTimeout = 60 * 1000;

server.listen(cfg.port, cfg.host, () => {
  log.info('startup', { service: SERVICE, version: VERSION, ...describe(cfg) });
});

function shutdown(signal: string): void {
  log.info('shutdown', { reason: signal });
  server.close(() => {
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
