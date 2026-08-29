/**
 * Encrypted SQLite handle.
 *
 * Uses better-sqlite3-multiple-ciphers with the SQLCipher scheme. The database
 * file is unreadable — not merely unqueryable — without the key: the header is
 * ciphertext, so `sqlite3` reports "file is not a database".
 *
 * Verified on this deployment (ARM64 / aarch64, Node 22): a prebuilt binary is
 * used, so there is no compiler toolchain requirement on the box.
 */
import Database from 'better-sqlite3-multiple-ciphers';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { LATEST_VERSION, MIGRATIONS } from './schema.js';

export type Db = Database.Database;

export class DbKeyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DbKeyError';
  }
}

export interface OpenOptions {
  path: string;
  key: Buffer;
  readonly?: boolean;
  /** Skip migrations (used by tools that only read). */
  migrate?: boolean;
}

/**
 * Open (creating if needed) an encrypted database and bring it to the latest
 * schema version. Throws DbKeyError when the key is wrong.
 */
export function openDatabase(opts: OpenOptions): Db {
  const { path, key, readonly = false, migrate = true } = opts;
  if (key.length !== 32) throw new DbKeyError('database key must be 32 bytes');
  if (!readonly) mkdirSync(dirname(path), { recursive: true });

  const db = new Database(path, { readonly });
  // Order matters: cipher settings must be applied before the key, and the key
  // before any statement touches a page.
  db.pragma('cipher=sqlcipher');
  db.pragma('legacy=4');
  db.key(key);

  try {
    db.prepare('SELECT count(*) FROM sqlite_master').get();
  } catch (err) {
    db.close();
    throw new DbKeyError(`cannot open database (wrong key or corrupt file): ${(err as Error).message}`);
  }

  if (!readonly) {
    db.pragma('journal_mode = WAL');
    db.pragma('synchronous = NORMAL');
    db.pragma('foreign_keys = ON');
    db.pragma('busy_timeout = 10000');
    // Modest cache: this box has 1 core, no swap, and a 512 MB service cap.
    db.pragma('cache_size = -16000'); // ~16 MB
    if (migrate) runMigrations(db);
  } else {
    db.pragma('foreign_keys = ON');
    db.pragma('busy_timeout = 10000');
  }
  return db;
}

export function runMigrations(db: Db): number {
  const current = Number((db.pragma('user_version', { simple: true }) as number) ?? 0);
  if (current >= LATEST_VERSION) return current;
  for (const m of MIGRATIONS) {
    if (m.version <= current) continue;
    db.exec('BEGIN');
    try {
      db.exec(m.sql);
      db.pragma(`user_version = ${m.version}`);
      db.exec('COMMIT');
    } catch (err) {
      db.exec('ROLLBACK');
      throw new Error(`migration ${m.version} (${m.name}) failed: ${(err as Error).message}`);
    }
  }
  return LATEST_VERSION;
}

export function schemaVersion(db: Db): number {
  return Number((db.pragma('user_version', { simple: true }) as number) ?? 0);
}

/**
 * Write a consistent snapshot to `dest` using SQLite's backup API, which is
 * safe while WAL writers are active. The copy stays encrypted with the same key.
 */
export function backupTo(db: Db, dest: string): void {
  db.exec(`VACUUM INTO '${dest.replace(/'/g, "''")}'`);
}
