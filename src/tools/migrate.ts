/**
 * Apply pending schema migrations. Safe to run repeatedly; a no-op when the
 * database is already current.
 *
 *   node dist/tools/migrate.js
 */
import { loadStorageConfig } from '../shared/config.js';
import { openDatabase, runMigrations, schemaVersion } from '../shared/db.js';
import { LATEST_VERSION } from '../shared/schema.js';

const storage = loadStorageConfig();
const db = openDatabase({ path: storage.dbPath, key: storage.dbKey, migrate: false });
const before = schemaVersion(db);
const after = runMigrations(db);
db.close();

process.stdout.write(
  JSON.stringify({ database: storage.dbPath, from: before, to: after, latest: LATEST_VERSION }) + '\n',
);
