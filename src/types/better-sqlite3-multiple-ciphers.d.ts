/**
 * Type shim.
 *
 * better-sqlite3-multiple-ciphers ships an index.d.ts but its package.json
 * "exports" map does not expose it, so NodeNext resolution cannot find it. The
 * API is better-sqlite3's plus the cipher key-management methods.
 */
declare module 'better-sqlite3-multiple-ciphers' {
  import type BetterSqlite3 from 'better-sqlite3';

  namespace Database {
    interface Database extends BetterSqlite3.Database {
      /** Apply the encryption key. Must be called before any statement runs. */
      key(key: Buffer | string): void;
      /** Re-encrypt an open database under a new key. */
      rekey(key: Buffer | string): void;
    }
    type Options = BetterSqlite3.Options;
    type Statement<P extends unknown[] = unknown[], R = unknown> = BetterSqlite3.Statement<P, R>;
    type Transaction<F extends (...a: never[]) => unknown = (...a: never[]) => unknown> =
      BetterSqlite3.Transaction<F>;
  }

  const Database: {
    new (filename: string, options?: Database.Options): Database.Database;
    (filename: string, options?: Database.Options): Database.Database;
  };

  export = Database;
}
