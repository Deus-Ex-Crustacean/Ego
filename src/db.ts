import { Database } from "bun:sqlite";
import { DB_PATH } from "./config.ts";

export const db = new Database(DB_PATH);

export function initDb() {
  db.exec("PRAGMA journal_mode = WAL");
  db.exec(`
    CREATE TABLE IF NOT EXISTS workspaces (
      id TEXT PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      client_secret TEXT NOT NULL,
      admin INTEGER NOT NULL DEFAULT 0,
      active INTEGER NOT NULL DEFAULT 1,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS signing_keys (
      id TEXT PRIMARY KEY,
      private_key TEXT NOT NULL,
      public_key TEXT NOT NULL,
      active INTEGER NOT NULL,
      created_at INTEGER NOT NULL
    );
  `);
}
