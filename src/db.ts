import { Database } from "bun:sqlite";
import { DB_PATH } from "./config.ts";

export const db = new Database(DB_PATH);

export function initDb() {
  db.exec("PRAGMA journal_mode = WAL");
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      client_secret TEXT NOT NULL,
      machine INTEGER NOT NULL DEFAULT 1,
      admin INTEGER NOT NULL DEFAULT 0,
      active INTEGER NOT NULL DEFAULT 1,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS groups (
      id TEXT PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS group_members (
      group_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      PRIMARY KEY (group_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS signing_keys (
      id TEXT PRIMARY KEY,
      private_key TEXT NOT NULL,
      public_key TEXT NOT NULL,
      active INTEGER NOT NULL,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS scim_targets (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      url TEXT NOT NULL,
      token TEXT NOT NULL,
      active INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS bootstrap (
      token_hash TEXT NOT NULL,
      consumed INTEGER NOT NULL DEFAULT 0
    );
  `);
}
