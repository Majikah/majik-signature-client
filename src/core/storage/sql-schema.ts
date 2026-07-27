import {
  MAJIKAH_SQL_SCHEMA_MAJIK_CLIENT_STATE,
  MAJIKAH_SQL_SCHEMA_MAJIK_KEYS,
  MAJIKAH_SQL_TABLE_MAJIK_KEY,
  MAJIKAH_SQL_TABLE_MAJIK_KEY_CLIENT_STATE,
} from "@majikah/majik-key-client";

type MajikahSQLSchema = string;

/**
 * Centralized SQLite table registry.
 * - `as const` keeps literal types
 * - `MajikahSQLTable` becomes a strict union type
 */
export const MAJIKAH_SQL_TABLES = {
  MAJIK_CLIENT_STATE: MAJIKAH_SQL_TABLE_MAJIK_KEY_CLIENT_STATE,
  MAJIK_KEYS: MAJIKAH_SQL_TABLE_MAJIK_KEY,
  MAJIK_CONTACTS: "majik_contacts",
  MAJIK_CONTACT_GROUPS: "majik_contact_groups",
  MAJIK_SIGNATURE_STAMPS: "majik_signature_stamps",
} as const;

export type MajikahSQLTable =
  (typeof MAJIKAH_SQL_TABLES)[keyof typeof MAJIKAH_SQL_TABLES];

function normalizeSQL(sql: MajikahSQLSchema): string {
  return sql
    .trim()
    .replace(/\s+/g, " ") // collapse all whitespace
    .toLowerCase();
}

export function buildSchemaSQL(schemas: MajikahSQLSchema[]): MajikahSQLSchema {
  const seen = new Set<MajikahSQLSchema>();

  return schemas
    .map((schema) => schema.trim())
    .filter(Boolean)
    .filter((schema) => {
      const normalized = normalizeSQL(schema);

      if (seen.has(normalized)) return false; // silently skip
      seen.add(normalized);

      return true;
    })
    .join("\n\n");
}

export const MAJIKAH_SQL_SCHEMA_MAJIK_CONTACTS: MajikahSQLSchema = `
CREATE TABLE IF NOT EXISTS ${MAJIKAH_SQL_TABLES.MAJIK_CONTACTS} (
  id TEXT PRIMARY KEY,
  json TEXT NOT NULL,
  fingerprint TEXT,
  label TEXT,
  created_at TEXT,
  updated_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_majik_contacts_created_at
ON ${MAJIKAH_SQL_TABLES.MAJIK_CONTACTS}(created_at);
`;

export const MAJIKAH_SQL_SCHEMA_MAJIK_CONTACT_GROUPS: MajikahSQLSchema = `
CREATE TABLE IF NOT EXISTS ${MAJIKAH_SQL_TABLES.MAJIK_CONTACT_GROUPS} (
  id TEXT PRIMARY KEY,
  json TEXT NOT NULL,
  name TEXT,
  created_at TEXT,
  updated_at TEXT,
  is_system INTEGER DEFAULT 0 CHECK(is_system IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_majik_contact_groups_created_at
ON ${MAJIKAH_SQL_TABLES.MAJIK_CONTACT_GROUPS}(created_at);
`;

export const MAJIKAH_SQL_SCHEMA_MAJIK_SIGNATURE_STAMPS: MajikahSQLSchema = `
CREATE TABLE IF NOT EXISTS ${MAJIKAH_SQL_TABLES.MAJIK_SIGNATURE_STAMPS} (
  id TEXT PRIMARY KEY,
  json TEXT NOT NULL,
  kind TEXT NOT NULL,
  name TEXT NOT NULL,
  mime_type TEXT,
  size_bytes INTEGER NOT NULL,
  fingerprint TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_majik_signature_stamps_kind
ON ${MAJIKAH_SQL_TABLES.MAJIK_SIGNATURE_STAMPS}(kind);

CREATE INDEX IF NOT EXISTS idx_majik_signature_stamps_fingerprint
ON ${MAJIKAH_SQL_TABLES.MAJIK_SIGNATURE_STAMPS}(fingerprint);

CREATE INDEX IF NOT EXISTS idx_majik_signature_stamps_updated_at
ON ${MAJIKAH_SQL_TABLES.MAJIK_SIGNATURE_STAMPS}(updated_at);

CREATE INDEX IF NOT EXISTS idx_majik_signature_stamps_fingerprint_kind
ON ${MAJIKAH_SQL_TABLES.MAJIK_SIGNATURE_STAMPS}(fingerprint, kind);
`;

export const MAJIKAH_SQL_SCHEMA_FULL: MajikahSQLSchema = buildSchemaSQL([
  MAJIKAH_SQL_SCHEMA_MAJIK_CLIENT_STATE,
  MAJIKAH_SQL_SCHEMA_MAJIK_KEYS,
  MAJIKAH_SQL_SCHEMA_MAJIK_CONTACTS,
  MAJIKAH_SQL_SCHEMA_MAJIK_CONTACT_GROUPS,
  MAJIKAH_SQL_SCHEMA_MAJIK_SIGNATURE_STAMPS,
]);
