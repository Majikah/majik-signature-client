import { MajikSignatureStampJSON } from "../../stamp/majik-signature-stamp";

import { MajikSignatureStampStorageAdapter } from "./_types";
import { SQLiteDatabase } from "../sql-db-manager";
import { MAJIKAH_SQL_TABLES } from "../sql-schema";
import { StorageQuery } from "../storage-adapter";

export class SQLiteStampstoreAdapter implements MajikSignatureStampStorageAdapter {
  constructor(private db: SQLiteDatabase) {}

  async save(stamp: MajikSignatureStampJSON): Promise<void> {
    await this.db.run(
      `INSERT OR REPLACE INTO ${MAJIKAH_SQL_TABLES.MAJIK_SIGNATURE_STAMPS}
       (id, json, kind, name, mime_type, size_bytes, fingerprint, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        stamp.id,
        JSON.stringify(stamp),
        stamp.kind,
        stamp.name,
        stamp.mimeType,
        stamp.sizeBytes,
        stamp.fingerprint,
        stamp.timestamp,
        stamp.lastUpdate,
      ],
    );
  }

  async getById(id: string): Promise<MajikSignatureStampJSON | null> {
    const row = await this.db.get<{ json: string }>(
      `SELECT json FROM ${MAJIKAH_SQL_TABLES.MAJIK_SIGNATURE_STAMPS} WHERE id = ?`,
      [id],
    );
    return row ? JSON.parse(row.json) : null;
  }

  async list(): Promise<MajikSignatureStampJSON[]> {
    const rows = await this.db.all<{ json: string }>(
      `SELECT json FROM ${MAJIKAH_SQL_TABLES.MAJIK_SIGNATURE_STAMPS}`,
    );
    return rows.map((r) => JSON.parse(r.json));
  }

  async remove(id: string): Promise<boolean> {
    const exists = await this.exists(id);
    if (!exists) return false;
    await this.db.run(
      `DELETE FROM ${MAJIKAH_SQL_TABLES.MAJIK_SIGNATURE_STAMPS} WHERE id = ?`,
      [id],
    );
    return true;
  }

  async clear(): Promise<void> {
    await this.db.run(
      `DELETE FROM ${MAJIKAH_SQL_TABLES.MAJIK_SIGNATURE_STAMPS}`,
    );
  }

  async count(): Promise<number> {
    const row = await this.db.get<{ n: number }>(
      `SELECT COUNT(*) as n FROM ${MAJIKAH_SQL_TABLES.MAJIK_SIGNATURE_STAMPS}`,
    );
    return row?.n ?? 0;
  }

  async exists(id: string): Promise<boolean> {
    const row = await this.db.get(
      `SELECT 1 FROM ${MAJIKAH_SQL_TABLES.MAJIK_SIGNATURE_STAMPS} WHERE id = ?`,
      [id],
    );
    return !!row;
  }

  async bulkSave(stamps: MajikSignatureStampJSON[]): Promise<void> {
    if (stamps.length === 0) return;
    await this.db.transaction(async (tx) => {
      for (const s of stamps) {
        await tx.run(
          `INSERT OR REPLACE INTO ${MAJIKAH_SQL_TABLES.MAJIK_SIGNATURE_STAMPS}
           (id, json, kind, name, mime_type, size_bytes, fingerprint, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            s.id,
            JSON.stringify(s),
            s.kind,
            s.name,
            s.mimeType,
            s.sizeBytes,
            s.fingerprint,
            s.timestamp,
            s.lastUpdate,
          ],
        );
      }
    });
  }

  async bulkRemove(ids: string[]): Promise<void> {
    if (ids.length === 0) return;
    await this.db.transaction(async (tx) => {
      for (const id of ids) {
        await tx.run(
          `DELETE FROM ${MAJIKAH_SQL_TABLES.MAJIK_SIGNATURE_STAMPS} WHERE id = ?`,
          [id],
        );
      }
    });
  }

  async query(
    query: StorageQuery<MajikSignatureStampJSON>,
  ): Promise<MajikSignatureStampJSON[]> {
    const clauses: string[] = [];
    const values: any[] = [];

    if (query.where) {
      for (const [key, value] of Object.entries(query.where)) {
        clauses.push(`${key} = ?`);
        values.push(value);
      }
    }

    let sql = `SELECT json FROM ${MAJIKAH_SQL_TABLES.MAJIK_SIGNATURE_STAMPS}`;
    if (clauses.length > 0) sql += ` WHERE ${clauses.join(" AND ")}`;
    if (query.orderBy)
      sql += ` ORDER BY ${String(query.orderBy)} ${query.orderDirection ?? "asc"}`;
    if (query.limit) sql += ` LIMIT ${query.limit}`;
    if (query.offset) sql += ` OFFSET ${query.offset}`;

    const rows = await this.db.all<{ json: string }>(sql, values);
    return rows.map((r) => JSON.parse(r.json));
  }
}
