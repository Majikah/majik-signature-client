// src/storage/adapters/log/sql-log-adapter-base.ts

import { BaseLogJSON } from "../../../log/core/types";
import { LogType } from "../../../log/core/enums";
import {
  MajikStorageAdapter,
  StorageQuery,
  StorageSource,
} from "../../storage-adapter";
import { SQLiteDatabase } from "../../sql-db-manager";

export interface SQLiteLogColumn<TJSON> {
  /** Kept identical to the JSON property name on purpose — StorageQuery.where
   *  keys then map straight onto SQL columns with no snake_case translation
   *  layer to keep in sync (see caveat on SQLiteStampstoreAdapter.query()). */
  name: keyof TJSON & string;
  value: (item: TJSON) => unknown;
}

/**
 * Shared SQLite behavior for any log JSON shape (HistoryLogJSON,
 * UserActivityLogJSON, ...). Mirrors SQLiteStampstoreAdapter: the full
 * record is stored as a `json` blob (source of truth for getById/list),
 * plus a handful of indexed columns so query() can filter at the SQL layer.
 *
 * Subclasses supply `tableName` and `extraColumns` — only the fields worth
 * indexing beyond the common envelope (id, reference_id, type, fingerprint,
 * version, timestamp), which this base handles once.
 */
export abstract class SQLiteLogAdapterBase<
  TJSON extends BaseLogJSON<LogType>,
> implements MajikStorageAdapter<TJSON> {
  protected abstract readonly tableName: string;
  protected abstract readonly extraColumns: SQLiteLogColumn<TJSON>[];

  constructor(protected db: SQLiteDatabase) {}

  private get commonColumns(): SQLiteLogColumn<TJSON>[] {
    return [
      { name: "reference_id" as const, value: (i) => i.reference_id },
      { name: "type" as const, value: (i) => i.type },
      { name: "fingerprint" as const, value: (i) => i.fingerprint },
      { name: "version" as const, value: (i) => i.version },
      { name: "timestamp" as const, value: (i) => i.timestamp },
    ] as SQLiteLogColumn<TJSON>[];
  }

  private get allColumns(): SQLiteLogColumn<TJSON>[] {
    return [...this.commonColumns, ...this.extraColumns];
  }

  private buildInsertSql(): string {
    const cols = ["id", "json", ...this.allColumns.map((c) => c.name)];
    return `INSERT OR REPLACE INTO ${this.tableName} (${cols.join(", ")}) VALUES (${cols.map(() => "?").join(", ")})`;
  }

  private buildInsertValues(item: TJSON): unknown[] {
    return [
      item.id,
      JSON.stringify(item),
      ...this.allColumns.map((c) => c.value(item)),
    ];
  }

  async save(item: TJSON, _source?: StorageSource): Promise<void> {
    await this.db.run(this.buildInsertSql(), this.buildInsertValues(item));
  }

  async getById(id: string, _source?: StorageSource): Promise<TJSON | null> {
    const row = await this.db.get<{ json: string }>(
      `SELECT json FROM ${this.tableName} WHERE id = ?`,
      [id],
    );
    return row ? JSON.parse(row.json) : null;
  }

  async list(_source?: StorageSource): Promise<TJSON[]> {
    const rows = await this.db.all<{ json: string }>(
      `SELECT json FROM ${this.tableName}`,
    );
    return rows.map((r) => JSON.parse(r.json));
  }

  async remove(id: string, _source?: StorageSource): Promise<boolean> {
    if (!(await this.exists(id))) return false;
    await this.db.run(`DELETE FROM ${this.tableName} WHERE id = ?`, [id]);
    return true;
  }

  async clear(_source?: StorageSource): Promise<void> {
    await this.db.run(`DELETE FROM ${this.tableName}`);
  }

  async count(_source?: StorageSource): Promise<number> {
    const row = await this.db.get<{ n: number }>(
      `SELECT COUNT(*) as n FROM ${this.tableName}`,
    );
    return row?.n ?? 0;
  }

  async exists(id: string, _source?: StorageSource): Promise<boolean> {
    const row = await this.db.get(
      `SELECT 1 FROM ${this.tableName} WHERE id = ?`,
      [id],
    );
    return !!row;
  }

  async bulkSave(items: TJSON[], _source?: StorageSource): Promise<void> {
    if (items.length === 0) return;
    const sql = this.buildInsertSql();
    await this.db.transaction(async (tx) => {
      for (const item of items) await tx.run(sql, this.buildInsertValues(item));
    });
  }

  async bulkRemove(ids: string[], _source?: StorageSource): Promise<void> {
    if (ids.length === 0) return;
    await this.db.transaction(async (tx) => {
      for (const id of ids)
        await tx.run(`DELETE FROM ${this.tableName} WHERE id = ?`, [id]);
    });
  }

  async query(
    query: StorageQuery<TJSON>,
    _source?: StorageSource,
  ): Promise<TJSON[]> {
    const indexed = new Set(this.allColumns.map((c) => c.name));
    const clauses: string[] = [];
    const values: unknown[] = [];

    if (query.where) {
      for (const [key, value] of Object.entries(query.where)) {
        if (!indexed.has(key as keyof TJSON & string)) {
          throw new Error(
            `${this.tableName}.query: "${key}" is not an indexed column — add it to extraColumns to make it queryable.`,
          );
        }
        clauses.push(`${key} = ?`);
        values.push(value);
      }
    }

    let sql = `SELECT json FROM ${this.tableName}`;
    if (clauses.length) sql += ` WHERE ${clauses.join(" AND ")}`;
    if (query.orderBy && indexed.has(query.orderBy as keyof TJSON & string)) {
      sql += ` ORDER BY ${String(query.orderBy)} ${query.orderDirection ?? "asc"}`;
    }
    if (query.limit) sql += ` LIMIT ${query.limit}`;
    if (query.offset) sql += ` OFFSET ${query.offset}`;

    const rows = await this.db.all<{ json: string }>(sql, values);
    return rows.map((r) => JSON.parse(r.json));
  }
}
