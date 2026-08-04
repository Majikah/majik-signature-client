// src/storage/adapters/log/sql-history-log-adapter.ts
import { HistoryLogJSON } from "../../../log/core/types";
import { SQLiteDatabase } from "../../sql-db-manager";
import { MAJIKAH_SQL_TABLES } from "../../sql-schema";
import { SQLiteLogAdapterBase, SQLiteLogColumn } from "../core/adapter-sql";

export class SQLiteHistoryLogAdapter extends SQLiteLogAdapterBase<HistoryLogJSON> {
  protected readonly tableName = MAJIKAH_SQL_TABLES.HISTORY_LOGS;

  protected readonly extraColumns: SQLiteLogColumn<HistoryLogJSON>[] = [
    { name: "historyType", value: (i) => i.historyType },
    { name: "status", value: (i) => i.status },
    { name: "source", value: (i) => i.source },
    { name: "network", value: (i) => i.network ?? null },
    { name: "transactionId", value: (i) => i.transactionId ?? null },
  ];

  constructor(db: SQLiteDatabase) {
    super(db);
  }
}
