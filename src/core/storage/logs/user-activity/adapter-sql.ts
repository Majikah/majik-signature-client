// src/storage/adapters/log/sql-audit-log-adapter.ts
import { UserActivityLogJSON } from "../../../log/core/types";
import { SQLiteDatabase } from "../../sql-db-manager";
import { MAJIKAH_SQL_TABLES } from "../../sql-schema";
import { SQLiteLogAdapterBase, SQLiteLogColumn } from "../core/adapter-sql";

export class SQLiteUserActivityLogAdapter extends SQLiteLogAdapterBase<UserActivityLogJSON> {
  protected readonly tableName = MAJIKAH_SQL_TABLES.USER_ACTIVITY_LOGS;

  protected readonly extraColumns: SQLiteLogColumn<UserActivityLogJSON>[] = [
    { name: "action", value: (i) => i.action },
  ];

  constructor(db: SQLiteDatabase) {
    super(db);
  }
}
