// src/storage/adapters/log/idb-history-log-adapter.ts
import { HistoryLogJSON } from "../../../log/core/types";
import { IDBGenericAdapter } from "../../idb-adapter";

const IDB_DB_NAME = "majik-signature-history-logs";
const IDB_STORE_NAME = "history-logs";
const IDB_VERSION = 1;

export const IDB_ADAPTER_HISTORY_LOG = new IDBGenericAdapter<HistoryLogJSON>(
  IDB_DB_NAME,
  IDB_STORE_NAME,
  IDB_VERSION,
);
