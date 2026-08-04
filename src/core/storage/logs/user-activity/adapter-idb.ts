// src/storage/adapters/log/idb-history-log-adapter.ts
import { UserActivityLogJSON } from "../../../log/core/types";
import { IDBGenericAdapter } from "../../idb-adapter";

const IDB_DB_NAME = "majik-signature-user-activity-logs";
const IDB_STORE_NAME = "audit-logs";
const IDB_VERSION = 1;

export const IDB_ADAPTER_USER_ACTIVITY_LOG =
  new IDBGenericAdapter<UserActivityLogJSON>(
    IDB_DB_NAME,
    IDB_STORE_NAME,
    IDB_VERSION,
  );
