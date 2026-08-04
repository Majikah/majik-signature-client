// src/log/user-activity-log-manager.ts

import { UserActivityLogJSON } from "./core/types";

import { BaseLogManager } from "./core/log-manager";

import { StorageSource } from "../storage";
import { IN_MEMORY_ADAPTER_USER_ACTIVITY_LOG } from "../storage/logs/user-activity/adapter-memory";
import {
  CreateUserActivityLogOptions,
  UserActivityLog,
} from "./core/user-activity-log";
import { UserActivityLogStorageAdapter } from "../storage/logs/user-activity/_types";
import { AuditAction } from "./core/enums";

export class UserActivityLogManager extends BaseLogManager<
  UserActivityLogJSON,
  UserActivityLog
> {
  protected readonly entityName = "UserActivityLog";

  constructor(adapter?: UserActivityLogStorageAdapter) {
    super(adapter ?? IN_MEMORY_ADAPTER_USER_ACTIVITY_LOG);
  }

  protected deserialize(
    json: UserActivityLogJSON,
    binary?: Uint8Array,
  ): UserActivityLog {
    return UserActivityLog.fromJSON(json, binary);
  }

  async create(
    options: CreateUserActivityLogOptions,
    source?: StorageSource,
  ): Promise<UserActivityLog> {
    const entry = await UserActivityLog.create(options);
    return this._store(entry, source);
  }

  static async fromJSON(
    data: UserActivityLogJSON[],
    adapter?: UserActivityLogStorageAdapter,
  ): Promise<UserActivityLogManager> {
    const manager = new UserActivityLogManager(adapter);
    await manager.bulkRestoreFromJSON(data);
    return manager;
  }

  // ── UserActivityLog-specific convenience filter ─────────────────────────

  listByAction(action: AuditAction): UserActivityLog[] {
    return this.list().filter((e) => e.action === action);
  }
}
