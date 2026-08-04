// src/log/history-log-manager.ts
import { HistoryLog, CreateHistoryLogOptions } from "./core/history-log";
import { HistoryLogJSON } from "./core/types";
import { HistoryType, HistoryStatus } from "./core/enums";
import { BaseLogManager } from "./core/log-manager";
import { HistoryLogStorageAdapter } from "../storage/logs/history/_types";
import { IN_MEMORY_ADAPTER_HISTORY_LOG } from "../storage/logs/history/adapter-memory";
import { StorageSource } from "../storage";

export class HistoryLogManager extends BaseLogManager<
  HistoryLogJSON,
  HistoryLog
> {
  protected readonly entityName = "HistoryLog";

  constructor(adapter?: HistoryLogStorageAdapter) {
    super(adapter ?? IN_MEMORY_ADAPTER_HISTORY_LOG);
  }

  protected deserialize(json: HistoryLogJSON, binary?: Uint8Array): HistoryLog {
    return HistoryLog.fromJSON(json, binary);
  }

  async create(
    options: CreateHistoryLogOptions,
    source?: StorageSource,
  ): Promise<HistoryLog> {
    const entry = await HistoryLog.create(options);
    return this._store(entry, source);
  }

  static async fromJSON(
    data: HistoryLogJSON[],
    adapter?: HistoryLogStorageAdapter,
  ): Promise<HistoryLogManager> {
    const manager = new HistoryLogManager(adapter);
    await manager.bulkRestoreFromJSON(data);
    return manager;
  }

  // ── HistoryLog-specific convenience filters ─────────────────────────────

  listByHistoryType(historyType: HistoryType): HistoryLog[] {
    return this.list().filter((e) => e.historyType === historyType);
  }

  listByStatus(status: HistoryStatus): HistoryLog[] {
    return this.list().filter((e) => e.status === status);
  }
}
