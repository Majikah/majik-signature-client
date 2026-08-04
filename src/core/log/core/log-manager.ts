// src/log/core/log-manager.ts
import { MajikFileDecryptIdentity } from "@majikah/majik-file";
import {
  MajikStorageAdapter,
  StorageQuery,
  StorageSource,
} from "../../storage/storage-adapter";
import { BaseLog } from "./log-entry";
import { BaseLogJSON } from "./types";
import { LogType } from "./enums";

export class LogManagerError extends Error {
  cause?: unknown;
  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = "LogManagerError";
    this.cause = cause;
  }
}

/**
 * Shared manager behavior for every log type (HistoryLog, UserActivityLog, ...).
 * Handles caching, persistence, decrypt-on-hydrate, and querying against the
 * BaseLogJSON envelope shape common to all log subclasses.
 *
 * Subclasses only need to supply `deserialize()` (their model's own
 * `fromJSON`) and their own typed `create()`, since creation options differ
 * per log type (CreateHistoryLogOptions vs CreateUserActivityLogOptions).
 * Unlike MajikSignatureStampManager, there's deliberately no rename()/
 * replaceContent() here — log entries are an audit trail, not editable assets.
 */
export abstract class BaseLogManager<
  TJSON extends BaseLogJSON<LogType>,
  TLog extends BaseLog<LogType>,
> {
  protected readonly _cache = new Map<string, TLog>();
  protected readonly _decryptErrors = new Map<string, string>();
  protected _adapter: MajikStorageAdapter<TJSON>;

  /** Used only for readable error messages, e.g. "HistoryLog not found: <id>". */
  protected abstract readonly entityName: string;

  protected constructor(adapter: MajikStorageAdapter<TJSON>) {
    this._adapter = adapter;
  }

  /** Rehydrates a concrete TLog instance from its JSON form. Delegates to
   *  the model's own static `fromJSON` (e.g. HistoryLog.fromJSON). */
  protected abstract deserialize(json: TJSON, binary?: Uint8Array): TLog;

  get adapter(): MajikStorageAdapter<TJSON> {
    return this._adapter;
  }

  setAdapter(adapter: MajikStorageAdapter<TJSON>): void {
    this._adapter = adapter;
  }

  // ── Hydration ─────────────────────────────────────────────────────────

  async hydrate(source?: StorageSource): Promise<void> {
    this._cache.clear();
    const all = await this._adapter.list(source);
    for (const json of all) {
      try {
        const entry = this.deserialize(json);
        this._cache.set(entry.id, entry);
      } catch (err) {
        console.warn(
          `${this.constructor.name}.hydrate: skipping malformed ${this.entityName} "${json?.id}":`,
          err,
        );
      }
    }
  }

  /**
   * Hydrate every log entry for `fingerprint`. If `identity` is given, each
   * entry's envelope is decrypted eagerly via `decryptContent()` so
   * `decryptedBytes` is ready immediately. Entries that fail to decrypt are
   * silently excluded from the cache — never a hard throw. Reasons are kept
   * in `getDecryptError()` for optional diagnostics.
   */
  async hydrateForFingerprint(
    fingerprint: string,
    identity?: MajikFileDecryptIdentity,
    source?: StorageSource,
  ): Promise<void> {
    this._cache.clear();
    this._decryptErrors.clear();

    const rows = this._adapter.query
      ? await this._adapter.query(
          { where: { fingerprint } as Partial<TJSON> },
          source,
        )
      : (await this._adapter.list(source)).filter(
          (r) => r.fingerprint === fingerprint,
        );

    const entries: TLog[] = [];
    for (const json of rows) {
      try {
        entries.push(this.deserialize(json));
      } catch (err) {
        console.warn(
          `${this.constructor.name}.hydrateForFingerprint: skipping malformed ${this.entityName} "${json?.id}":`,
          err,
        );
      }
    }

    if (!identity) {
      for (const e of entries) this._cache.set(e.id, e);
      return;
    }

    const results = await Promise.allSettled(
      entries.map((entry) => entry.decryptContent(identity)),
    );

    results.forEach((result, i) => {
      const entry = entries[i];
      if (result.status === "fulfilled") {
        this._cache.set(entry.id, entry);
      } else {
        this._decryptErrors.set(
          entry.id,
          result.reason instanceof Error
            ? result.reason.message
            : String(result.reason),
        );
      }
    });
  }

  getDecryptError(id: string): string | undefined {
    return this._decryptErrors.get(id);
  }

  // ── Serialization ─────────────────────────────────────────────────────

  async toJSON(source?: StorageSource): Promise<TJSON[]> {
    return this._adapter.list(source);
  }

  async bulkRestoreFromJSON(
    data: TJSON[],
    source?: StorageSource,
  ): Promise<void> {
    if (!Array.isArray(data)) {
      throw new LogManagerError(
        `bulkRestoreFromJSON: expected ${this.entityName}JSON[]`,
      );
    }
    await this._adapter.bulkSave(data, source);
    await this.hydrate(source);
  }

  protected async _persist(entry: TLog, source?: StorageSource): Promise<void> {
    await this._adapter.save(entry.toJSON() as unknown as TJSON, source);
  }

  /** Persists a freshly created entry and caches it. Subclasses call this
   *  from their own typed `create()` after building the entry via their
   *  model's static `create()` factory. */
  protected async _store(entry: TLog, source?: StorageSource): Promise<TLog> {
    await this._persist(entry, source);
    this._cache.set(entry.id, entry);
    return entry;
  }

  // ── Core CRUD ───────────────────────────────────────────────────────────

  async save(entry: TLog, source?: StorageSource): Promise<void> {
    await this._persist(entry, source);
    this._cache.set(entry.id, entry);
  }

  async load(id: string, source?: StorageSource): Promise<TLog | null> {
    const cached = this._cache.get(id);
    if (cached) return cached;
    const json = await this._adapter.getById(id, source);
    if (!json) return null;
    const entry = this.deserialize(json);
    this._cache.set(entry.id, entry);
    return entry;
  }

  async getOrThrow(id: string, source?: StorageSource): Promise<TLog> {
    const entry = await this.load(id, source);
    if (!entry) {
      throw new LogManagerError(`${this.entityName} not found: ${id}`);
    }
    return entry;
  }

  async loadAll(source?: StorageSource): Promise<TLog[]> {
    const all = await this._adapter.list(source);
    for (const json of all) {
      if (!this._cache.has(json.id)) {
        try {
          const entry = this.deserialize(json);
          this._cache.set(entry.id, entry);
        } catch (err) {
          console.warn(
            `${this.constructor.name}.loadAll: skipping malformed ${this.entityName} "${json?.id}":`,
            err,
          );
        }
      }
    }
    return [...this._cache.values()];
  }

  async delete(id: string, source?: StorageSource): Promise<void> {
    await this._adapter.remove(id, source);
    this._cache.delete(id);
  }

  async has(id: string, source?: StorageSource): Promise<boolean> {
    if (this._cache.has(id)) return true;
    return this._adapter.exists(id, source);
  }

  async count(source?: StorageSource): Promise<number> {
    return this._adapter.count(source);
  }

  get(id: string): TLog | undefined {
    return this._cache.get(id);
  }

  list(): TLog[] {
    return [...this._cache.values()];
  }

  listByReferenceId(reference_id: string): TLog[] {
    return this.list().filter((e) => e.reference_id === reference_id);
  }

  listByFingerprint(fingerprint: string): TLog[] {
    return this.list().filter((e) => e.fingerprint === fingerprint);
  }

  async query(
    query: StorageQuery<TJSON>,
    source?: StorageSource,
  ): Promise<TJSON[]> {
    if (!this._adapter.query) {
      throw new LogManagerError(
        "query: current adapter does not support query()",
      );
    }
    return this._adapter.query(query, source);
  }

  async decryptContent(
    id: string,
    identity: MajikFileDecryptIdentity,
  ): Promise<Uint8Array> {
    const entry = await this.getOrThrow(id);
    return entry.decryptContent(identity);
  }

  async bulkRemove(ids: string[], source?: StorageSource): Promise<void> {
    if (ids.length === 0) return;
    await this._adapter.bulkRemove(ids, source);
    for (const id of ids) this._cache.delete(id);
  }
}
