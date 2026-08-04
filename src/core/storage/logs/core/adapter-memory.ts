import { MajikStorageAdapter, StorageQuery } from "../../storage-adapter";

/**
 * Generic in-memory adapter for any log JSON shape. Structurally identical
 * to InMemoryStampstoreAdapter — extracted as one generic class here so
 * HistoryLog/UserActivityLog don't need near-duplicate implementations.
 */
export class InMemoryLogAdapter<
  T extends { id: string },
> implements MajikStorageAdapter<T> {
  private _store: Map<string, T> = new Map();

  async save(item: T): Promise<void> {
    this._store.set(item.id, item);
  }
  async getById(id: string): Promise<T | null> {
    return this._store.get(id) ?? null;
  }
  async list(): Promise<T[]> {
    return Array.from(this._store.values());
  }
  async remove(id: string): Promise<boolean> {
    return this._store.delete(id);
  }
  async clear(): Promise<void> {
    this._store.clear();
  }
  async count(): Promise<number> {
    return this._store.size;
  }
  async exists(id: string): Promise<boolean> {
    return this._store.has(id);
  }
  async bulkSave(items: T[]): Promise<void> {
    for (const item of items) this._store.set(item.id, item);
  }
  async bulkRemove(ids: string[]): Promise<void> {
    for (const id of ids) this._store.delete(id);
  }
  async query(query: StorageQuery<T>): Promise<T[]> {
    let results = Array.from(this._store.values());
    if (query.where) {
      const where = query.where;
      results = results.filter((item) =>
        (Object.keys(where) as (keyof T)[]).every((k) => item[k] === where[k]),
      );
    }
    if (query.orderBy) {
      const key = query.orderBy;
      const dir = query.orderDirection === "desc" ? -1 : 1;
      results.sort((a, b) =>
        a[key] === b[key] ? 0 : a[key] > b[key] ? dir : -dir,
      );
    }
    if (query.offset) results = results.slice(query.offset);
    if (query.limit) results = results.slice(0, query.limit);
    return results;
  }
}
