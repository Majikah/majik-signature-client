import { MajikSignatureStampJSON } from "../../stamp/majik-signature-stamp";

import { MajikSignatureStampStorageAdapter } from "./_types";

export class InMemoryStampstoreAdapter implements MajikSignatureStampStorageAdapter {
  private _store: Map<string, MajikSignatureStampJSON> = new Map();

  async save(item: MajikSignatureStampJSON): Promise<void> {
    this._store.set(item.id, item);
  }
  async getById(id: string): Promise<MajikSignatureStampJSON | null> {
    return this._store.get(id) ?? null;
  }
  async list(): Promise<MajikSignatureStampJSON[]> {
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
  async bulkSave(items: MajikSignatureStampJSON[]): Promise<void> {
    for (const item of items) this._store.set(item.id, item);
  }
  async bulkRemove(ids: string[]): Promise<void> {
    for (const id of ids) this._store.delete(id);
  }
}
