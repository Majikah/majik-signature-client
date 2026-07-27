import {
  MajikFile,
  type BatchLockResult,
  type MajikFileIdentity,
} from "@majikah/majik-file";
import {
  MajikSignatureStamp,
  MajikSignatureStampJSON,
  StampAssetKind,
  CreateStampOptions,
} from "./majik-signature-stamp";

import { StorageQuery } from "../storage/storage-adapter";
import {
  InMemoryStampstoreAdapter,
  MajikSignatureStampStorageAdapter,
} from "../storage";
import { MajikKey } from "@majikah/majik-key";

export class MajikSignatureStampManagerError extends Error {
  cause?: unknown;
  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = "MajikSignatureStampManagerError";
    this.cause = cause;
  }
}

export class MajikSignatureStampManager {
  private readonly _cache = new Map<string, MajikSignatureStamp>();
  private _decryptErrors = new Map<string, string>();

  private _adapter: MajikSignatureStampStorageAdapter;

  constructor(adapter?: MajikSignatureStampStorageAdapter) {
    this._adapter = adapter ?? new InMemoryStampstoreAdapter();
  }

  get adapter(): MajikSignatureStampStorageAdapter {
    return this._adapter;
  }

  setAdapter(adapter: MajikSignatureStampStorageAdapter): void {
    this._adapter = adapter;
  }

  // ── Hydration ─────────────────────────────────────────────────────────
  async hydrate(): Promise<void> {
    this._cache.clear();
    const all = await this._adapter.list();
    for (const json of all) {
      try {
        const stamp = MajikSignatureStamp.fromJSON(json);
        this._cache.set(stamp.id, stamp);
      } catch (err) {
        console.warn(
          `MajikSignatureStampManager.hydrate: skipping malformed stamp "${json?.id}":`,
          err,
        );
      }
    }
  }

  /**
   * Hydrate every stamp for `fingerprint`. If `key` is given (must be
   * unlocked, matching that fingerprint), each stamp is decrypted so its
   * plaintext is ready for preview. Stamps that fail to decrypt are
   * silently excluded from the cache — never a hard throw. Reasons are
   * kept in getDecryptError() for optional diagnostics.
   *
   * NOTE: this intentionally does NOT call MajikFile.batchDecrypt() —
   * that method gates on MajikFile.canDecrypt(), which currently compares
   * key.fingerprint against a list of public keys and will reject every
   * file. Once that's fixed upstream, this can call batchDecrypt() directly
   * instead of looping decryptHydrate() manually.
   */
  async hydrateForFingerprint(
    fingerprint: string,
    key?: MajikKey,
  ): Promise<void> {
    this._cache.clear();
    this._decryptErrors.clear();

    const rows = this._adapter.query
      ? await this._adapter.query({ where: { fingerprint } })
      : (await this._adapter.list()).filter(
          (r) => r.fingerprint === fingerprint,
        );

    const stamps: MajikSignatureStamp[] = [];
    for (const json of rows) {
      try {
        stamps.push(MajikSignatureStamp.fromJSON(json));
      } catch (err) {
        console.warn(
          `hydrateForFingerprint: skipping malformed stamp "${json?.id}":`,
          err,
        );
      }
    }

    if (!key) {
      for (const s of stamps) this._cache.set(s.id, s);
      return;
    }

    const results = await Promise.allSettled(
      stamps.map((stamp) => stamp.toMajikFile().decryptHydrate(key)),
    );

    results.forEach((result, i) => {
      const stamp = stamps[i];
      if (result.status === "fulfilled") {
        this._cache.set(stamp.id, stamp);
      } else {
        this._decryptErrors.set(
          stamp.id,
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

  /** Wipe decrypted plaintext from every currently cached stamp's MajikFile.
   *  MajikFile.batchLock() has no canDecrypt-style gate, safe to use as-is. */
  lockAll(): BatchLockResult {
    const files = this.list().map((s) => s.toMajikFile());
    return MajikFile.batchLock(files);
  }

  // ── Serialization ─────────────────────────────────────────────────────
  async toJSON(): Promise<MajikSignatureStampJSON[]> {
    return this._adapter.list();
  }

  async bulkRestoreFromJSON(data: MajikSignatureStampJSON[]): Promise<void> {
    if (!Array.isArray(data)) {
      throw new MajikSignatureStampManagerError(
        "bulkRestoreFromJSON: expected MajikSignatureStampJSON[]",
      );
    }
    await this._adapter.bulkSave(data);
    await this.hydrate();
  }

  static async fromJSON(
    data: MajikSignatureStampJSON[],
    adapter?: MajikSignatureStampStorageAdapter,
  ): Promise<MajikSignatureStampManager> {
    const manager = new MajikSignatureStampManager(adapter);
    await manager.bulkRestoreFromJSON(data);
    return manager;
  }

  private async _persist(stamp: MajikSignatureStamp): Promise<void> {
    await this._adapter.save(stamp.toJSON());
  }

  // ── Core CRUD ───────────────────────────────────────────────────────────

  async create(options: CreateStampOptions): Promise<MajikSignatureStamp> {
    const stamp = await MajikSignatureStamp.create(options);
    await this._persist(stamp);
    this._cache.set(stamp.id, stamp);
    return stamp;
  }

  async save(stamp: MajikSignatureStamp): Promise<void> {
    await this._persist(stamp);
    this._cache.set(stamp.id, stamp);
  }

  async load(id: string): Promise<MajikSignatureStamp | null> {
    const cached = this._cache.get(id);
    if (cached) return cached;
    const json = await this._adapter.getById(id);
    if (!json) return null;
    const stamp = MajikSignatureStamp.fromJSON(json);
    this._cache.set(stamp.id, stamp);
    return stamp;
  }

  async getStampOrThrow(id: string): Promise<MajikSignatureStamp> {
    const stamp = await this.load(id);
    if (!stamp)
      throw new MajikSignatureStampManagerError(`Stamp not found: ${id}`);
    return stamp;
  }

  async loadAll(): Promise<MajikSignatureStamp[]> {
    const all = await this._adapter.list();
    for (const json of all) {
      if (!this._cache.has(json.id)) {
        try {
          const stamp = MajikSignatureStamp.fromJSON(json);
          this._cache.set(stamp.id, stamp);
        } catch (err) {
          console.warn(
            `MajikSignatureStampManager.loadAll: skipping malformed stamp "${json?.id}":`,
            err,
          );
        }
      }
    }
    return [...this._cache.values()];
  }

  async delete(id: string): Promise<void> {
    await this._adapter.remove(id);
    this._cache.delete(id);
  }

  async has(id: string): Promise<boolean> {
    if (this._cache.has(id)) return true;
    return this._adapter.exists(id);
  }

  get(id: string): MajikSignatureStamp | undefined {
    return this._cache.get(id);
  }

  list(): MajikSignatureStamp[] {
    return [...this._cache.values()];
  }

  listByKind(kind: StampAssetKind): MajikSignatureStamp[] {
    return this.list().filter((s) => s.kind === kind);
  }

  listByFingerprint(fingerprint: string): MajikSignatureStamp[] {
    return this.list().filter((s) => s.fingerprint === fingerprint);
  }

  async query(
    query: StorageQuery<MajikSignatureStampJSON>,
  ): Promise<MajikSignatureStampJSON[]> {
    if (!this._adapter.query) {
      throw new MajikSignatureStampManagerError(
        "query: current adapter does not support query()",
      );
    }
    return this._adapter.query(query);
  }

  // ── Mutations ───────────────────────────────────────────────────────────

  async rename(id: string, newName: string): Promise<MajikSignatureStamp> {
    const stamp = await this.getStampOrThrow(id);
    stamp.rename(newName);
    await this._persist(stamp);
    return stamp;
  }

  /** Write-once at the MajikFile layer — id is preserved explicitly. */
  async replaceContent(
    id: string,
    rawBytes: Uint8Array,
    identity: MajikFileIdentity,
    mimeType?: string,
  ): Promise<MajikSignatureStamp> {
    const existing = await this.getStampOrThrow(id);
    const replacement = await MajikSignatureStamp.create({
      id: existing.id,
      data: rawBytes,
      identity,
      kind: existing.kind,
      name: existing.name,
      mimeType: mimeType ?? existing.mimeType ?? undefined,
    });
    await this._persist(replacement);
    this._cache.set(replacement.id, replacement);
    return replacement;
  }

  async decryptContent(
    id: string,
    identity: Pick<MajikFileIdentity, "fingerprint" | "mlKemSecretKey">,
  ): Promise<Uint8Array> {
    const stamp = await this.getStampOrThrow(id);
    return stamp.decryptContent(identity);
  }

  async bulkRemove(ids: string[]): Promise<void> {
    if (ids.length === 0) return;
    await this._adapter.bulkRemove(ids);
    for (const id of ids) this._cache.delete(id);
  }
}
