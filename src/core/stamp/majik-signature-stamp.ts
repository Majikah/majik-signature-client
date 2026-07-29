// majik-signature-stamp.ts
import { MajikFile } from "@majikah/majik-file";
import type {
  MajikFileDecryptIdentity,
  MajikFileIdentity,
  MajikFileJSON,
} from "@majikah/majik-file";
import { arrayToBase64, base64ToUint8Array } from "../utils/utilities";

export type StampAssetKind = "image" | "audio" | "video" | "text";

export interface MajikSignatureStampJSON {
  id: string; // == the underlying MajikFile's json.id, never regenerated separately
  kind: StampAssetKind;
  name: string;
  mimeType: string | null;
  sizeBytes: number; // plaintext size, pre-encryption
  fingerprint: string; // identity.fingerprint used to encrypt — tells you which key can decrypt this row
  data: string; // base64-encoded encrypted .mjkb binary
  timestamp: string;
  lastUpdate: string;
  /** Full MajikFile metadata — required to reconstruct a working MajikFile
   *  instance via MajikFile.fromJSON() for decryptHydrate()/secureLock(). */
  fileJson: MajikFileJSON;
}

export interface CreateStampOptions {
  data: Uint8Array | ArrayBuffer;
  identity: MajikFileIdentity;
  kind: StampAssetKind;
  name: string;
  mimeType?: string;
  /** Pass the existing id back in when replacing content on a stamp that
   *  already exists — MajikFile is write-once, so this is a *new* encrypted
   *  artifact under the hood, but the id stays stable for the caller. */
  id?: string;
}

export class MajikSignatureStamp {
  private readonly _id: string;
  private readonly _kind: StampAssetKind;
  private _name: string;
  private readonly _mimeType: string | null;
  private readonly _sizeBytes: number;
  private readonly _fingerprint: string;
  private readonly _timestamp: string;

  private readonly _fileJson: MajikFileJSON;
  private _file: MajikFile | null = null; // reconstructed lazily, cached per instance

  private _lastUpdate: string;
  private _encryptedBinary: Uint8Array; // the .mjkb bytes — never the plaintext

  private constructor(json: MajikSignatureStampJSON, binary: Uint8Array) {
    this._id = json.id;
    this._kind = json.kind;
    this._name = json.name;
    this._mimeType = json.mimeType;
    this._sizeBytes = json.sizeBytes;
    this._fingerprint = json.fingerprint;
    this._timestamp = json.timestamp;
    this._lastUpdate = json.lastUpdate;
    this._encryptedBinary = binary;
    this._fileJson = json.fileJson;
  }

  get id(): string {
    return this._id;
  }
  get kind(): StampAssetKind {
    return this._kind;
  }
  get name(): string {
    return this._name;
  }
  get mimeType(): string | null {
    return this._mimeType;
  }
  get sizeBytes(): number {
    return this._sizeBytes;
  }
  get fingerprint(): string {
    return this._fingerprint;
  }
  get timestamp(): string {
    return this._timestamp;
  }
  get lastUpdate(): string {
    return this._lastUpdate;
  }

  // ── CREATE ──────────────────────────────────────────────────────────────

  static async create(
    options: CreateStampOptions,
  ): Promise<MajikSignatureStamp> {
    const { data, identity, kind, name, mimeType, id } = options;
    if (!data) throw new Error("MajikSignatureStamp.create: data is required");
    if (!identity)
      throw new Error("MajikSignatureStamp.create: identity is required");
    if (!name?.trim())
      throw new Error("MajikSignatureStamp.create: name is required");

    const file = await MajikFile.create({
      id,
      data,
      identity,
      originalName: name,
      mimeType,
      userId: identity.fingerprint,
    });

    const fileJson = file.toJSON();
    const now = new Date().toISOString();
    const binary = file.toBinaryBytes();

    const json: MajikSignatureStampJSON = {
      id: fileJson.id,
      kind,
      name,
      mimeType: fileJson.mime_type,
      sizeBytes: fileJson.size_original,
      fingerprint: identity.fingerprint,
      data: arrayToBase64(binary),
      timestamp: fileJson.timestamp ?? now,
      lastUpdate: fileJson.last_update ?? now,
      fileJson,
    };

    const instance = new MajikSignatureStamp(json, binary);
    instance._file = file; // reuse — already fully constructed, no need to refetch
    return instance;
  }

  /** Plaintext-only rename — no re-encryption, no MajikFile involvement. */
  rename(newName: string): void {
    if (!newName?.trim()) throw new Error("rename: name must be non-empty");
    this._name = newName.trim();
    this._lastUpdate = new Date().toISOString();
  }

  toJSON(): MajikSignatureStampJSON {
    return {
      id: this._id,
      kind: this._kind,
      name: this._name,
      mimeType: this._mimeType,
      sizeBytes: this._sizeBytes,
      fingerprint: this._fingerprint,
      data: arrayToBase64(this._encryptedBinary),
      timestamp: this._timestamp,
      lastUpdate: this._lastUpdate,
      fileJson: this._fileJson,
    };
  }

  static fromJSON(json: MajikSignatureStampJSON): MajikSignatureStamp {
    return new MajikSignatureStamp(json, base64ToUint8Array(json.data));
  }

  /** Reconstruct (or return the cached) MajikFile backing this stamp. */
  toMajikFile(): MajikFile {
    if (!this._file) {
      this._file = MajikFile.fromJSON(this._fileJson, this._encryptedBinary);
    }
    return this._file;
  }

  /** Cached decrypted bytes, if hydrateForFingerprint()/decryptHydrate() has
   *  already run for this stamp this session. Undefined otherwise, or after
   *  a lock. */
  get decryptedBytes(): Uint8Array | undefined {
    return this._file?.hasDecryptedFile ? this._file.decryptedFile : undefined;
  }

  /** Accepts a full MajikKey OR a bare {fingerprint, mlKemSecretKey} —
   *  matches MajikFile's own MajikFileDecryptIdentity shape. */
  async decryptContent(
    identity: MajikFileDecryptIdentity,
  ): Promise<Uint8Array> {
    return MajikFile.decrypt(this._encryptedBinary, identity);
  }
}
