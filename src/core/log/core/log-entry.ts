import { MajikFile } from "@majikah/majik-file";
import type {
  MajikFileDecryptIdentity,
  MajikFileIdentity,
  MajikFileJSON,
} from "@majikah/majik-file";
import { arrayToBase64, base64ToUint8Array } from "../../utils/utilities";
import { LogType } from "./enums";
import { LogError } from "./error";
import { BaseLogJSON } from "./types";

export interface MajikEnvelopeResult {
  binary?: Uint8Array;
  fileJson?: MajikFileJSON;
  fingerprint?: string;
}

/**
 * Abstract Base Log Model
 * Cannot be instantiated directly. Must be extended by HistoryLog or UserActivityLog.
 * Implements the MajikFile encrypted envelope mechanism shared by both log types.
 *
 * IMPORTANT: subclasses are responsible for calling `this.validate()` themselves,
 * once *all* of their own fields have been assigned (i.e. at the end of their own
 * constructor, after `super(...)` returns). This base constructor deliberately does
 * NOT call `this.validate()` — doing so would invoke the *overridden* subclass
 * `validate()` before the subclass's own fields exist yet (a classic "virtual call
 * in a constructor" bug), causing every subclass instantiation to throw on fields
 * that are simply not assigned yet.
 */
export abstract class BaseLog<T extends LogType> {
  protected readonly _id: string;
  protected readonly _reference_id: string;
  protected readonly _type: T;
  protected readonly _timestamp: string;
  protected readonly _version: number;

  protected readonly _fingerprint?: string;
  protected readonly _fileJson?: MajikFileJSON;
  protected _file: MajikFile | null = null; // Reconstructed lazily and cached per instance
  protected readonly _encryptedBinary?: Uint8Array; // Raw .mjkb bytes — never plaintext
  protected _decryptedBytes?: Uint8Array; // Cached plaintext once decryptContent() has resolved

  protected constructor(json: BaseLogJSON<T>, binary?: Uint8Array) {
    this._id = json.id;
    this._reference_id = json.reference_id;
    this._type = json.type;
    this._timestamp = json.timestamp;
    this._version = json.version;
    this._fingerprint = json.fingerprint;
    this._fileJson = json.fileJson;

    // Resolve binary: prioritize passed binary argument, fallback to decoding base64 from JSON if present
    this._encryptedBinary =
      binary ?? (json.data ? base64ToUint8Array(json.data) : undefined);

    // Deliberately no this.validate() call here — see class docblock above.
  }

  // ==========================================
  // GETTERS
  // ==========================================

  get id(): string {
    return this._id;
  }

  get reference_id(): string {
    return this._reference_id;
  }

  get type(): T {
    return this._type;
  }

  get timestamp(): string {
    return this._timestamp;
  }

  get version(): number {
    return this._version;
  }

  get fingerprint(): string | undefined {
    return this._fingerprint;
  }

  get fileJson(): MajikFileJSON | undefined {
    return this._fileJson;
  }

  get encryptedBinary(): Uint8Array | undefined {
    return this._encryptedBinary;
  }

  /**
   * Cached decrypted bytes, populated once `decryptContent()` has resolved.
   * Undefined until then — this is a plain in-memory cache, not a signal that
   * decryption is unnecessary.
   */
  get decryptedBytes(): Uint8Array | undefined {
    return this._decryptedBytes;
  }

  // ==========================================
  // MAJIK FILE ENVELOPE HELPERS
  // ==========================================

  /**
   * Reconstructs or returns the cached MajikFile backing this log entry.
   */
  public toMajikFile(): MajikFile {
    if (!this._file) {
      if (!this._fileJson || !this._encryptedBinary) {
        throw new LogError(
          "Missing fileJson or encrypted binary to build MajikFile",
          "MISSING_MAJIK_FILE_DATA",
        );
      }
      this._file = MajikFile.fromJSON(this._fileJson, this._encryptedBinary);
    }
    return this._file;
  }

  /**
   * Decrypts the log payload using a given identity and caches the result
   * on this instance, so `decryptedBytes` reflects it immediately afterwards.
   */
  async decryptContent(
    identity: MajikFileDecryptIdentity,
  ): Promise<Uint8Array> {
    if (!this._encryptedBinary) {
      throw new LogError(
        "No encrypted binary present to decrypt",
        "DECRYPTION_FAILED",
      );
    }
    const bytes = await MajikFile.decrypt(this._encryptedBinary, identity);
    this._decryptedBytes = bytes;
    return bytes;
  }

  // ==========================================
  // SHARED CREATE()/DESERIALIZE HELPERS
  // ==========================================

  /**
   * Shared id generator used by every subclass's create() factory.
   * Falls back to a non-cryptographic id only when crypto.randomUUID isn't
   * available (e.g. non-secure contexts) — kept as one implementation so
   * both log types stay in sync if this ever needs to change.
   */
  protected static generateId(): string {
    return (
      crypto.randomUUID?.() ??
      `log_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`
    );
  }

  /**
   * Wraps payload bytes into a MajikFile encrypted envelope, if both `data`
   * and `identity` were supplied. Centralizes the envelope-creation
   * boilerplate that HistoryLog.create() and UserActivityLog.create()
   * previously duplicated.
   */
  protected static async prepareEnvelope(
    data: Uint8Array | ArrayBuffer | undefined,
    identity: MajikFileIdentity | undefined,
    id: string | undefined,
    originalName: string,
  ): Promise<MajikEnvelopeResult> {
    if (!data || !identity) return {};

    const file = await MajikFile.create({
      id,
      data,
      identity,
      originalName,
      userId: identity.fingerprint,
    });

    return {
      binary: file.toBinaryBytes(),
      fileJson: file.toJSON(),
      fingerprint: identity.fingerprint,
    };
  }

  // ==========================================
  // VALIDATOR
  // ==========================================

  /**
   * Validates the fields owned by BaseLog. Subclasses MUST call
   * `super.validate()` at the top of their own override.
   */
  public validate(): void {
    if (!this._id) throw new LogError("Missing ID", "VALIDATION_FAILED");
    if (!this._reference_id)
      throw new LogError("Missing Reference ID", "VALIDATION_FAILED");
    if (!this._type)
      throw new LogError("Missing Log Type", "VALIDATION_FAILED");
    if (!this._timestamp)
      throw new LogError("Missing Timestamp", "VALIDATION_FAILED");
    if (isNaN(Date.parse(this._timestamp)))
      throw new LogError("Invalid Timestamp", "VALIDATION_FAILED");
    if (typeof this._version !== "number" || this._version < 1) {
      throw new LogError("Invalid Version", "VALIDATION_FAILED");
    }
  }

  // ==========================================
  // SERIALIZATION (JSON)
  // ==========================================

  /**
   * Serializes the model into a JSON-safe format (converts binary Uint8Array to base64 string).
   * Subclasses override this and spread `...super.toJSON()`.
   */
  public toJSON(): BaseLogJSON<T> {
    return {
      id: this._id,
      reference_id: this._reference_id,
      type: this._type,
      timestamp: this._timestamp,
      version: this._version,
      fingerprint: this._fingerprint,
      data: this._encryptedBinary
        ? arrayToBase64(this._encryptedBinary)
        : undefined,
      fileJson: this._fileJson,
    };
  }

  // Deserialization is intentionally handled by each subclass's own static
  // fromJSON(), since BaseLogJSON alone isn't a constructible variant (T is
  // generic here) — see HistoryLog.fromJSON / UserActivityLog.fromJSON.
}
