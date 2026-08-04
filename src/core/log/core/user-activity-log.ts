import { AuditAction, AuditActions, LogTypes } from "./enums";
import { LogError } from "./error";
import { BaseLog } from "./log-entry";
import { UserActivityLogJSON } from "./types";
import { MajikFileIdentity } from "@majikah/majik-file";
import { arrayToBase64 } from "../../utils/utilities";

export interface CreateUserActivityLogOptions {
  id?: string;
  reference_id: string;
  fingerprint?: string;
  action: AuditAction;
  metadata?: Record<string, unknown>;
  version?: number;
  timestamp?: string;
  data?: Uint8Array | ArrayBuffer;
  identity?: MajikFileIdentity; // Optional: used to encrypt audit payload details via Majik envelope
}

/**
 * User Activity / Audit Log Model
 * Extends the abstract BaseLog class specifically for user activity logs.
 */
export class UserActivityLog extends BaseLog<"audit"> {
  protected _action: AuditAction;
  protected _metadata?: Record<string, unknown>;

  constructor(json: UserActivityLogJSON, binary?: Uint8Array) {
    super(json, binary);

    this._action = json.action;
    this._metadata = json.metadata;

    // Safe here: every UserActivityLog-owned field has been assigned above.
    this.validate();
  }

  // ==========================================
  // FACTORY METHODS (CREATE / DESERIALIZE)
  // ==========================================

  public static async create(
    options: CreateUserActivityLogOptions,
  ): Promise<UserActivityLog> {
    const id = options.id ?? BaseLog.generateId();
    const timestamp = options.timestamp ?? new Date().toISOString();

    const {
      binary,
      fileJson,
      fingerprint: envelopeFingerprint,
    } = await BaseLog.prepareEnvelope(
      options.data,
      options.identity,
      id,
      `audit-${options.action}.bin`,
    );

    const json: UserActivityLogJSON = {
      id,
      reference_id: options.reference_id,
      type: LogTypes.AUDIT,
      timestamp,
      version: options.version ?? 1,
      action: options.action,
      metadata: options.metadata,
      fingerprint: options.fingerprint ?? envelopeFingerprint, // explicit wins
      fileJson,
      data: binary ? arrayToBase64(binary) : undefined,
    };

    return new UserActivityLog(json, binary);
  }

  /** Rehydrates a UserActivityLog from its serialized JSON form (symmetrical with toJSON()). */
  public static fromJSON(
    json: UserActivityLogJSON,
    binary?: Uint8Array,
  ): UserActivityLog {
    return new UserActivityLog(json, binary);
  }

  // ==========================================
  // GETTERS & SETTERS
  // ==========================================

  get action(): AuditAction {
    return this._action;
  }

  set action(value: AuditAction) {
    this.validateAction(value);
    this._action = value;
  }

  get metadata(): Record<string, unknown> | undefined {
    return this._metadata;
  }

  set metadata(value: Record<string, unknown> | undefined) {
    this._metadata = value;
  }

  // ==========================================
  // VALIDATOR
  // ==========================================

  public override validate(): void {
    super.validate();

    if (this._type !== LogTypes.AUDIT) {
      throw new LogError(
        "Invalid type for UserActivityLog",
        "INVALID_LOG_TYPE",
      );
    }

    this.validateAction(this._action);
  }

  private validateAction(action: AuditAction): void {
    const validActions = Object.values(AuditActions) as string[];
    if (!action || !validActions.includes(action)) {
      throw new LogError(
        `Invalid audit action: '${action}'`,
        "INVALID_AUDIT_ACTION",
      );
    }
  }

  // ==========================================
  // SERIALIZATION & DESERIALIZATION
  // ==========================================

  public override toJSON(): UserActivityLogJSON {
    return {
      ...super.toJSON(),
      action: this._action,
      metadata: this._metadata,
    };
  }
}
