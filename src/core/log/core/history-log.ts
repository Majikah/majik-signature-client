import { arrayToBase64 } from "../../utils/utilities";
import {
  LogTypes,
  HistoryTypes,
  HistoryStatuses,
  HistorySources,
  NotaryNetworks,
  HistoryType,
  HistoryStatus,
  HistorySource,
  NotaryNetwork,
} from "./enums";
import { LogError } from "./error";
import { BaseLog } from "./log-entry";
import { HistoryLogJSON, SignatureOperation } from "./types";
import { MajikFileIdentity } from "@majikah/majik-file";

// core/log/core/history-log.ts
export interface CreateHistoryLogOptions {
  id?: string;
  reference_id: string;
  fingerprint?: string;
  historyType: HistoryType;
  status: HistoryStatus;
  source: HistorySource;
  operation: SignatureOperation;
  signerCount?: number;
  valid?: boolean;
  network?: NotaryNetwork;
  transactionId?: string;
  version?: number;
  timestamp?: string;
  data?: Uint8Array | ArrayBuffer;
  identity?: MajikFileIdentity;
}

/**
 * History Log Model
 * Extends the abstract BaseLog class to handle document lifecycle events
 * (signing, verifying, sealing, and notarizing) following the Majik envelope pattern.
 */
export class HistoryLog extends BaseLog<"history"> {
  protected _historyType: HistoryType;
  protected _status: HistoryStatus;
  protected _source: HistorySource;
  protected _operation: SignatureOperation;

  // Conditional fields based on historyType
  protected _signerCount?: number;
  protected _valid?: boolean;
  protected _network?: NotaryNetwork;
  protected _transactionId?: string;

  constructor(json: HistoryLogJSON, binary?: Uint8Array) {
    super(json, binary);

    this._historyType = json.historyType;
    this._status = json.status;
    this._source = json.source;
    this._operation = json.operation;
    this._signerCount = json.signerCount;
    this._valid = json.valid;
    this._network = json.network;
    this._transactionId = json.transactionId;

    // Safe here: every HistoryLog-owned field has been assigned above.
    this.validate();
  }

  // ==========================================
  // FACTORY METHODS (CREATE / DESERIALIZE)
  // ==========================================

  public static async create(
    options: CreateHistoryLogOptions,
  ): Promise<HistoryLog> {
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
      `history-${options.historyType}.bin`,
    );

    const json: HistoryLogJSON = {
      id,
      reference_id: options.reference_id,
      type: LogTypes.HISTORY,
      timestamp,
      version: options.version ?? 1,
      historyType: options.historyType,
      status: options.status,
      source: options.source,
      operation: options.operation,
      signerCount: options.signerCount,
      valid: options.valid,
      network: options.network,
      transactionId: options.transactionId,
      fingerprint: options.fingerprint ?? envelopeFingerprint, // explicit wins
      fileJson,
      data: binary ? arrayToBase64(binary) : undefined,
    };

    return new HistoryLog(json, binary);
  }

  /** Rehydrates a HistoryLog from its serialized JSON form (symmetrical with toJSON()). */
  public static fromJSON(
    json: HistoryLogJSON,
    binary?: Uint8Array,
  ): HistoryLog {
    return new HistoryLog(json, binary);
  }

  // ==========================================
  // GETTERS & SETTERS
  // ==========================================

  get historyType(): HistoryType {
    return this._historyType;
  }

  set historyType(value: HistoryType) {
    this.validateHistoryType(value);
    this._historyType = value;
  }

  get status(): HistoryStatus {
    return this._status;
  }

  set status(value: HistoryStatus) {
    this.validateStatus(value);
    this._status = value;
  }

  get source(): HistorySource {
    return this._source;
  }

  set source(value: HistorySource) {
    this.validateSource(value);
    this._source = value;
  }

  get operation(): SignatureOperation {
    return this._operation;
  }

  set operation(value: SignatureOperation) {
    this.validateOperation(value);
    this._operation = value;
  }

  get signerCount(): number | undefined {
    return this._signerCount;
  }
  get valid(): boolean | undefined {
    return this._valid;
  }
  get network(): NotaryNetwork | undefined {
    return this._network;
  }
  get transactionId(): string | undefined {
    return this._transactionId;
  }

  // ==========================================
  // VALIDATOR
  // ==========================================

  public override validate(): void {
    super.validate();

    if (this._type !== LogTypes.HISTORY) {
      throw new LogError(
        "Invalid root type for HistoryLog",
        "INVALID_LOG_TYPE",
      );
    }

    this.validateHistoryType(this._historyType);
    this.validateStatus(this._status);
    this.validateSource(this._source);
    this.validateOperation(this._operation);
  }

  // Individual field validators — each is called both from validate() and
  // from its matching setter, so there is exactly one implementation of
  // each rule (no re-running validate() wholesale from a single-field setter).

  private validateStatus(value: HistoryStatus): void {
    const validStatuses = Object.values(HistoryStatuses) as string[];
    if (!validStatuses.includes(value)) {
      throw new LogError(`Invalid status: '${value}'`, "INVALID_STATUS");
    }
  }

  private validateSource(value: HistorySource): void {
    const validSources = Object.values(HistorySources) as string[];
    if (!validSources.includes(value)) {
      throw new LogError(`Invalid source: '${value}'`, "INVALID_SOURCE");
    }
  }

  private validateOperation(value: SignatureOperation): void {
    if (!value || !value.digest) {
      throw new LogError(
        "Operation must include a digest",
        "INVALID_OPERATION",
      );
    }
  }

  private validateHistoryType(value: HistoryType): void {
    const validHistoryTypes = Object.values(HistoryTypes) as string[];
    if (!validHistoryTypes.includes(value)) {
      throw new LogError(
        `Invalid history type: '${value}'`,
        "INVALID_HISTORY_TYPE",
      );
    }

    // Conditional-field rules read the *current* instance state for the
    // fields not being changed by this particular setter call.
    switch (value) {
      case HistoryTypes.SIGN:
        if (typeof this._signerCount !== "number" || this._signerCount < 1) {
          throw new LogError(
            "Sign operations must include a signerCount >= 1",
            "MISSING_SIGNER_COUNT",
          );
        }
        break;
      case HistoryTypes.VERIFY:
        if (typeof this._valid !== "boolean") {
          throw new LogError(
            "Verify operations must explicitly state if they are valid",
            "MISSING_VALID_FLAG",
          );
        }
        break;
      case HistoryTypes.NOTARIZE: {
        const validNetworks = Object.values(NotaryNetworks) as string[];
        if (!this._network || !validNetworks.includes(this._network)) {
          throw new LogError(
            "Notarize operations require a valid NotaryNetwork",
            "MISSING_NETWORK",
          );
        }
        break;
      }
      case HistoryTypes.SEAL:
        break;
    }
  }

  // ==========================================
  // SERIALIZATION & DESERIALIZATION
  // ==========================================

  public override toJSON(): HistoryLogJSON {
    return {
      ...super.toJSON(),
      historyType: this._historyType,
      status: this._status,
      source: this._source,
      operation: this._operation,
      signerCount: this._signerCount,
      valid: this._valid,
      network: this._network,
      transactionId: this._transactionId,
    };
  }
}
