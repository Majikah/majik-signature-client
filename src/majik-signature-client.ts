/**
 * MajikSignatureClient.ts
 *
 * High-level wrapper client for MajikSignature.
 *
 * Extends MajikKeyClient, which owns all MajikKey account management
 * (create/import/replace, lock/unlock, passphrase, active-account tracking,
 * account ordering, and base events). This class adds everything specific
 * to Majik Signature: the contact directory, stamps, signing, verification,
 * seal/multi-sig, and backup/restore.
 *
 * Designed to be used alongside MajikSignature in the same webapp.
 * Accounts are automatically shared via the base class's keyManager.
 * Contacts are shared by passing the same MajikContactManager instance
 * to both MajikSignature and MajikSignatureClient at construction time.
 */

import { MajikKey, MajikKeyAddress } from "@majikah/majik-key";

import {
  BatchFileInput,
  BatchSignOptions,
  BatchVerifyInput,
  MajikSignature,
  MajikSignatureEnvelope,
} from "@majikah/majik-signature";
import { normalizeToBytes } from "@majikah/majik-signature/dist/core/embed/utils";
import {
  BatchVerifyOptions,
  EnvelopeInfo,
  EnvelopeInput,
  ExpectedSigner,
  FileLike,
  FileVerifyResult,
  MajikSignatureJSON,
  MajikSignatureMap,
  MajikSignerPublicKeys,
  MajikTimestamp,
  MjksMapResolveStatus,
  SealInfo,
  SealVerificationResult,
  SignatoriesFilter,
  SignatoriesResult,
  SignatoryInfo,
  SignOptions,
  VerificationResult,
} from "@majikah/majik-signature";
import { base64ToUint8Array } from "./core/utils/utilities";

import { AppBackUpData, MAJIK_API_RESPONSE } from "./core/types";
import {
  ImageSignatureStub,
  ImageSignOptions,
  ImageVerificationResult,
} from "@majikah/majik-signature/dist/core/stamp";
import {
  MajikContactManager,
  MajikContactManagerAdapters,
} from "./core/contacts/majik-contact-manager";
import { MajikContactManagerJSON } from "./core/contacts/types";
import {
  MajikContact,
  MajikContactGroup,
  MajikContactGroupMeta,
  MajikContactMeta,
  SerializedMajikContact,
} from "@majikah/majik-contact";
import { ClientStateManager } from "./core/client-state-manager";
import {
  ClientStateStorageAdapter,
  InMemoryClientStateAdapter,
  InMemoryStampstoreAdapter,
  MajikSignatureStampStorageAdapter,
  UserAppPreferences,
} from "./core/storage";
import { MajikCompressedJSON } from "@majikah/majik-cjson";
import { prependMagic, readBackupBlob } from "./core/backup/utils";
import {
  MAJIK_SIGNATURE_BACKUP_MAGIC,
  MAJIK_SIGNATURE_BACKUP_MAGIC_SIZE,
} from "./core/backup/constants";
import { AppDataSnapshot, ContactManagerSnapshot } from "./core/backup/types";
import { MajikSignatureStampManager } from "./core/stamp/majik-signature-stamp-manager";
import { MajikFileIdentity } from "@majikah/majik-file";
import {
  MajikSignatureStamp,
  MajikSignatureStampJSON,
  StampAssetKind,
} from "./core/stamp/majik-signature-stamp";
import {
  MajikKeyClient,
  MajikKeyClientBaseEvents,
  MajikKeyClientConfig,
} from "@majikah/majik-key-client";
import { HistoryLogManager } from "./core/log/history-log-manager";
import { UserActivityLogManager } from "./core/log/user-activity-log-manager";
import { HistoryLogStorageAdapter } from "./core/storage/logs/history/_types";
import { UserActivityLogStorageAdapter } from "./core/storage/logs/user-activity/_types";
import {
  CreateHistoryLogOptions,
  HistoryLog,
} from "./core/log/core/history-log";
import {
  CreateUserActivityLogOptions,
  UserActivityLog,
} from "./core/log/core/user-activity-log";
import {
  AuditActions,
  HistorySource,
  HistorySources,
  HistoryStatuses,
  HistoryTypes,
} from "./core/log/core/enums";
import { SignatureOrderResult } from "@majikah/majik-signature/dist/core/order";

// ─── Types ────────────────────────────────────────────────────────────────────

/**
 * Event names emitted by `MajikSignatureClient`.
 *
 * Includes all base `MajikKeyClient` lifecycle events plus Signature-specific events:
 *
 * - `sign` — emitted with a `SignResult`.
 * - `verify` — emitted with a `VerifyResult`.
 * - `new-stamp` / `removed-stamp` — emitted when a stored stamp is added or removed.
 * - `new-contact` / `removed-contact` — emitted when contacts are added or removed.
 * - `new-contact-group` / `removed-contact-group` / `contact-group-change` — emitted for group mutations.
 * - `history-log` — emitted with a newly recorded `HistoryLog`.
 * - `activity-log` — emitted with a newly recorded `UserActivityLog`.
 */
type MajikSignatureClientEvents =
  | MajikKeyClientBaseEvents
  | "sign"
  | "verify"
  | "new-stamp"
  | "removed-stamp"
  | "new-contact"
  | "new-contact-group"
  | "removed-contact"
  | "removed-contact-group"
  | "contact-group-change"
  | "history-log"
  | "activity-log";

/**
 * Configuration used to initialize `MajikSignatureClient`, including optional
 * manager instances and persistent storage adapters.
 *
 * @remarks
 * When both an explicit manager and its corresponding adapter are supplied,
 * the manager instance takes precedence for that domain.
 */
export interface MajikSignatureClientConfig extends MajikKeyClientConfig {
  /** Signature-specific client state manager. */
  clientStateManager?: ClientStateManager;
  /** Shared contact directory manager. */
  contactManager?: MajikContactManager;
  /** Encrypted signature stamp manager. */
  stampsManager?: MajikSignatureStampManager;
  /** History log manager used for persisted audit/history records. */
  historyManager?: HistoryLogManager;
  /** User activity log manager used for persisted activity records. */
  activityManager?: UserActivityLogManager;
  /** Storage adapters used when the corresponding manager is not injected. */
  adapters?: MajikKeyClientConfig["adapters"] & {
    /** Contact directory storage adapters. */
    contacts?: MajikContactManagerAdapters;
    /** Encrypted stamp storage adapter. */
    stamps?: MajikSignatureStampStorageAdapter;
    /** History log storage adapter. */
    historyLogs?: HistoryLogStorageAdapter;
    /** User activity log storage adapter. */
    userActivityLogs?: UserActivityLogStorageAdapter;
  };
}

/**
 * Result returned by a successful signing operation.
 */
export interface SignResult {
  /** Signature produced by the signing operation. */
  signature: MajikSignature;
  /** Identifier of the signer associated with the signature. */
  signerId: string;
  /** Stable content digest protected by the signature. */
  contentHash: string;
  /** Timestamp associated with the signature. */
  timestamp: string;
  /** Optional content type associated with the signed payload. */
  contentType?: string;
}

/**
 * Verification result enriched with a human-readable signer label when the
 * signer can be resolved from the local contact directory.
 */
export interface VerifyResult extends VerificationResult {
  /** Optional human-readable signer label resolved from the contact directory. */
  signerLabel?: string;
}

/**
 * Serializable Signature client state containing contacts and optional owned-account ordering.
 */
export interface MajikSignatureClientJSON {
  /** Client/application identifier represented by this serialized state. */
  id: string;
  /** Serialized contact-directory state. */
  contacts: MajikContactManagerJSON;
  /** Optional serialized own-account cache and ordering. */
  ownAccounts?: {
    /** Serialized owned-account contact records. */
    accounts: SerializedMajikContact[];
    /** Account identifiers in active-account priority order. */
    order: string[];
  };
}

/**
 * Anything the UI can hand to the client to identify a signer.
 * A reference may be an owned `MajikKey`, an `ExpectedSigner`, or a contact
 * identifier resolved through the local directory.
 */
export type SignerRef = MajikKey | ExpectedSigner | { contactId: string };

/**
 *  Accepted input forms for MJKS map operations.
 */
export type MjksMapInput = MajikSignatureMap | Blob | Uint8Array;

/**
 *  Verification options for MJKS maps, including trusted contact, address, or key resolution.
 */
export interface MjksMapVerifyOptions extends BatchVerifyOptions {
  /** Trusted contact identifier used to resolve signer public keys. */
  contactId?: string;
  /** Trusted Majik public-key address used to resolve a signer. */
  address?: MajikKeyAddress;
  /** Trusted MajikKey used for verification. */
  key?: MajikKey;
}

/**
 *  Structured result returned from MJKS map verification.
 */
export interface MjksMapVerifyResult {
  /** Per-file verification results. */
  results: FileVerifyResult[];
  /** Aggregate summary of the verification results. */
  summary: ReturnType<typeof MajikSignature.summarizeBatchVerification>;
  /** Map entries with no supplied file and no relocation entry accounting for them. */
  missingFromBatch: string[];
  /** Whether verification used trusted supplied/resolved keys rather than only envelope self-reported keys. */
  trustedKeys: boolean;
}

/**
 *  Per-file result returned by MJKS map signature-order verification.
 */
export interface MjksMapOrderFileResult {
  /** Normalized MJKS map path for the file. */
  path: string;
  /** Status describing how the expected signing order was resolved. */
  resolveStatus: MjksMapResolveStatus;
  /** Resolved signature order when available. */
  order?: SignatureOrderResult;
  /** Optional reason explaining a failed or unresolved order check. */
  reason?: string;
}

// ─── MajikSignatureClient ─────────────────────────────────────────────────────

/**
 * High-level Majik Signature application client built on top of `MajikKeyClient`.
 *
 * `MajikSignatureClient` composes inherited Majik Key account management with
 * Signature-specific domains: contact and group management, post-quantum signing
 * and verification, embedded and detached file signatures, multi-signature workflows,
 * envelope sealing, encrypted reusable stamps, MJKS map operations, and portable
 * application backups.
 *
 * @remarks
 * Managers and storage adapters can be injected through `MajikSignatureClientConfig`.
 * This allows applications to share existing manager instances or replace the default
 * in-memory adapters with persistent storage. The static `create()` helper constructs
 * and hydrates the client before returning it.
 *
 * @example
 * ```ts
 * const client = await MajikSignatureClient.create({
 *   adapters: {
 *     contacts: contactsAdapter,
 *     stamps: stampsAdapter,
 *   },
 * });
 *
 * const result = await client.signFile(file, {
 *   contentType: "application/pdf",
 * });
 * ```
 *
 * @see MajikKeyClient
 */
export class MajikSignatureClient extends MajikKeyClient<
  MajikContact,
  MajikContactMeta,
  MajikSignatureClientEvents,
  ClientStateManager
> {
  /** Shared contact directory manager used for signer resolution and contact/group persistence. */
  private _contacts: MajikContactManager;
  /** Encrypted signature stamp manager used for stamp persistence and key-bound content protection. */
  private _stamps: MajikSignatureStampManager;
  /** History log manager used for non-blocking audit/history records. */
  private _history: HistoryLogManager;
  /** User activity log manager used for non-blocking activity records. */
  private _activity: UserActivityLogManager;

  /**
   * Creates a Majik Signature client with the supplied managers and storage adapters.
   *
   * Use `create()` when the client should be hydrated before first use.
   *
   * @param config - Client configuration, including optional managers and storage adapters.
   */
  constructor(config: MajikSignatureClientConfig) {
    super(config);

    this._contacts =
      config.contactManager ??
      new MajikContactManager(undefined, undefined, config.adapters?.contacts);

    this._stamps =
      config.stampsManager ??
      new MajikSignatureStampManager(
        config.adapters?.stamps ?? new InMemoryStampstoreAdapter(),
      );

    this._history =
      config.historyManager ??
      new HistoryLogManager(config.adapters?.historyLogs);

    this._activity =
      config.activityManager ??
      new UserActivityLogManager(config.adapters?.userActivityLogs);

    this._registerEventNames([
      "sign",
      "verify",
      "new-stamp",
      "removed-stamp",
      "new-contact",
      "new-contact-group",
      "removed-contact",
      "removed-contact-group",
      "contact-group-change",
      "history-log",
      "activity-log",
    ]);
  }

  /**
   * Override — without this, MajikKeyClient's constructor falls back to
   * building a plain MajikKeyClientStateManager (ACCOUNT_ORDER only),
   * and every call to getUserAppPreferences() etc. throws at runtime.
   * @param adapter - Optional storage adapter used for persisted client state.
   * @returns The result of the create default state manager operation (`ClientStateManager`).
   */
  protected _createDefaultStateManager(
    adapter?: ClientStateStorageAdapter,
  ): ClientStateManager {
    return new ClientStateManager(adapter ?? new InMemoryClientStateAdapter());
  }

  /**
   * Returns the encrypted signature stamp manager used by this client.
   * @returns The configured `MajikSignatureStampManager` instance.
   */
  get stampManager(): MajikSignatureStampManager {
    return this._stamps;
  }

  /**
   * Returns the history log manager used by this client.
   * @returns The configured `HistoryLogManager` instance.
   */
  get historyManager(): HistoryLogManager {
    return this._history;
  }

  /**
   * Returns the user activity log manager used by this client.
   * @returns The configured `UserActivityLogManager` instance.
   */
  get activityManager(): UserActivityLogManager {
    return this._activity;
  }

  // ==========================================================================
  // ── MajikKeyClient HOOKS ──────────────────────────────────────────────────
  // ==========================================================================

  /**
   * Converts a MajikKey into the MajikContact representation used by this client.
   * @param key - MajikKey used as the cryptographic identity for the operation.
   * @param meta - Optional metadata associated with the contact, account, or group.
   * @returns The result of the build own account contact operation (`MajikContact`).
   */
  protected _buildOwnAccountContact(
    key: MajikKey,
    meta?: Partial<MajikContactMeta>,
  ): MajikContact {
    return key.toContact(meta);
  }

  /**
   * Synchronizes a newly registered own account into the shared contact directory.
   * @param contact - Majik contact record to add, export, or otherwise operate on.
   * @returns Completes when the operation has finished.
   */
  protected async _onAccountRegistered(contact: MajikContact): Promise<void> {
    if (!this._contacts.hasContact(contact.id)) {
      await this._contacts.addContact(contact);
    }
  }

  /**
   * Removes an own account from the shared contact directory.
   * @param id - Unique identifier of the target entity.
   * @returns Completes when the operation has finished.
   */
  protected async _onAccountRemoved(id: string): Promise<void> {
    await this._contacts.removeContact(id);
  }

  /**
   * Clears Signature-specific key-derived data while preserving audit history.
   * @returns Completes when the operation has finished.
   */
  protected async _onResetKeyData(): Promise<void> {
    await this._contacts.clear();
    await this._stamps.adapter.clear();
    this._stamps = new MajikSignatureStampManager(this._stamps.adapter);

    // Deliberately NOT clearing _history/_activity here — see class docblock
    // note above. Audit trail must survive a key-data reset; record the
    // reset itself instead of erasing what came before it.
    await this._recordActivity(undefined, {
      reference_id: "key-data-reset",
      action: AuditActions.KEY_DATA_RESET, // ⚠️ verify this member exists
      metadata: { at: new Date().toISOString() },
    });
  }

  // ── Hydration ─────────────────────────────────────────────────────────────

  /**
   * Load all domains from their adapters and restore client state.
   * Call once on startup.
   *
   * Order matters: contacts/stamps must be hydrated before own-account
   * hydration, since _onAccountRegistered() syncs derived accounts into
   * the contact directory.
   *
   * ```ts
   * const client = new MajikSignatureClient({ adapters: { keys: idbAdapter, ... } });
   * await client.hydrate();
   * ```
   * @returns Completes when the operation has finished.
   */
  async hydrate(): Promise<void> {
    await this._hydrateKeys();
    await this._contacts.hydrate();
    await this._stamps.hydrate();
    await this._history.hydrate();
    await this._activity.hydrate();
    await this._hydrateState();
    await this._hydrateOwnAccounts();
    await this._restoreAccountOrder();
  }

  /**
   * Constructs a client and immediately hydrates it.
   *
   * @typeParam T - Concrete `MajikSignatureClient` subtype returned by the constructor.
   * @param config - Client configuration, including optional managers and storage adapters.
   * @returns The result of the create operation (`Promise<T>`).
   */
  static async create<T extends MajikSignatureClient>(
    this: new (config: MajikSignatureClientConfig) => T,
    config: MajikSignatureClientConfig = {},
  ): Promise<T> {
    const client = new this(config);
    await client.hydrate();
    return client;
  }

  // ── Logging (private, non-throwing) ─────────────────────────────────────

  /**
   * Lists history log entries associated with the currently active account.
   * @returns The result of the list history for active account operation (`HistoryLog[]`).
   */
  listHistoryForActiveAccount(): HistoryLog[] {
    const key = this.getActiveAccountKey();
    if (!key) return [];
    return this._history.listByFingerprint(key.fingerprint);
  }

  /**
   * Lists user activity log entries associated with the currently active account.
   * @returns The result of the list activity for active account operation (`UserActivityLog[]`).
   */
  listActivityForActiveAccount(): UserActivityLog[] {
    const key = this.getActiveAccountKey();
    if (!key) return [];
    return this._activity.listByFingerprint(key.fingerprint);
  }

  /**
   * Builds a MajikFileIdentity directly from an already-resolved, in-scope key —
   * never re-looks-up "the active account." Returns undefined (not throw) when
   * the key can't support envelope encryption, since logging must never block
   * the operation it's attached to.
   * @param key - MajikKey used as the cryptographic identity for the operation.
   * @returns The result of the identity from key operation (`MajikFileIdentity | undefined`).
   */
  private _identityFromKey(key: MajikKey): MajikFileIdentity | undefined {
    if (key.isLocked) return undefined;
    const mlKemSecretKey = this._keys.getMlKemSecretKey(key.id);
    if (!mlKemSecretKey) return undefined;
    return {
      publicKey: key.publicKeyBase64,
      fingerprint: key.fingerprint,
      mlKemPublicKey: key.mlKemPublicKey,
      mlKemSecretKey,
    };
  }

  /**
   * Writes a HistoryLog entry. Never throws — a logging failure must not fail
   * the signing/verification/seal operation it's attached to. `fingerprint` is
   * the caller's responsibility: pass the fingerprint of whichever key actually
   * performed the operation, not whatever happens to be the active account.
   * @param fingerprint - Majik identity fingerprint used to identify the owning cryptographic account.
   * @param options - Optional operation-specific settings.
   * @returns The result of the record history operation (`Promise<HistoryLog | null>`).
   */
  protected async _recordHistory(
    fingerprint: string | undefined,
    options: Omit<CreateHistoryLogOptions, "id" | "timestamp" | "fingerprint">,
  ): Promise<HistoryLog | null> {
    try {
      // 1. Fetch user app preferences
      const prefs = await this.getUserAppPreferences();
      const historyPrefs = prefs.general?.history;

      // 2. Abort if the user disabled history logging
      if (historyPrefs?.enabled === false) {
        return null;
      }

      // 3. Create the new log entry
      const entry = await this._history.create({ ...options, fingerprint });
      this._emit("history-log", entry);

      // 4. Enforce the maxCount limit
      const maxCount = historyPrefs?.maxCount ?? 100;

      if (fingerprint && maxCount > 0) {
        // Fetch all logs for this specific fingerprint
        const userLogs = this._history.listByFingerprint(fingerprint);

        if (userLogs.length > maxCount) {
          // Sort logs chronologically (oldest first) based on the timestamp string
          userLogs.sort(
            (a, b) =>
              new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime(),
          );

          // Identify the oldest logs that exceed the maxCount threshold
          const excessCount = userLogs.length - maxCount;
          const logsToDelete = userLogs.slice(0, excessCount);
          const idsToDelete = logsToDelete.map((log) => log.id);

          // Batch delete the old logs from cache and storage adapter
          await this._history.bulkRemove(idsToDelete);
        }
      }

      return entry;
    } catch (err) {
      console.warn("MajikSignatureClient: failed to record history log", err);
      return null;
    }
  }

  /**
   * Records a user activity entry without allowing logging failures to interrupt the calling operation.
   * @param fingerprint - Majik identity fingerprint used to identify the owning cryptographic account.
   * @param options - Optional operation-specific settings.
   * @returns The result of the record activity operation (`Promise<UserActivityLog | null>`).
   */
  protected async _recordActivity(
    fingerprint: string | undefined,
    options: Omit<
      CreateUserActivityLogOptions,
      "id" | "timestamp" | "fingerprint"
    >,
  ): Promise<UserActivityLog | null> {
    try {
      const entry = await this._activity.create({ ...options, fingerprint });
      this._emit("activity-log", entry);

      // Enforce the hardcoded 5000 log limit
      const MAX_ACTIVITY_LOGS = 5000;

      if (fingerprint) {
        const userLogs = this._activity.listByFingerprint(fingerprint);

        if (userLogs.length > MAX_ACTIVITY_LOGS) {
          // Sort logs chronologically (oldest first)
          userLogs.sort(
            (a, b) =>
              new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime(),
          );

          // Identify and bulk delete the oldest excess logs
          const excessCount = userLogs.length - MAX_ACTIVITY_LOGS;
          const logsToDelete = userLogs.slice(0, excessCount);
          const idsToDelete = logsToDelete.map((log) => log.id);

          await this._activity.bulkRemove(idsToDelete);
        }
      }

      return entry;
    } catch (err) {
      console.warn("MajikSignatureClient: failed to record activity log", err);
      return null;
    }
  }

  /**
   * Clears only the history logs for the active account.
   * @returns Completes when the operation has finished.
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async clearHistoryLogsForActiveAccount(): Promise<void> {
    const key = this.getActiveAccountKey();
    if (!key) {
      throw new Error("No active account — call setActiveAccount() first");
    }

    const fingerprint = key.fingerprint;
    const historyLogs = this._history.listByFingerprint(fingerprint);

    if (historyLogs.length > 0) {
      const historyIds = historyLogs.map((log) => log.id);
      await this._history.bulkRemove(historyIds);
    }
  }

  /**
   * Clears only the activity logs for the active account.
   * @returns Completes when the operation has finished.
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async clearActivityLogsForActiveAccount(): Promise<void> {
    const key = this.getActiveAccountKey();
    if (!key) {
      throw new Error("No active account — call setActiveAccount() first");
    }

    const fingerprint = key.fingerprint;
    const activityLogs = this._activity.listByFingerprint(fingerprint);

    if (activityLogs.length > 0) {
      const activityIds = activityLogs.map((log) => log.id);
      await this._activity.bulkRemove(activityIds);
    }
  }

  /**
   * Unified method: Clears both history and activity logs for the active account,
   * then seeds a new log acknowledging the reset.
   * @returns Completes when the operation has finished.
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async restartLogsForActiveAccount(): Promise<void> {
    const key = this.getActiveAccountKey();
    if (!key) {
      throw new Error("No active account — call setActiveAccount() first");
    }

    // Call the separated clear methods
    await this.clearHistoryLogsForActiveAccount();
    await this.clearActivityLogsForActiveAccount();

    // Record the restart action itself as the new initial log
    await this._recordActivity(key.fingerprint, {
      reference_id: "logs-restarted",
      action: AuditActions.KEY_DATA_RESET, // Adjust if you have a specific LOGS_CLEARED action
      metadata: {
        at: new Date().toISOString(),
        message: "History and activity logs restarted",
      },
    });
  }

  /**
   * Hydrate history + activity logs scoped to the active account's
   * fingerprint. Mirrors hydrateStampsForActiveAccount() — separate from
   * the general hydrate() above because it needs an unlocked active
   * account and is typically called after unlockAccount(), not at startup.
   * @returns Completes when the operation has finished.
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async hydrateLogsForActiveAccount(): Promise<void> {
    const key = this.getActiveAccountKey();
    if (!key)
      throw new Error("No active account — call setActiveAccount() first");
    await this._history.hydrateForFingerprint(key.fingerprint);
    await this._activity.hydrateForFingerprint(key.fingerprint);
  }

  // ==========================================================================
  // ── USER APP PREFERENCES ──────────────────────────────────────────────────────
  // ==========================================================================

  /**
   * Retrieve persisted user app prefernces, or `null` if none have been saved.
   * @returns The result of the get user app preferences operation (`Promise<UserAppPreferences>`).
   */
  async getUserAppPreferences(): Promise<UserAppPreferences> {
    return this.stateManager.getUserAppPreferences();
  }

  /**
   * Persist user app prefernces.
   * @param preferences - Application preferences to persist or restore.
   * @returns Completes when the operation has finished.
   */
  async setUserAppPreferences(preferences: UserAppPreferences): Promise<void> {
    await this.stateManager.setUserAppPreferences(preferences);
  }

  /**
   * Remove persisted user app prefernces.
   * @returns Completes when the operation has finished.
   */
  async removeUserAppPreferences(): Promise<void> {
    await this.stateManager.removeUserAppPreferences();
  }

  /**
   * Reset persisted user app prefernces to default settings.
   * @returns Completes when the operation has finished.
   */
  async resetUserAppPreferences(): Promise<void> {
    await this.stateManager.resetUserAppPreferences();
  }

  /**
   * Checks whether analytics sharing is enabled in the current application preferences.
   * @returns The result of the is analytics enabled operation (`Promise<boolean>`).
   */
  async isAnalyticsEnabled(): Promise<boolean> {
    const appPreferences = await this.stateManager.getUserAppPreferences();
    return appPreferences.privacy.shareAnalytics ?? false;
  }

  /**
   * Checks whether automatic sealing is enabled after signing.
   * @returns The result of the is auto seal enabled operation (`Promise<boolean>`).
   */
  async isAutoSealEnabled(): Promise<boolean> {
    const appPreferences = await this.stateManager.getUserAppPreferences();
    return appPreferences.signing.autoSeal ?? false;
  }

  /**
   * Checks whether timestamping with the configured TSA is enabled by default.
   * @returns The result of the is default to t s a enabled operation (`Promise<boolean>`).
   */
  async isDefaultToTSAEnabled(): Promise<boolean> {
    const appPreferences = await this.stateManager.getUserAppPreferences();
    return appPreferences.signing.defaultToTSA ?? false;
  }

  /**
   * Checks whether detached signing is enabled by default.
   * @returns The result of the is default to detached enabled operation (`Promise<boolean>`).
   */
  async isDefaultToDetachedEnabled(): Promise<boolean> {
    const appPreferences = await this.stateManager.getUserAppPreferences();
    return appPreferences.signing.defaultToDetached ?? false;
  }

  /**
   * Checks whether keys are automatically locked when the application is minimized.
   * @returns The result of the is auto lock on minimize enabled operation (`Promise<boolean>`).
   */
  async isAutoLockOnMinimizeEnabled(): Promise<boolean> {
    const appPreferences = await this.stateManager.getUserAppPreferences();
    return appPreferences.security?.key?.autoLockOnMinimize ?? false;
  }

  /**
   * Returns the configured automatic key-lock interval, when one is configured.
   * @returns The result of the auto lock interval operation (`Promise<number | undefined>`).
   */
  async autoLockInterval(): Promise<number | undefined> {
    const appPreferences = await this.stateManager.getUserAppPreferences();
    return appPreferences.security?.key?.autoLockInterval;
  }

  /**
   * Checks whether one-time unlock behavior is enabled.
   * @returns The result of the is onetime unlock enabled operation (`Promise<boolean>`).
   */
  async isOnetimeUnlockEnabled(): Promise<boolean> {
    const appPreferences = await this.stateManager.getUserAppPreferences();
    return appPreferences.security?.key?.onetimeUnlock ?? true;
  }

  /**
   * Checks whether signed output is automatically saved after signing.
   * @returns The result of the is auto save after sign enabled operation (`Promise<boolean>`).
   */
  async isAutoSaveAfterSignEnabled(): Promise<boolean> {
    const appPreferences = await this.stateManager.getUserAppPreferences();
    return appPreferences.signing?.autosave?.afterSign?.enabled ?? false;
  }

  /**
   * Checks whether output is automatically saved after sealing.
   * @returns The result of the is auto save after seal enabled operation (`Promise<boolean>`).
   */
  async isAutoSaveAfterSealEnabled(): Promise<boolean> {
    const appPreferences = await this.stateManager.getUserAppPreferences();
    return appPreferences.signing?.autosave?.afterSeal?.enabled ?? false;
  }

  /**
   * Checks whether output is automatically saved after notarization.
   * @returns The result of the is auto save after notarize enabled operation (`Promise<boolean>`).
   */
  async isAutoSaveAfterNotarizeEnabled(): Promise<boolean> {
    const appPreferences = await this.stateManager.getUserAppPreferences();
    return appPreferences.signing?.autosave?.afterNotary?.enabled ?? false;
  }

  // ==========================================================================
  // ── ACCOUNT MANAGEMENT (overrides / additions on top of MajikKeyClient) ──
  // ==========================================================================

  /**
   * Update the metadata (e.g., label) of an owned account.
   * This updates both the contact directory and the local ownAccounts cache.
   * @param id - Unique identifier of the target entity.
   * @param meta - Optional metadata associated with the contact, account, or group.
   * @returns Completes when the operation has finished.
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async updateOwnAccountMeta(
    id: string,
    meta: Partial<MajikContactMeta>,
  ): Promise<void> {
    if (!this._ownAccounts.has(id)) {
      throw new Error(`Account not found in own accounts: "${id}"`);
    }

    // 1. Update the contact record in the shared directory
    await this._contacts.updateContactMeta(id, meta);
    if (meta.label && meta.label.trim()) {
      await this.keyManager.updateLabel(id, meta.label);
    }

    // 2. Fetch the updated contact and sync the local _ownAccounts map
    const updatedContact = this._contacts.getContact(id);
    if (updatedContact) {
      this._ownAccounts.set(id, updatedContact);
    }
  }

  /**
   * Checks whether an identity with the supplied fingerprint exists in the key manager.
   * @param fingerprint - Majik identity fingerprint used to identify the owning cryptographic account.
   * @returns The result of the has own identity operation (`Promise<boolean>`).
   */
  async hasOwnIdentity(fingerprint: string): Promise<boolean> {
    return this.keyManager.has(fingerprint);
  }

  // ==========================================================================
  // ── CONTACT MANAGEMENT ────────────────────────────────────────────────────
  // ==========================================================================

  /**
   * Returns a contact by its unique identifier.
   * @param id - Unique identifier of the target entity.
   * @returns The result of the get contact by i d operation (`MajikContact | null`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  getContactByID(id: string): MajikContact | null {
    if (!id?.trim()) throw new Error("Invalid contact ID");
    return this._contacts.getContact(id) ?? null;
  }

  /**
   * Checks whether a contact with the supplied identifier exists.
   * @param id - Unique identifier of the target entity.
   * @returns The result of the has contact operation (`boolean`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  hasContact(id: string): boolean {
    if (!id?.trim()) throw new Error("Invalid contact ID");
    return this._contacts.hasContact(id);
  }

  /**
   * Checks whether a contact exists for the supplied public-key address.
   * @param publicKey - Public-key address or key material used to identify or resolve a signer.
   * @returns The result of the has contact by address operation (`Promise<boolean>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async hasContactByAddress(publicKey: MajikKeyAddress): Promise<boolean> {
    if (!publicKey?.trim())
      throw new Error("Invalid contact public key address");
    return await this._contacts.hasContactByAddress(publicKey);
  }

  /**
   * Returns a contact associated with the supplied public-key address.
   * @param address - Public-key address used to identify a contact or signer.
   * @returns The result of the get contact by address operation (`Promise<MajikContact | null>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async getContactByAddress(
    address: MajikKeyAddress,
  ): Promise<MajikContact | null> {
    if (!address?.trim()) throw new Error("Invalid public key address");
    return (await this._contacts.getContactByAddress(address)) ?? null;
  }

  /**
   * Returns contacts matching the supplied identifiers.
   * @param ids - Collection of entity identifiers to resolve.
   * @param strict - Whether missing or unmatched entities should be treated as an error instead of being skipped.
   * @returns The result of the get contacts by i d operation (`MajikContact[]`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  getContactsByID(ids: string[], strict = false): MajikContact[] {
    if (!ids?.length) throw new Error("At least 1 id is required");
    return this._contacts.getContactsByIds(ids, strict);
  }

  /**
   * Returns contacts matching the supplied public keys.
   * @param publicKeys - Collection of public keys used to resolve contacts or verify signatures.
   * @returns The result of the get contacts by public key operation (`Promise<MajikContact[]>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async getContactsByPublicKey(publicKeys: string[]): Promise<MajikContact[]> {
    if (!publicKeys?.length)
      throw new Error("At least 1 public key is required");
    return await this._contacts.getContactsByPublicKeys(publicKeys);
  }

  /**
   * Exports a contact as a JSON string suitable for storage or transport.
   * @param id - Unique identifier of the target entity.
   * @returns The result of the export contact as j s o n operation (`Promise<string | null>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async exportContactAsJSON(id: string): Promise<string | null> {
    if (!id?.trim()) throw new Error("Invalid contact ID");
    return this._contacts.exportContactAsJSON(id);
  }

  /**
   * Exports a contact using the contact manager string representation.
   * @param id - Unique identifier of the target entity.
   * @returns The result of the export contact as string operation (`Promise<string | null>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async exportContactAsString(id: string): Promise<string | null> {
    if (!id?.trim()) throw new Error("Invalid contact ID");
    return this._contacts.exportContactAsString(id);
  }

  /**
   * Imports a contact from its JSON representation.
   * @param jsonStr - Serialized contact JSON string.
   * @returns The result of the import contact from j s o n operation (`Promise<MAJIK_API_RESPONSE>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async importContactFromJSON(jsonStr: string): Promise<MAJIK_API_RESPONSE> {
    if (!jsonStr?.trim()) throw new Error("Invalid contact JSON");
    return this._contacts.importContactFromJSON(jsonStr);
  }

  /**
   * Imports a contact from the contact manager string representation.
   * @param base64Str - Base64-encoded serialized contact or backup value.
   * @returns The result of the import contact from string operation (`Promise<MAJIK_API_RESPONSE>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async importContactFromString(
    base64Str: string,
  ): Promise<MAJIK_API_RESPONSE> {
    if (!base64Str?.trim()) throw new Error("Invalid contact string");

    const response = await this._contacts.importContactFromString(base64Str);

    if (response.success) {
      this._emit("new-contact", response.data);
    } else {
      this._emit("error", response.message);
    }

    return response;
  }

  /**
   * Exports a contact as a compressed, portable base64 representation.
   * @param contact - Majik contact record to add, export, or otherwise operate on.
   * @returns The result of the export contact compressed operation (`Promise<string>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async exportContactCompressed(contact: MajikContact): Promise<string> {
    if (!contact?.id?.trim()) throw new Error("Invalid contact");
    return this._contacts.exportContactCompressed(contact);
  }

  /**
   * Imports a contact from a compressed base64 representation.
   * @param base64Str - Base64-encoded serialized contact or backup value.
   * @returns The result of the import contact compressed operation (`Promise<MajikContact>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async importContactCompressed(base64Str: string): Promise<MajikContact> {
    if (!base64Str?.trim()) throw new Error("Invalid contact string");
    return this._contacts.importContactCompressed(base64Str);
  }

  /**
   * Adds a contact to the shared contact directory and records the corresponding activity event.
   * @param contact - Majik contact record to add, export, or otherwise operate on.
   * @returns Completes when the operation has finished.
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async addContact(contact: MajikContact): Promise<void> {
    if (
      !contact?.id ||
      !contact?.publicKey ||
      !contact?.fingerprint ||
      !contact?.mlKey
    ) {
      throw new Error("Invalid contact — missing required fields");
    }
    await this._contacts.addContact(contact);

    this._recordActivity(this.getActiveAccountKey()?.fingerprint, {
      reference_id: contact.id,
      action: AuditActions.CONTACT_ADDED, // ⚠️ verify member name
      metadata: { contactFingerprint: contact.fingerprint },
    });

    this._emit("new-contact", contact);
  }

  /**
   * Removes a contact from the shared contact directory.
   * @param id - Unique identifier of the target entity.
   * @returns Completes when the operation has finished.
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async removeContact(id: string): Promise<void> {
    const result = await this._contacts.removeContact(id);
    if (!result.success) throw new Error(result.message);

    this._recordActivity(this.getActiveAccountKey()?.fingerprint, {
      reference_id: id,
      action: AuditActions.CONTACT_DELETED, // ⚠️
    });

    this._emit("removed-contact", id);
  }

  /**
   * Lists contacts, optionally including the client’s own accounts and restricting results to Majikah contacts.
   * @param includeOwnAccounts - Whether the returned contact collection should include the client’s own accounts.
   * @param majikahOnly - Whether to restrict results to Majikah contacts.
   * @returns The result of the list contacts operation (`MajikContact[]`).
   */
  listContacts(
    includeOwnAccounts = false,
    majikahOnly: boolean = false,
  ): MajikContact[] {
    const contacts = this._contacts.listContacts(true, majikahOnly);
    if (includeOwnAccounts) return contacts;
    const ownIds = new Set(this.listOwnAccounts().map((a) => a.id));
    return contacts.filter((c) => !ownIds.has(c.id));
  }

  /**
   * Updates metadata for a contact in the shared directory.
   * @param id - Unique identifier of the target entity.
   * @param meta - Optional metadata associated with the contact, account, or group.
   * @returns Completes when the operation has finished.
   */
  async updateContactMeta(
    id: string,
    meta: Partial<MajikContactMeta>,
  ): Promise<void> {
    await this._contacts.updateContactMeta(id, meta);
  }

  /**
   * Creates a contact group and optionally populates it with initial members.
   * @param id - Unique identifier of the target entity.
   * @param name - Human-readable name for the new or existing asset.
   * @param meta - Optional metadata associated with the contact, account, or group.
   * @param initialMemberIds - Optional contact identifiers to add when the group is created.
   * @returns The result of the create group operation (`Promise<this>`).
   */
  async createGroup(
    id: string,
    name: string,
    meta?: Partial<Omit<MajikContactGroupMeta, "name">>,
    initialMemberIds?: string[],
  ): Promise<this> {
    const newGroup = await this._contacts.createGroup(
      id,
      name,
      meta,
      initialMemberIds,
    );
    this._emit("new-contact-group", newGroup);
    return this;
  }

  /**
   * Adds an existing contact group to the directory.
   * @param group - Value used by the add group operation.
   * @returns The result of the add group operation (`Promise<this>`).
   */
  async addGroup(group: MajikContactGroup): Promise<this> {
    await this._contacts.addGroup(group);
    this._emit("new-contact-group", group);
    return this;
  }

  /**
   * Removes a contact group from the directory.
   * @param id - Unique identifier of the target entity.
   * @returns The result of the remove group operation (`Promise<MAJIK_API_RESPONSE>`).
   */
  async removeGroup(id: string): Promise<MAJIK_API_RESPONSE> {
    const response = await this._contacts.removeGroup(id);
    this._emit("removed-contact-group", response.data as MajikContactGroup);
    return response;
  }

  /**
   * Returns a contact group by identifier, or undefined when it is not present.
   * @param id - Unique identifier of the target entity.
   * @returns The result of the get contact group operation (`MajikContactGroup | undefined`).
   */
  getContactGroup(id: string): MajikContactGroup | undefined {
    return this._contacts.getGroup(id);
  }

  /**
   * Returns a contact group by identifier and throws when it cannot be found.
   * @param id - Unique identifier of the target entity.
   * @returns The result of the get group or throw operation (`MajikContactGroup`).
   */
  getGroupOrThrow(id: string): MajikContactGroup {
    return this._contacts.getGroupOrThrow(id);
  }

  /**
   * Checks whether a contact group exists.
   * @param id - Unique identifier of the target entity.
   * @returns The result of the has group operation (`boolean`).
   */
  hasGroup(id: string): boolean {
    return this._contacts.hasGroup(id);
  }

  /**
   * Lists contact groups with optional inclusion of system groups and name sorting.
   * @param includeSystem - Whether system-managed groups should be included.
   * @param sortedByName - Whether groups should be sorted by display name.
   * @returns The result of the list contact groups operation (`MajikContactGroup[]`).
   */
  listContactGroups(
    includeSystem = true,
    sortedByName = false,
  ): MajikContactGroup[] {
    return this._contacts.listGroups(includeSystem, sortedByName);
  }

  /**
   * Lists user-created contact groups.
   * @param sortedByName - Whether groups should be sorted by display name.
   * @returns The result of the list user groups operation (`MajikContactGroup[]`).
   */
  listUserGroups(sortedByName = true): MajikContactGroup[] {
    return this._contacts.listGroups(false, sortedByName);
  }

  /**
   * Lists system-managed contact groups.
   * @returns The result of the list system groups operation (`MajikContactGroup[]`).
   */
  listSystemGroups(): MajikContactGroup[] {
    return this._contacts.listGroups(true).filter((g) => g.isSystem);
  }

  /**
   * Updates mutable metadata for a contact group.
   * @param id - Unique identifier of the target entity.
   * @param meta - Optional metadata associated with the contact, account, or group.
   * @returns The result of the update group meta operation (`Promise<this>`).
   */
  async updateGroupMeta(
    id: string,
    meta: Partial<
      Pick<MajikContactGroupMeta, "name" | "description" | "color">
    >,
  ): Promise<this> {
    const updatedGroup = await this._contacts.updateGroupMeta(id, meta);
    this._emit("contact-group-change", updatedGroup);
    return this;
  }

  /**
   * Adds one contact to a contact group.
   * @param groupID - Identifier of the target contact group.
   * @param contactID - Contact identifier used to resolve the member being updated.
   * @returns The result of the add contact to group operation (`Promise<this>`).
   */
  async addContactToGroup(groupID: string, contactID: string): Promise<this> {
    const updatedGroup = await this._contacts.addContactToGroup(
      groupID,
      contactID,
    );
    this._emit("contact-group-change", updatedGroup);
    return this;
  }

  /**
   * Adds multiple contacts to a contact group.
   * @param groupID - Identifier of the target contact group.
   * @param contactIds - Collection of contact identifiers to add to the group.
   * @returns The result of the add contacts to group operation (`Promise<this>`).
   */
  async addContactsToGroup(
    groupID: string,
    contactIds: string[],
  ): Promise<this> {
    const updatedGroup = await this._contacts.addContactsToGroup(
      groupID,
      contactIds,
    );
    this._emit("contact-group-change", updatedGroup);
    return this;
  }

  /**
   * Removes one contact from a contact group.
   * @param groupID - Identifier of the target contact group.
   * @param contactID - Contact identifier used to resolve the member being updated.
   * @returns The result of the remove contact from group operation (`Promise<this>`).
   */
  async removeContactFromGroup(
    groupID: string,
    contactID: string,
  ): Promise<this> {
    const updatedGroup = await this._contacts.removeContactFromGroup(
      groupID,
      contactID,
    );
    this._emit("contact-group-change", updatedGroup);
    return this;
  }

  /**
   * Moves a contact from one group to another.
   * @param contactID - Contact identifier used to resolve the member being updated.
   * @param fromGroupId - Identifier of the source contact group.
   * @param toGroupId - Identifier of the destination contact group.
   * @returns The result of the move contact between groups operation (`Promise<this>`).
   */
  async moveContactBetweenGroups(
    contactID: string,
    fromGroupId: string,
    toGroupId: string,
  ): Promise<this> {
    const updatedGroup = await this._contacts.moveContactBetweenGroups(
      contactID,
      fromGroupId,
      toGroupId,
    );
    this._emit("contact-group-change", updatedGroup);
    return this;
  }

  /**
   * Returns contacts belonging to a contact group.
   * @param groupID - Identifier of the target contact group.
   * @returns The result of the get contacts in group operation (`MajikContact[]`).
   */
  getContactsInGroup(groupID: string): MajikContact[] {
    return this._contacts.getContactsInGroup(groupID);
  }

  /**
   * Returns contacts belonging to a contact group in sorted order.
   * @param groupID - Identifier of the target contact group.
   * @returns The result of the get contacts in group sorted operation (`MajikContact[]`).
   */
  getContactsInGroupSorted(groupID: string): MajikContact[] {
    return this._contacts.getContactsInGroupSorted(groupID);
  }

  /**
   * Checks whether a contact belongs to a contact group.
   * @param groupID - Identifier of the target contact group.
   * @param contactID - Contact identifier used to resolve the member being updated.
   * @returns The result of the is contact in group operation (`boolean`).
   */
  isContactInGroup(groupID: string, contactID: string): boolean {
    return this._contacts.isContactInGroup(groupID, contactID);
  }

  /**
   * Returns all groups containing the specified contact.
   * @param contactID - Contact identifier used to resolve the member being updated.
   * @returns The result of the get groups for contact operation (`MajikContactGroup[]`).
   */
  getGroupsForContact(contactID: string): MajikContactGroup[] {
    return this._contacts.getGroupsForContact(contactID);
  }

  /**
   * Returns the identifiers of groups containing the specified contact.
   * @param contactID - Contact identifier used to resolve the member being updated.
   * @returns The result of the get group ids for contact operation (`string[]`).
   */
  getGroupIdsForContact(contactID: string): string[] {
    return this._contacts.getGroupIdsForContact(contactID);
  }

  /**
   * Adds a contact to the built-in favorites group.
   * @param contactID - Contact identifier used to resolve the member being updated.
   * @returns The result of the add contact to favorites operation (`Promise<this>`).
   */
  async addContactToFavorites(contactID: string): Promise<this> {
    const updatedGroup = await this._contacts.addToFavorites(contactID);
    this._emit("contact-group-change", updatedGroup);
    return this;
  }

  /**
   * Removes a contact from the built-in favorites group.
   * @param contactID - Contact identifier used to resolve the member being updated.
   * @returns The result of the remove contact from favorites operation (`Promise<this>`).
   */
  async removeContactFromFavorites(contactID: string): Promise<this> {
    const updatedGroup = await this._contacts.removeFromFavorites(contactID);
    this._emit("contact-group-change", updatedGroup);
    return this;
  }

  /**
   * Checks whether a contact is in the favorites group.
   * @param contactID - Contact identifier used to resolve the member being updated.
   * @returns The result of the is contact favorite operation (`boolean`).
   */
  isContactFavorite(contactID: string): boolean {
    return this._contacts.isFavorite(contactID);
  }
  /**
   * Checks whether a contact is in the blocked group.
   * @param contactID - Contact identifier used to resolve the member being updated.
   * @returns The result of the is contact blocked operation (`boolean`).
   */
  isContactBlocked(contactID: string): boolean {
    return this._contacts.isContactBlocked(contactID);
  }
  /**
   * Returns the built-in favorites group.
   * @returns The result of the get favorites group operation (`MajikContactGroup`).
   */
  getFavoritesGroup(): MajikContactGroup {
    return this._contacts.getFavoritesGroup();
  }
  /**
   * Returns the built-in blocked group.
   * @returns The result of the get blocked group operation (`MajikContactGroup`).
   */
  getBlockedGroup(): MajikContactGroup {
    return this._contacts.getBlockedGroup();
  }

  /**
   * Returns all contacts in the favorites group.
   * @returns The result of the get favorite contacts operation (`MajikContact[]`).
   */
  getFavoriteContacts(): MajikContact[] {
    return this._contacts.getContactsInGroup(
      this._contacts.getFavoritesGroup().id,
    );
  }

  /**
   * Returns all contacts in the blocked group.
   * @returns The result of the get blocked contacts operation (`MajikContact[]`).
   */
  getBlockedContacts(): MajikContact[] {
    return this._contacts.getContactsInGroup(
      this._contacts.getBlockedGroup().id,
    );
  }

  /**
   * Clears the shared contact directory and returns the client for chaining.
   * @returns The result of the clear directory operation (`Promise<this>`).
   */
  async clearDirectory(): Promise<this> {
    await this._contacts.clear();
    return this;
  }

  /**
   * Resolves a human-readable signer label from owned accounts or the contact directory.
   * @param signerId - Signer identifier whose display label should be resolved.
   * @returns The result of the resolve signer label operation (`string`).
   */
  resolveSignerLabel(signerId: string): string {
    const ownAccount = this._ownAccounts.get(signerId);
    if (ownAccount?.meta?.label) return ownAccount.meta.label;
    const contact = this._contacts.getContact(signerId);
    if (contact?.meta?.label) return contact.meta.label;
    return `${signerId.slice(0, 16)}…`;
  }

  // ── Signing ───────────────────────────────────────────────────────────────

  /**
   * Creates a cryptographic signature for text or raw bytes using a selected signing account. The selected account must have usable signing keys and be unlocked when the underlying operation requires private-key access.
   * @param content - Content to process, supplied as text or raw bytes.
   * @param options - Optional operation-specific settings.
   * @param accountId - Account identifier to use. When omitted, the currently active account is used where supported.
   * @param source - History source recorded for the operation.
   * @returns The result of the sign operation (`Promise<SignResult>`).
   */
  async sign(
    content: Uint8Array | string,
    options?: SignOptions,
    accountId?: string,
    source: HistorySource = HistorySources.SYSTEM,
  ): Promise<SignResult> {
    return this._withSigningKey(accountId, "sign", async (key) => {
      const signature = await MajikSignature.sign(content, key, options);

      const result: SignResult = {
        signature,
        signerId: signature.signerId,
        contentHash: signature.contentHash,
        timestamp: signature.timestamp,
        contentType: signature.contentType,
      };

      this._recordHistory(key.fingerprint, {
        reference_id: result.contentHash,
        historyType: HistoryTypes.SIGN,
        status: HistoryStatuses.SUCCESS,
        source,
        operation: {
          digest: result.contentHash,
          detached: false,
          sealed: false,
          tsa: false,
        },
        signerCount: 1,
      }).catch((err) => console.warn(err));

      this._emit("sign", result);
      return result;
    });
  }

  /**
   * Sign content and immediately serialize to a base64 string.
   * Convenience wrapper around sign() + serialize().
   * @param content - Content to process, supplied as text or raw bytes.
   * @param options - Optional operation-specific settings.
   * @param accountId - Account identifier to use. When omitted, the currently active account is used where supported.
   * @returns The result of the sign and serialize operation (`Promise<string>`).
   */
  async signAndSerialize(
    content: Uint8Array | string,
    options?: SignOptions,
    accountId?: string,
  ): Promise<string> {
    const { signature } = await this.sign(content, options, accountId);
    return signature.serialize();
  }

  /**
   * Sign content and return the full JSON envelope.
   * Convenience wrapper around sign() + toJSON().
   * @param content - Content to process, supplied as text or raw bytes.
   * @param options - Optional operation-specific settings.
   * @param accountId - Account identifier to use. When omitted, the currently active account is used where supported.
   * @returns The result of the sign to j s o n operation (`Promise<MajikSignatureJSON>`).
   */
  async signToJSON(
    content: Uint8Array | string,
    options?: SignOptions,
    accountId?: string,
  ): Promise<MajikSignatureJSON> {
    const { signature } = await this.sign(content, options, accountId);
    return signature.toJSON();
  }

  // ── Verification ──────────────────────────────────────────────────────────

  /**
   * Verify a signature against content.
   *
   * Public keys can be supplied directly, extracted from the envelope itself,
   * or resolved from a known MajikKey account or contact in the directory.
   *
   * No private key is needed. Safe to call on locked accounts.
   *
   * @param content     - The original content that was signed
   * @param signature   - MajikSignature instance, JSON object, or base64 string
   * @param publicKeys  - Optional. If omitted, public keys are extracted from
   *                        the envelope (self-reported — cross-check signerId
   *                        against a trusted source for full security).
   * @param source - History source recorded for the operation.
   * @param now - Optional point-in-time used when evaluating temporal validity; defaults to the current time when omitted.
   * @returns The result of the verify operation (`VerifyResult`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  verify(
    content: Uint8Array | string,
    signature: MajikSignature | MajikSignatureJSON | string,
    publicKeys?: MajikSignerPublicKeys,
    source: HistorySource = HistorySources.SYSTEM,
    now?: Date,
  ): VerifyResult {
    try {
      // Deserialize if base64 string
      const sig =
        typeof signature === "string"
          ? MajikSignature.deserialize(signature)
          : signature instanceof MajikSignature
            ? signature
            : MajikSignature.fromJSON(signature);

      // Resolve public keys
      const keys: MajikSignerPublicKeys =
        publicKeys ??
        (sig instanceof MajikSignature
          ? sig.extractPublicKeys()
          : MajikSignature.fromJSON(
              sig as MajikSignatureJSON,
            ).extractPublicKeys());

      const result = MajikSignature.verify(content, sig, keys, now);

      const verifyResult: VerifyResult = {
        ...result,
        signerLabel: result.signerId?.trim()
          ? this.resolveSignerLabel(result.signerId)
          : undefined,
      };

      this._recordHistory(this.getActiveAccountKey()?.fingerprint, {
        reference_id: verifyResult.contentHash!,
        historyType: HistoryTypes.VERIFY,
        status: verifyResult.valid
          ? HistoryStatuses.SUCCESS
          : HistoryStatuses.FAILED,
        source,
        operation: {
          digest: verifyResult.contentHash!,
          detached: false,
          sealed: false,
          tsa: false,
        },
        valid: verifyResult.valid,
      }).catch((err) => console.warn(err));

      this._emit("verify", verifyResult);
      return verifyResult;
    } catch (err) {
      this._emit("error", err, { context: "verify" });
      throw err;
    }
  }

  /**
   * Verify against a specific known MajikKey account.
   * Automatically extracts public keys from the key client.
   * Works on locked accounts — only public key fields are used.
   * @param content - Content to process, supplied as text or raw bytes.
   * @param signature - Signature value, supplied as a MajikSignature, JSON representation, or serialized string as supported by the method.
   * @param accountId - Account identifier to use. When omitted, the currently active account is used where supported.
   * @param source - History source recorded for the operation.
   * @param now - Optional point-in-time used when evaluating temporal validity; defaults to the current time when omitted.
   * @returns The result of the verify with account operation (`VerifyResult`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  verifyWithAccount(
    content: Uint8Array | string,
    signature: MajikSignature | MajikSignatureJSON | string,
    accountId: string,
    source: HistorySource = HistorySources.SYSTEM,
    now?: Date,
  ): VerifyResult {
    const key = this._keys.get(accountId);
    if (!key) throw new Error(`Account not found: "${accountId}"`);

    if (!key.hasSigningKeys) {
      throw new Error(
        `Account "${accountId}" has no signing public keys. ` +
          `Re-import via importAccountFromMnemonicBackup() to enable verification.`,
      );
    }

    const publicKeys = MajikSignature.publicKeysFromMajikKey(key);
    return this.verify(content, signature, publicKeys, source, now);
  }

  /**
   * Verify against a contact from the directory by their ID.
   * Useful when you have the signer's contact card stored locally.
   * @param content - Content to process, supplied as text or raw bytes.
   * @param signature - Signature value, supplied as a MajikSignature, JSON representation, or serialized string as supported by the method.
   * @param contactId - Contact identifier used to resolve and trust a signer.
   * @param source - History source recorded for the operation.
   * @param now - Optional point-in-time used when evaluating temporal validity; defaults to the current time when omitted.
   * @returns The result of the verify with contact operation (`Promise<VerifyResult>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async verifyWithContact(
    content: Uint8Array | string,
    signature: MajikSignature | MajikSignatureJSON | string,
    contactId: string,
    source: HistorySource = HistorySources.SYSTEM,
    now?: Date,
  ): Promise<VerifyResult> {
    const contact = this._contacts.getContact(contactId);
    if (!contact) throw new Error(`Contact not found: "${contactId}"`);

    const sig =
      typeof signature === "string"
        ? MajikSignature.deserialize(signature)
        : signature instanceof MajikSignature
          ? signature
          : MajikSignature.fromJSON(signature as MajikSignatureJSON);

    // Cross-check: the envelope's signerId must match the contact's fingerprint
    const envelopeSignerId =
      sig instanceof MajikSignature
        ? sig.signerId
        : (sig as MajikSignatureJSON).signerId;

    if (envelopeSignerId !== contact.fingerprint) {
      const result: VerifyResult = {
        valid: false,
        signerId: envelopeSignerId,
        contentHash:
          sig instanceof MajikSignature
            ? sig.contentHash
            : (sig as MajikSignatureJSON).contentHash,
        timestamp:
          sig instanceof MajikSignature
            ? sig.timestamp
            : (sig as MajikSignatureJSON).timestamp,
        signerLabel: this.resolveSignerLabel(envelopeSignerId),
        reason: "Signer does not match contact",
      };
      this._emit("verify", result);
      return result;
    }

    if (!contact.edPublicKeyBase64 || !contact.mlDsaPublicKeyBase64) {
      throw new Error(`Contact "${contactId}" has no signing public keys.`);
    }
    const publicKeys: MajikSignerPublicKeys = {
      signerId: contact.fingerprint,
      edPublicKey: base64ToUint8Array(contact.edPublicKeyBase64),
      mlDsaPublicKey: base64ToUint8Array(contact.mlDsaPublicKeyBase64),
    };

    return this.verify(content, sig, publicKeys, source, now);
  }

  /**
   * Batch verify multiple signatures against the same content.
   * Returns one VerifyResult per signature in the same order.
   * @param content - Content to process, supplied as text or raw bytes.
   * @param signatures - Collection of signatures to verify or process.
   * @param publicKeys - Collection of public keys used to resolve contacts or verify signatures.
   * @param source - History source recorded for the operation.
   * @param now - Optional point-in-time used when evaluating temporal validity; defaults to the current time when omitted.
   * @returns The result of the verify batch operation (`VerifyResult[]`).
   */
  verifyBatch(
    content: Uint8Array | string,
    signatures: Array<MajikSignature | MajikSignatureJSON | string>,
    publicKeys?: MajikSignerPublicKeys,
    source: HistorySource = HistorySources.SYSTEM,
    now?: Date,
  ): VerifyResult[] {
    return signatures.map((sig) => {
      try {
        return this.verify(content, sig, publicKeys, source, now);
      } catch (err) {
        this._emit("error", err, { context: "verifyBatch" });
        return {
          valid: false,
          signerId: "",
          contentHash: "",
          timestamp: "",
          signerLabel: undefined,
        };
      }
    });
  }

  // ── Text / Detached Signing ───────────────────────────────────────────────────

  /**
   * Convenience alias for signing a plain string.
   *
   * @example
   *     const sig = await majik.signText("Hello world", { contentType: "text/plain" });
   *     const b64 = sig.serialize(); // store alongside the text
   * @param text - Non-empty text content to process.
   * @param options - Optional operation-specific settings.
   * @returns The result of the sign text operation (`Promise<MajikSignature>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async signText(
    text: string,
    options?: {
      contentType?: string;
      timestamp?: string;
      accountId?: string;
      validUntil?: string;
    },
  ): Promise<MajikSignature> {
    if (!text?.trim())
      throw new Error("signText: text must be a non-empty string");
    return this.signContent(text, options);
  }

  /**
   * Sign content and return both the MajikSignature instance and a portable
   * base64-serialized string in one call.
   *
   * @example — sign a document and store the detached signature
   *     const { serialized } = await majik.signAndDetach(docBytes, {
   *       contentType: "application/pdf",
   *     });
   *     await db.insert({ doc_id, signature: serialized });
   * @param content - Content to process, supplied as text or raw bytes.
   * @param options - Optional operation-specific settings.
   * @returns The result of the sign and detach operation (`Promise<{ signature: MajikSignature; serialized: string }>`).
   */
  async signAndDetach(
    content: Uint8Array | string,
    options?: {
      contentType?: string;
      timestamp?: string;
      accountId?: string;
      validUntil?: string;
    },
  ): Promise<{ signature: MajikSignature; serialized: string }> {
    const signature = await this.signContent(content, options);
    return { signature, serialized: signature.serialize() };
  }

  // ── Text / Detached Verification ──────────────────────────────────────────────

  /**
   * Verify a plain string against a MajikSignature.
   *
   * @example
   *     const result = await majik.verifyText("Hello world", sig, {
   *       contactId: "contact_abc",
   *     });
   *     if (result.valid) console.log("Authentic");
   * @param text - Non-empty text content to process.
   * @param signature - Signature value, supplied as a MajikSignature, JSON representation, or serialized string as supported by the method.
   * @param options - Optional operation-specific settings.
   * @returns The result of the verify text operation (`Promise<VerificationResult>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async verifyText(
    text: string,
    signature: MajikSignature | MajikSignatureJSON | string,
    options?: {
      contactId?: string;
      publicKeyBase64?: string;
      key?: MajikKey;
      expectedSignerId?: string;
      now?: Date;
    },
  ): Promise<VerificationResult> {
    if (!text?.trim())
      throw new Error("verifyText: text must be a non-empty string");

    const sig =
      typeof signature === "string"
        ? MajikSignature.deserialize(signature)
        : signature;

    return this.verifyContent(text, sig, options);
  }

  /**
   * Verify content against a base64-serialized detached signature string.
   *
   * @example
   *     const row = await db.findOne({ doc_id });
   *     const result = await majik.verifyDetached(docBytes, row.signature, {
   *       contactId: row.signer_contact_id,
   *     });
   *     if (result.valid) console.log("Signed by", result.signerId);
   * @param content - Content to process, supplied as text or raw bytes.
   * @param serializedSignature - Detached serialized signature to parse and verify.
   * @param options - Optional operation-specific settings.
   * @param source - History source recorded for the operation.
   * @returns The result of the verify detached operation (`Promise<VerificationResult>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async verifyDetached(
    content: Uint8Array | string,
    serializedSignature: string,
    options?: {
      contactId?: string;
      publicKeyBase64?: string;
      key?: MajikKey;
      expectedSignerId?: string;
      now?: Date;
    },
    source: HistorySource = HistorySources.SYSTEM,
  ): Promise<VerificationResult> {
    if (!serializedSignature?.trim()) {
      throw new Error(
        "verifyDetached: serializedSignature must be a non-empty string",
      );
    }

    let sig: MajikSignature;
    try {
      sig = MajikSignature.deserialize(serializedSignature);
    } catch {
      // Fallback: maybe caller passed raw JSON rather than base64
      try {
        sig = MajikSignature.fromJSON(serializedSignature);
      } catch {
        throw new Error(
          "verifyDetached: could not parse signature — expected a base64 " +
            "string from sig.serialize() or a JSON string from sig.toJSON()",
        );
      }
    }

    const verifyResult = await this.verifyContent(
      content,
      sig,
      options,
      source,
    );

    return verifyResult;
  }

  // ── Signature Serialization Helpers ──────────────────────────────────────────

  /**
   * Deserialize a base64 signature string into a MajikSignature client.
   *
   * @example
   *     const sig = majik.deserializeSignature(storedBase64);
   *     console.log(sig.signerId, sig.timestamp);
   * @param serialized - Serialized signature or data representation.
   * @returns The result of the deserialize signature operation (`MajikSignature`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  deserializeSignature(serialized: string): MajikSignature {
    if (!serialized?.trim()) {
      throw new Error("deserializeSignature: input must be a non-empty string");
    }
    return MajikSignature.deserialize(serialized);
  }

  /**
   * Extract lightweight metadata from a base64 or JSON signature string
   * without performing cryptographic verification.
   *
   * @example
   *     const meta = majik.getSignatureMetadata(storedSig);
   *     if (meta) {
   *       const contact = majik.getContactByID(meta.signerId);
   *       console.log(`Signed by ${contact?.meta?.label ?? meta.signerId} at ${meta.timestamp}`);
   *     }
   * @param serialized - Serialized signature or data representation.
   * @returns The result of the get signature metadata operation (`{ signerId: string; timestamp: string; contentType: string | undefined; contentHash: string; version: number; } | null`).
   */
  getSignatureMetadata(serialized: string): {
    signerId: string;
    timestamp: string;
    contentType: string | undefined;
    contentHash: string;
    version: number;
  } | null {
    if (!serialized?.trim()) return null;

    try {
      let sig: MajikSignature;
      try {
        sig = MajikSignature.deserialize(serialized);
      } catch {
        sig = MajikSignature.fromJSON(serialized);
      }

      return {
        signerId: sig.signerId,
        timestamp: sig.timestamp,
        contentType: sig.contentType,
        contentHash: sig.contentHash,
        version: sig.version,
      };
    } catch {
      return null;
    }
  }

  // ── Content & File Signing ────────────────────────────────────────────────

  /**
   * Sign raw bytes or a string using the active account.
   *
   * @example
   *     const sig = await majik.signContent(documentBytes, { contentType: "application/pdf" });
   *     const b64 = sig.serialize(); // store alongside the document
   * @param content - Content to process, supplied as text or raw bytes.
   * @param options - Optional operation-specific settings.
   * @param source - History source recorded for the operation.
   * @returns The result of the sign content operation (`Promise<MajikSignature>`).
   */
  async signContent(
    content: Uint8Array | string,
    options?: {
      contentType?: string;
      timestamp?: string;
      accountId?: string;
      validUntil?: string;
    },
    source: HistorySource = HistorySources.SYSTEM,
  ): Promise<MajikSignature> {
    const { signature } = await this.sign(
      content,
      {
        contentType: options?.contentType,
        timestamp: options?.timestamp,
        validUntil: options?.validUntil,
      },
      options?.accountId,
      source,
    );
    return signature;
  }

  /**
   * Sign a file and embed the signature directly into it using the active account.
   *
   * @example
   *     const { blob: signedPdf } = await majik.signFile(pdfBlob);
   *
   * @example — non-active account
   *     const { blob } = await majik.signFile(wavBlob, { accountId: "acc_xyz" });
   * @param file - Input file or Blob-like value to sign, verify, inspect, or transform.
   * @param options - Optional operation-specific settings.
   * @param source - History source recorded for the operation.
   * @returns The result of the sign file operation (`Promise<Awaited<ReturnType<typeof MajikSignature.signFile>>>`).
   */

  async signFile(
    file: FileLike,
    options?: {
      contentType?: string;
      timestamp?: string;
      mimeType?: string;
      accountId?: string;
      expectedSigners?: ExpectedSigner[];
      validUntil?: string;
      /** Pre-stamp original, when the current file's embedded envelope was
       *  destroyed by a wholesale re-encode (PDF flatten, image re-render,
       *  audio re-mux). Lets the prior signature chain be recovered. */
      priorSignedFile?: Blob;
      /** Optional note attached to this specific revision. */
      message?: string;
    },
    source: HistorySource = HistorySources.SYSTEM,
  ): Promise<Awaited<ReturnType<typeof MajikSignature.signFile>>> {
    return this._withSigningKey(options?.accountId, "signFile", async (key) => {
      const signedResponse = await MajikSignature.signFile(file, key, {
        contentType: options?.contentType,
        timestamp: options?.timestamp,
        mimeType: options?.mimeType,
        expectedSigners: options?.expectedSigners,
        validUntil: options?.validUntil,
        priorSignedFile: options?.priorSignedFile,
        message: options?.message,
      });

      const signedBytes = new Uint8Array(
        await signedResponse.blob.arrayBuffer(),
      );

      this._recordHistory(key.fingerprint, {
        reference_id: signedResponse.signature.contentHash,
        historyType: HistoryTypes.SIGN,
        status: HistoryStatuses.SUCCESS,
        source,
        operation: {
          digest: signedResponse.signature.contentHash,
          detached: false,
          sealed: false,
          tsa: false,
        },
        signerCount: 1,
        data: signedBytes,
        identity: this._identityFromKey(key),
      }).catch((err) => console.warn(err));

      return signedResponse;
    });
  }

  /**
   * Sign a file with a detached signature envelope.
   *
   * @example
   *     const { blob: signedPdf } = await majik.signFileDetached(pdfBlob);
   *
   * @example — non-active account
   *     const { blob } = await majik.signFileDetached(wavBlob, { accountId: "acc_xyz" });
   * @param file - Input file or Blob-like value to sign, verify, inspect, or transform.
   * @param options - Optional operation-specific settings.
   * @param source - History source recorded for the operation.
   * @returns The result of the sign file detached operation (`Promise<Awaited<ReturnType<typeof MajikSignature.signFileDetached>>>`).
   */

  async signFileDetached(
    file: FileLike,
    options?: {
      contentType?: string;
      timestamp?: string;
      mimeType?: string;
      accountId?: string;
      expectedSigners?: ExpectedSigner[];
      validUntil?: string;
      existingEnvelope?: EnvelopeInput;
      tsa?: MajikTimestamp;
    },
    source: HistorySource = HistorySources.SYSTEM,
  ): Promise<Awaited<ReturnType<typeof MajikSignature.signFileDetached>>> {
    return this._withSigningKey(
      options?.accountId,
      "signFileDetached",
      async (key) => {
        const signedResponse = await MajikSignature.signFileDetached(
          file,
          key,
          {
            contentType: options?.contentType,
            timestamp: options?.timestamp,
            mimeType: options?.mimeType,
            expectedSigners: options?.expectedSigners,
            existingEnvelope: options?.existingEnvelope,
            tsa: options?.tsa,
            validUntil: options?.validUntil,
          },
        );

        const envelopeBytes = signedResponse.envelope.toMJKSIGBytes();

        this._recordHistory(key.fingerprint, {
          reference_id: signedResponse.signature.contentHash,
          historyType: HistoryTypes.SIGN,
          status: HistoryStatuses.SUCCESS,
          source,
          operation: {
            digest: signedResponse.signature.contentHash,
            detached: true,
            sealed: false,
            tsa: !!options?.tsa,
          },
          signerCount: 1,
          data: envelopeBytes,
          identity: this._identityFromKey(key),
        }).catch((err) => console.warn(err));

        return signedResponse;
      },
    );
  }

  /**
   * Sign multiple files with one account in a single unlock.
   * Per-file failures are returned in `error`, not thrown; unlock/key failures
   * (no account, no signing keys) still throw, as before.
   * @param files - Collection of files to process as a batch.
   * @param options - Optional operation-specific settings.
   * @param source - History source recorded for the operation.
   * @returns The result of the batch sign files operation (`Promise< Array<{ blob: Blob | null; signature: MajikSignature | null; serialized: string | null; handler: string | null; mimeType: string | null; error: Error | null; }> >`).
   */
  async batchSignFiles(
    files: Array<{
      file: Blob;
      contentType?: string;
      timestamp?: string;
      mimeType?: string;
      validUntil?: string;
    }>,
    options?: { accountId?: string },
    source: HistorySource = HistorySources.SYSTEM,
  ): Promise<
    Array<{
      blob: Blob | null;
      signature: MajikSignature | null;
      serialized: string | null;
      handler: string | null;
      mimeType: string | null;
      error: Error | null;
    }>
  > {
    return this._withSigningKey(options?.accountId, "batchSignFiles", (key) =>
      Promise.all(
        files.map(
          async ({ file, contentType, timestamp, mimeType, validUntil }) => {
            try {
              const result = await MajikSignature.signFile(file, key, {
                contentType,
                timestamp,
                mimeType,
                validUntil,
              });

              this._recordHistory(key.fingerprint, {
                reference_id: result.signature.contentHash,
                historyType: HistoryTypes.SIGN,
                status: HistoryStatuses.SUCCESS,
                source,
                operation: {
                  digest: result.signature.contentHash,
                  detached: false,
                  sealed: false,
                  tsa: false,
                },
                signerCount: 1,
              }).catch((err) => console.warn(err));

              return {
                blob: result.blob,
                signature: result.signature,
                serialized: result.signature.serialize(),
                handler: result.handler,
                mimeType: result.mimeType,
                error: null,
              };
            } catch (err) {
              this._emit("error", err, { context: "batchSignFiles" });
              return {
                blob: null,
                signature: null,
                serialized: null,
                handler: null,
                mimeType: null,
                error: err instanceof Error ? err : new Error(String(err)),
              };
            }
          },
        ),
      ),
    );
  }
  // ── Verification ──────────────────────────────────────────────────────────

  /**
   * Verify raw bytes or a string against a MajikSignature.
   *
   * > ⚠️ When no signer is provided, the extracted public keys are self-reported
   * > by whoever created the signature. Always cross-check `result.signerId`
   * > against a known contact fingerprint before trusting the result.
   *
   * @example — verify against a known contact
   *     const result = await majik.verifyContent(docBytes, sig, { contactId: "contact_abc" });
   *     if (result.valid) console.log("Authentic, signed by:", result.signerId);
   * @param content - Content to process, supplied as text or raw bytes.
   * @param signature - Signature value, supplied as a MajikSignature, JSON representation, or serialized string as supported by the method.
   * @param options - Optional operation-specific settings.
   * @param source - History source recorded for the operation.
   * @returns The result of the verify content operation (`Promise<VerificationResult>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async verifyContent(
    content: Uint8Array | string,
    signature: MajikSignature | MajikSignatureJSON,
    options?: {
      contactId?: string;
      publicKeyBase64?: string;
      key?: MajikKey;
      expectedSignerId?: string;
      now?: Date;
    },
    source: HistorySource = HistorySources.SYSTEM,
  ): Promise<VerificationResult> {
    try {
      const publicKeys = await this._resolveSignerPublicKeys(options);
      return this.verify(
        content,
        signature,
        publicKeys ?? undefined,
        source,
        options?.now,
      );
    } catch (err) {
      this._emit("error", err, { context: "verifyContent" });
      throw err;
    }
  }

  /**
   * Verify a file's embedded signature.
   *
   * @example — verify a signed PDF against a known contact
   *     const result = await majik.verifyFile(signedPdf, { contactId: "contact_abc" });
   *     if (result.valid) console.log("Verified:", result.signerId, result.timestamp);
   * @param file - Input file or Blob-like value to sign, verify, inspect, or transform.
   * @param options - Optional operation-specific settings.
   * @param source - History source recorded for the operation.
   * @returns The result of the verify file operation (`Promise<VerificationResult & { handler?: string; reason?: string }>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async verifyFile(
    file: FileLike,
    options?: {
      contactId?: string;
      publicKeyBase64?: string;
      key?: MajikKey;
      expectedSignerId?: string;
      mimeType?: string;
      now?: Date;
    },
    source: HistorySource = HistorySources.SYSTEM,
  ): Promise<VerificationResult & { handler?: string; reason?: string }> {
    try {
      const publicKeys = await this._resolveSignerPublicKeys(options);
      let result: VerificationResult & { handler?: string; reason?: string };

      if (publicKeys) {
        const results = await MajikSignature.verifyFile(file, publicKeys, {
          expectedSignerId: options?.expectedSignerId,
          mimeType: options?.mimeType,
          now: options?.now,
        });
        result = results[0];
      } else {
        const extracted = await MajikSignature.extractFrom(file, {
          mimeType: options?.mimeType,
        });
        if (!extracted.length) {
          result = {
            valid: false,
            signerId: "",
            contentHash: "",
            timestamp: new Date().toISOString(),
            reason: "No embedded signature found",
          };
        } else {
          // Honor expectedSignerId when resolving which embedded signature to
          // check — previously this always fell back to extracted[0], so every
          // iteration of a per-signer verify loop (verifySignersForFile) ended
          // up re-checking the SAME first signer instead of each one in turn.
          const targetSig = options?.expectedSignerId
            ? (extracted.find((s) => s.signerId === options.expectedSignerId) ??
              extracted[0])
            : extracted[0];

          const results = await MajikSignature.verifyFile(
            file,
            targetSig.extractPublicKeys(),
            {
              expectedSignerId: targetSig.signerId,
              mimeType: options?.mimeType,
              now: options?.now,
            },
          );
          result = results[0];
        }
      }

      if (result.contentHash) {
        const isSealed = await MajikSignature.isSealed(file);
        const signatures = await MajikSignature.extractFrom(file);
        const firstSigHasTSA = !!signatures[0]?.hasTSA;

        this._recordHistory(this.getActiveAccountKey()?.fingerprint, {
          reference_id: result.contentHash,
          historyType: HistoryTypes.VERIFY,
          status: result.valid
            ? HistoryStatuses.SUCCESS
            : HistoryStatuses.FAILED,
          source,
          operation: {
            digest: result.contentHash,
            detached: false,
            sealed: isSealed ?? false,
            tsa: firstSigHasTSA ?? false,
          },
          valid: result.valid,
        });
      }

      return result;
    } catch (err) {
      this._emit("error", err, { context: "verifyFile" });
      throw err;
    }
  }

  /**
   * Verify a file's detached signature.
   *
   * @example — verify a signed PDF's detached signature against a known contact
   *     const result = await majik.verifyFileDetached(signedPdf, envelope, { contactId: "contact_abc" });
   *     if (result.valid) console.log("Verified:", result.signerId, result.timestamp);
   * @param file - Input file or Blob-like value to sign, verify, inspect, or transform.
   * @param envelope - Detached envelope containing the signatures associated with the file.
   * @param options - Optional operation-specific settings.
   * @param source - History source recorded for the operation.
   * @returns The result of the verify file detached operation (`Promise<VerificationResult & { handler?: string; reason?: string }>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async verifyFileDetached(
    file: FileLike,
    envelope: EnvelopeInput,
    options?: {
      contactId?: string;
      publicKeyBase64?: string;
      key?: MajikKey;
      expectedSignerId?: string;
      mimeType?: string;
      now?: Date;
    },
    source: HistorySource = HistorySources.SYSTEM,
  ): Promise<VerificationResult & { handler?: string; reason?: string }> {
    try {
      const publicKeys = await this._resolveSignerPublicKeys(options);
      let result: VerificationResult & { handler?: string; reason?: string };

      if (publicKeys) {
        const results = await MajikSignature.verifyFileDetached(
          file,
          envelope,
          publicKeys,
          {
            expectedSignerId: options?.expectedSignerId,
            mimeType: options?.mimeType,
          },
        );
        result = results[0];
      } else {
        const resolvedEnvelope = await MajikSignatureEnvelope.from(envelope);
        const firstSigJson = resolvedEnvelope.signatures[0];

        if (!firstSigJson) {
          result = {
            valid: false,
            signerId: "",
            contentHash: "",
            timestamp: new Date().toISOString(),
            reason: "Envelope contains no signatures",
          };
        } else {
          const targetSig = options?.expectedSignerId
            ? (resolvedEnvelope.signatures.find(
                (s) => s.signerId === options.expectedSignerId,
              ) ?? resolvedEnvelope.signatures[0])
            : resolvedEnvelope.signatures[0];

          const parsedTargetSig = MajikSignature.fromJSON(targetSig);

          const results = await MajikSignature.verifyFileDetached(
            file,
            resolvedEnvelope,
            parsedTargetSig.extractPublicKeys(),
            {
              expectedSignerId: parsedTargetSig.signerId,
              mimeType: options?.mimeType,
              now: options?.now,
            },
          );
          result = results[0];
        }
      }

      if (result.contentHash) {
        this._recordHistory(this.getActiveAccountKey()?.fingerprint, {
          reference_id: result.contentHash,
          historyType: HistoryTypes.VERIFY,
          status: result.valid
            ? HistoryStatuses.SUCCESS
            : HistoryStatuses.FAILED,
          source,
          operation: {
            digest: result.contentHash,
            detached: true,
            sealed: false,
            tsa: false,
          },
          valid: result.valid,
        });
      }

      return result;
    } catch (err) {
      this._emit("error", err, { context: "verifyFileDetached" });
      throw err;
    }
  }

  /**
   * Verifies the revision/signature chain embedded in a signed file.
   * @param file - Input file or Blob-like value to sign, verify, inspect, or transform.
   * @param options - Optional operation-specific settings.
   * @returns The result of the verify file chain operation (`Promise<ReturnType<typeof MajikSignature.verifyFileChain>>`).
   */
  async verifyFileChain(
    file: FileLike,
    options?: { mimeType?: string; now?: Date },
  ): Promise<ReturnType<typeof MajikSignature.verifyFileChain>> {
    return MajikSignature.verifyFileChain(file, options);
  }

  /**
   * Verify a full revision chain by matching a set of supplied prior-version
   * files against the loaded file's fileVersions history. Unlike verifyFile()
   * (which only checks the CURRENT bytes against the latest signer),
   * this re-hashes every supplied revision and confirms each one lines up
   * with its recorded chain entry AND its recorded signature.
   *
   * @example
   *     const result = await majik.verifyFileRevisions(currentFile, [v1File, v2File]);
   *     if (!result.allValid) console.warn(result.results.filter(r => r.status !== "verified"));
   * @param finalFile - Value used by the verify file revisions operation.
   * @param revisions - Value used by the verify file revisions operation.
   * @param options - Optional operation-specific settings.
   * @returns The result of the verify file revisions operation (`Promise<ReturnType<typeof MajikSignature.verifyFileRevisions>>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async verifyFileRevisions(
    finalFile: FileLike,
    revisions: FileLike[],
    options?: {
      mimeType?: string;
      now?: Date;
      resolvePublicKeys?: (
        signerId: string,
      ) => MajikSignerPublicKeys | Promise<MajikSignerPublicKeys>;
    },
  ): Promise<ReturnType<typeof MajikSignature.verifyFileRevisions>> {
    try {
      return await MajikSignature.verifyFileRevisions(
        finalFile,
        revisions,
        options,
      );
    } catch (err) {
      this._emit("error", err, { context: "verifyFileRevisions" });
      throw err;
    }
  }

  // ── Verify ALL signatures (embedded) ──────────────────────────────────────

  /**
   * Verify every embedded signature in a file, each checked against its own
   * self-reported public keys.
   *
   * ⚠️ Self-reported: for each result, cross-check `signerId` against your
   * contact directory (see `resolveSignerLabel`) before trusting authenticity.
   * A tampered envelope can carry a signature whose self-reported keys pass
   * verification but don't belong to who they claim to be.
   * @param file - Input file or Blob-like value to sign, verify, inspect, or transform.
   * @param options - Optional operation-specific settings.
   * @param source - History source recorded for the operation.
   * @returns The result of the verify file all signatures operation (`Promise<VerifyResult[]>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async verifyFileAllSignatures(
    file: FileLike,
    options?: { mimeType?: string; now?: Date },
    source: HistorySource = HistorySources.SYSTEM,
  ): Promise<VerifyResult[]> {
    try {
      const signatures = await this.extractSignature(file, options);
      if (!signatures.length) {
        return [
          {
            valid: false,
            signerId: "",
            contentHash: "",
            timestamp: new Date().toISOString(),
            reason: "No embedded signature found",
          } as VerifyResult,
        ];
      }

      const strippedBlob = await this.stripSignature(file, options);
      const contentBytes = new Uint8Array(await strippedBlob.arrayBuffer());
      const activeFingerprint = this.getActiveAccountKey()?.fingerprint;

      return signatures.map((sig) => {
        try {
          const result = MajikSignature.verify(
            contentBytes,
            sig,
            sig.extractPublicKeys(),
            options?.now,
          );

          this._recordHistory(activeFingerprint, {
            reference_id: result.contentHash!,
            historyType: HistoryTypes.VERIFY,
            status: result.valid
              ? HistoryStatuses.SUCCESS
              : HistoryStatuses.FAILED,
            source,
            operation: {
              digest: result.contentHash!,
              detached: false,
              sealed: false,
              tsa: false,
            },
            valid: result.valid,
          });

          return {
            ...result,
            signerLabel: result.signerId
              ? this.resolveSignerLabel(result.signerId)
              : undefined,
          };
        } catch (err) {
          return {
            valid: false,
            signerId: sig.signerId,
            contentHash: sig.contentHash,
            timestamp: sig.timestamp,
            reason: err instanceof Error ? err.message : String(err),
          } as VerifyResult;
        }
      });
    } catch (err) {
      this._emit("error", err, { context: "verifyFileAllSignatures" });
      throw err;
    }
  }

  // ── Verify ALL signatures (detached) ──────────────────────────────────────

  /**
   * Verify every signature inside a detached envelope against the stripped
   * content, each checked against its own self-reported public keys.
   * @param file - Input file or Blob-like value to sign, verify, inspect, or transform.
   * @param envelope - Detached envelope containing the signatures associated with the file.
   * @param source - History source recorded for the operation.
   * @param now - Optional point-in-time used when evaluating temporal validity; defaults to the current time when omitted.
   * @returns The result of the verify file detached all signatures operation (`Promise<VerifyResult[]>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async verifyFileDetachedAllSignatures(
    file: FileLike,
    envelope: EnvelopeInput,
    source: HistorySource = HistorySources.SYSTEM,
    now?: Date,
  ): Promise<VerifyResult[]> {
    try {
      const resolvedEnvelope = await MajikSignatureEnvelope.from(envelope);

      const integrity = resolvedEnvelope.verifyAllowlistIntegrity();
      if (!integrity.valid) {
        return [
          {
            valid: false,
            signerId: "",
            contentHash: "",
            timestamp: new Date().toISOString(),
            reason: integrity.reason,
          } as VerifyResult,
        ];
      }

      const signatures = resolvedEnvelope.signatures;
      if (!signatures.length) {
        return [
          {
            valid: false,
            signerId: "",
            contentHash: "",
            timestamp: new Date().toISOString(),
            reason: "Envelope contains no signatures",
          } as VerifyResult,
        ];
      }

      const contentBytes = await normalizeToBytes(file);

      const activeFingerprint = this.getActiveAccountKey()?.fingerprint;

      return signatures.map((sigJson) => {
        try {
          const sig = MajikSignature.fromJSON(sigJson);
          const result = MajikSignature.verify(
            contentBytes,
            sig,
            sig.extractPublicKeys(),
            now,
          );

          this._recordHistory(activeFingerprint, {
            reference_id: result.contentHash!,
            historyType: HistoryTypes.VERIFY,
            status: result.valid
              ? HistoryStatuses.SUCCESS
              : HistoryStatuses.FAILED,
            source,
            operation: {
              digest: result.contentHash!,
              detached: true,
              sealed: false,
              tsa: false,
            },
            valid: result.valid,
          });

          return {
            ...result,
            signerLabel: result.signerId
              ? this.resolveSignerLabel(result.signerId)
              : undefined,
          };
        } catch (err) {
          return {
            valid: false,
            signerId: sigJson.signerId,
            contentHash: sigJson.contentHash,
            timestamp: sigJson.timestamp,
            reason: err instanceof Error ? err.message : String(err),
          } as VerifyResult;
        }
      });
    } catch (err) {
      this._emit("error", err, { context: "verifyFileDetachedAllSignatures" });
      throw err;
    }
  }

  /**
   * Verify multiple files' embedded signatures against the same signer in
   * one call.
   *
   * @example
   *     const results = await majik.batchVerifyFiles(
   *       [pdfBlob, wavBlob, mp4Blob],
   *       { contactId: "contact_abc" },
   *     );
   *     const allValid = results.every(r => r.valid);
   * @param files - Collection of files to process as a batch.
   * @param options - Optional operation-specific settings.
   * @param source - History source recorded for the operation.
   * @returns The result of the batch verify files operation (`Promise< Array< VerificationResult & { handler: string | undefined; mimeType: string | undefined; error: Error | null; } > >`).
   */
  async batchVerifyFiles(
    files: Array<
      Blob | { file: Blob; mimeType?: string; expectedSignerId?: string }
    >,
    options?: {
      contactId?: string;
      publicKeyBase64?: string;
      key?: MajikKey;
      expectedSignerId?: string;
      now?: Date;
    },
    source: HistorySource = HistorySources.SYSTEM,
  ): Promise<
    Array<
      VerificationResult & {
        handler: string | undefined;
        mimeType: string | undefined;
        error: Error | null;
      }
    >
  > {
    const publicKeys = await this._resolveSignerPublicKeys(options).catch(
      () => null,
    );
    const activeFingerprint = this.getActiveAccountKey()?.fingerprint;

    return Promise.all(
      files.map(async (entry) => {
        const { file, mimeType, expectedSignerId } =
          entry instanceof Blob
            ? {
                file: entry,
                mimeType: undefined,
                expectedSignerId: options?.expectedSignerId,
              }
            : {
                ...entry,
                expectedSignerId:
                  entry.expectedSignerId ?? options?.expectedSignerId,
              };

        try {
          let result: VerificationResult;

          if (publicKeys) {
            const results = await MajikSignature.verifyFile(file, publicKeys, {
              mimeType,
              expectedSignerId,
              now: options?.now,
            });
            result = results[0];
          } else {
            const extracted = await MajikSignature.extractFrom(file, {
              mimeType,
            });
            if (!extracted.length) {
              return {
                valid: false,
                signerId: undefined,
                contentHash: undefined,
                timestamp: new Date().toISOString(),
                reason: "No embedded signature found",
                handler: undefined,
                mimeType,
                error: null,
              };
            }

            const targetSig = options?.expectedSignerId
              ? (extracted.find(
                  (s) => s.signerId === options.expectedSignerId,
                ) ?? extracted[0])
              : extracted[0];

            const results = await MajikSignature.verifyFile(
              file,
              targetSig.extractPublicKeys(),
              {
                expectedSignerId: targetSig.signerId,
                mimeType: mimeType,
              },
            );
            result = results[0];
          }

          if (result.contentHash) {
            this._recordHistory(activeFingerprint, {
              reference_id: result.contentHash,
              historyType: HistoryTypes.VERIFY,
              status: result.valid
                ? HistoryStatuses.SUCCESS
                : HistoryStatuses.FAILED,
              source,
              operation: {
                digest: result.contentHash,
                detached: false,
                sealed: false,
                tsa: false,
              },
              valid: result.valid,
            });
          }

          return { ...result, handler: result.handler, mimeType, error: null };
        } catch (err) {
          this._emit("error", err, { context: "batchVerifyFiles" });
          return {
            valid: false,
            signerId: undefined,
            contentHash: undefined,
            timestamp: new Date().toISOString(),
            handler: undefined,
            mimeType,
            error: err instanceof Error ? err : new Error(String(err)),
          };
        }
      }),
    );
  }
  // ── Signature Utilities ───────────────────────────────────────────────────

  /**
   * Extract the embedded MajikSignature from a file.
   * Does not verify — use verifyFile() to verify.
   * @param file - Input file or Blob-like value to sign, verify, inspect, or transform.
   * @param options - Optional operation-specific settings.
   * @returns The result of the extract signature operation (`Promise<MajikSignature[]>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async extractSignature(
    file: FileLike,
    options?: { mimeType?: string },
  ): Promise<MajikSignature[]> {
    try {
      return MajikSignature.extractFrom(file, options);
    } catch (err) {
      this._emit("error", err, { context: "extractSignature" });
      throw err;
    }
  }

  /**
   * Return a clean copy of the file with any embedded signature removed.
   * @param file - Input file or Blob-like value to sign, verify, inspect, or transform.
   * @param options - Optional operation-specific settings.
   * @returns The result of the strip signature operation (`Promise<Blob>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async stripSignature(
    file: FileLike,
    options?: { mimeType?: string },
  ): Promise<Blob> {
    try {
      return await MajikSignature.stripFrom(file, options);
    } catch (err) {
      this._emit("error", err, { context: "stripSignature" });
      throw err;
    }
  }

  /**
   * Check whether a file contains an embedded MajikSignature.
   * @param file - Input file or Blob-like value to sign, verify, inspect, or transform.
   * @param options - Optional operation-specific settings.
   * @returns The result of the is file signed operation (`Promise<boolean>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async isFileSigned(
    file: FileLike,
    options?: { mimeType?: string },
  ): Promise<boolean> {
    try {
      return MajikSignature.isSigned(file, options);
    } catch (err) {
      this._emit("error", err, { context: "isFileSigned" });
      throw err;
    }
  }

  /**
   * Get the public keys for the active account, ready for use with
   * MajikSignature.verify() or for sharing with another party.
   *
   * @example
   *     const myKeys = await majik.getSigningPublicKeys();
   * @param accountId - Account identifier to use. When omitted, the currently active account is used where supported.
   * @returns The result of the get signing public keys operation (`Promise<MajikSignerPublicKeys>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async getSigningPublicKeys(
    accountId?: string,
  ): Promise<MajikSignerPublicKeys> {
    const id = accountId ?? this.getActiveAccount()?.id;
    if (!id)
      throw new Error("No active account — call setActiveAccount() first");

    const key = this._keys.get(id);
    if (!key) throw new Error(`Account not found in keystore: "${id}"`);
    if (!key.hasSigningKeys) {
      throw new Error(
        `Account "${id}" has no signing keys. ` +
          `Re-import via importAccountFromMnemonicBackup() to enable signing.`,
      );
    }

    return MajikSignature.publicKeysFromMajikKey(key);
  }

  /**
   * Re-sign a file blob — strips any existing embedded signature, signs
   * with the active (or specified) account, and returns the newly signed blob.
   *
   * @example
   *     const { blob } = await majik.resignFile(oldSignedPdf);
   *     await r2.put(key, await blob.arrayBuffer());
   * @param file - Input file or Blob-like value to sign, verify, inspect, or transform.
   * @param options - Optional operation-specific settings.
   * @returns The result of the resign file operation (`Promise<ReturnType<typeof MajikSignature.signFile>>`).
   */
  async resignFile(
    file: FileLike,
    options?: {
      contentType?: string;
      timestamp?: string;
      mimeType?: string;
      accountId?: string;
      validUntil?: string;
    },
  ): Promise<ReturnType<typeof MajikSignature.signFile>> {
    // signFile already strips before signing — resignFile is a named alias
    // that makes the caller's intent explicit at the call-site.
    return this.signFile(file, options);
  }

  /**
   * Extract metadata from a file's embedded signature without verifying it.
   *
   * @example
   *     const info = await majik.getFileSignatureInfo(pdfBlob);
   *     if (info) {
   *       const contact = majik.getContactByID(info.signerId);
   *       console.log(`Signed by ${contact?.meta?.label ?? info.signerId}`);
   *     }
   * @param file - Input file or Blob-like value to sign, verify, inspect, or transform.
   * @param options - Optional operation-specific settings.
   * @returns The result of the get file signature info operation (`Promise<MajikSignature[]>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async getFileSignatureInfo(
    file: FileLike,
    options?: { mimeType?: string },
  ): Promise<MajikSignature[]> {
    try {
      return MajikSignature.extractFrom(file, options);
    } catch (err) {
      this._emit("error", err, { context: "getFileSignatureInfo" });
      throw err;
    }
  }

  // ── Multi-sig & Allowlist ─────────────────────────────────────────────────

  /**
   * Build an ExpectedSigner entry from a MajikKey.
   *
   * @example
   *     const { blob } = await majik.signFile(file, {
   *       expectedSigners: [
   *         MajikSignatureClient.expectedSignerFromKey(aliceKey),
   *         MajikSignatureClient.expectedSignerFromKey(bobKey),
   *       ],
   *     });
   * @param key - MajikKey used as the cryptographic identity for the operation.
   * @returns The result of the expected signer from key operation (`ExpectedSigner`).
   */
  static expectedSignerFromKey(key: MajikKey): ExpectedSigner {
    return MajikSignature.expectedSignerFromKey(key);
  }

  /**
   * Get the allowlist from a file without verifying any signatures.
   * Returns null for open-signing files or unsigned files.
   * @param file - Input file or Blob-like value to sign, verify, inspect, or transform.
   * @param options - Optional operation-specific settings.
   * @returns The result of the get allowlist operation (`Promise<ExpectedSigner[] | null>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async getAllowlist(
    file: FileLike,
    options?: { mimeType?: string },
  ): Promise<ExpectedSigner[] | null> {
    try {
      return MajikSignature.getAllowlist(file, options);
    } catch (err) {
      this._emit("error", err, { context: "getAllowlist" });
      throw err;
    }
  }

  /**
   * Check whether a MajikKey is permitted to add a signature to this file.
   * @param file - Input file or Blob-like value to sign, verify, inspect, or transform.
   * @param key - MajikKey used as the cryptographic identity for the operation.
   * @param options - Optional operation-specific settings.
   * @returns The result of the can sign operation (`Promise<ReturnType<typeof MajikSignature.canSign>>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async canSign(
    file: FileLike,
    key: MajikKey,
    options?: { mimeType?: string },
  ): Promise<ReturnType<typeof MajikSignature.canSign>> {
    try {
      return MajikSignature.canSign(file, key, options);
    } catch (err) {
      this._emit("error", err, { context: "canSign" });
      throw err;
    }
  }

  /**
   * Returns true when the file has a restricted multi-sig envelope.
   * @param file - Input file or Blob-like value to sign, verify, inspect, or transform.
   * @param options - Optional operation-specific settings.
   * @returns The result of the is multi sig operation (`Promise<boolean>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async isMultiSig(
    file: FileLike,
    options?: { mimeType?: string },
  ): Promise<boolean> {
    try {
      return MajikSignature.isMultiSig(file, options);
    } catch (err) {
      this._emit("error", err, { context: "isMultiSig" });
      throw err;
    }
  }

  /**
   * Core signatories method — returns all, signed, and pending arrays.
   * @param file - Input file or Blob-like value to sign, verify, inspect, or transform.
   * @param options - Optional operation-specific settings.
   * @param filter - Optional signatory filter used to select a subset of envelope participants.
   * @returns The result of the get signatories operation (`Promise<SignatoriesResult | null>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async getSignatories(
    file: FileLike,
    options?: { mimeType?: string },
    filter?: SignatoriesFilter,
  ): Promise<SignatoriesResult | null> {
    try {
      return MajikSignature.getSignatories(file, options, filter);
    } catch (err) {
      this._emit("error", err, { context: "getSignatories" });
      throw err;
    }
  }

  /**
   * Returns signatories who have already completed their signatures.
   * @param file - Input file or Blob-like value to sign, verify, inspect, or transform.
   * @param options - Optional operation-specific settings.
   * @returns The result of the get signed signatories operation (`Promise<SignatoriesResult | null>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async getSignedSignatories(
    file: FileLike,
    options?: { mimeType?: string },
  ): Promise<SignatoriesResult | null> {
    try {
      return MajikSignature.getSignedSignatories(file, options);
    } catch (err) {
      this._emit("error", err, { context: "getSignedSignatories" });
      throw err;
    }
  }

  /**
   * Returns signatories who are still pending in a multi-signature workflow.
   * @param file - Input file or Blob-like value to sign, verify, inspect, or transform.
   * @param options - Optional operation-specific settings.
   * @returns The result of the get pending signatories operation (`Promise<SignatoriesResult | null>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async getPendingSignatories(
    file: FileLike,
    options?: { mimeType?: string },
  ): Promise<SignatoriesResult | null> {
    try {
      return MajikSignature.getPendingSignatories(file, options);
    } catch (err) {
      this._emit("error", err, { context: "getPendingSignatories" });
      throw err;
    }
  }

  /**
   * Returns all known signatories in the file envelope.
   * @param file - Input file or Blob-like value to sign, verify, inspect, or transform.
   * @param options - Optional operation-specific settings.
   * @returns The result of the get all signatories operation (`Promise<SignatoriesResult | null>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async getAllSignatories(
    file: FileLike,
    options?: { mimeType?: string },
  ): Promise<SignatoriesResult | null> {
    try {
      return MajikSignature.getAllSignatories(file, options);
    } catch (err) {
      this._emit("error", err, { context: "getAllSignatories" });
      throw err;
    }
  }

  /**
   * Returns the issuer — the signer who established the allowlist and
   * controls sealing. Returns null for open-signing or unsigned files.
   * @param file - Input file or Blob-like value to sign, verify, inspect, or transform.
   * @param options - Optional operation-specific settings.
   * @returns The result of the get issuer operation (`Promise<SignatoryInfo | null>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async getIssuer(
    file: FileLike,
    options?: { mimeType?: string },
  ): Promise<SignatoryInfo | null> {
    try {
      return MajikSignature.getIssuer(file, options);
    } catch (err) {
      this._emit("error", err, { context: "getIssuer" });
      throw err;
    }
  }

  /**
   * Return a complete summary of the envelope state in one file read.
   * @param file - Input file or Blob-like value to sign, verify, inspect, or transform.
   * @param options - Optional operation-specific settings.
   * @returns The result of the get envelope info operation (`Promise<EnvelopeInfo | null>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async getEnvelopeInfo(
    file: FileLike,
    options?: { mimeType?: string },
  ): Promise<EnvelopeInfo | null> {
    try {
      return MajikSignature.getEnvelopeInfo(file, options);
    } catch (err) {
      this._emit("error", err, { context: "getEnvelopeInfo" });
      throw err;
    }
  }

  // ── Seal ──────────────────────────────────────────────────────────────────

  /**
   * Seal a restricted multi-sig file, preventing any further signatures.
   *
   * @example
   *     const { blob, sealInfo } = await majik.seal(signedFile);
   *     console.log("Sealed at", sealInfo.sealTimestamp);
   * @param file - Input file or Blob-like value to sign, verify, inspect, or transform.
   * @param options - Optional operation-specific settings.
   * @param source - History source recorded for the operation.
   * @returns The result of the seal operation (`Promise<Awaited<ReturnType<typeof MajikSignature.seal>>>`).
   */

  async seal(
    file: FileLike,
    options?: { mimeType?: string; timestamp?: string; accountId?: string },
    source: HistorySource = HistorySources.SYSTEM,
  ): Promise<Awaited<ReturnType<typeof MajikSignature.seal>>> {
    return this._withSigningKey(options?.accountId, "seal", async (key) => {
      const sealResult = await MajikSignature.seal(file, key, {
        mimeType: options?.mimeType,
        timestamp: options?.timestamp,
      });

      const sealedBytes = new Uint8Array(await sealResult.blob.arrayBuffer());

      this._recordHistory(key.fingerprint, {
        reference_id: sealResult.sealInfo.sealHash,
        historyType: HistoryTypes.SEAL,
        status: HistoryStatuses.SUCCESS,
        source,
        operation: {
          digest: sealResult.sealInfo.sealHash,
          detached: false,
          sealed: true,
          tsa: false,
        },
        data: sealedBytes,
        identity: this._identityFromKey(key),
      }).catch((err) => console.warn(err));

      return sealResult;
    });
  }

  /**
   * Verify the seal hash against the current signatories and seal timestamp.
   * @param file - Input file or Blob-like value to sign, verify, inspect, or transform.
   * @param options - Optional operation-specific settings.
   * @returns The result of the verify seal operation (`Promise<SealVerificationResult>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async verifySeal(
    file: FileLike,
    options?: { mimeType?: string },
  ): Promise<SealVerificationResult> {
    try {
      return MajikSignature.verifySeal(file, options);
    } catch (err) {
      this._emit("error", err, { context: "verifySeal" });
      throw err;
    }
  }

  /**
   * Get seal metadata without verifying.
   * @param file - Input file or Blob-like value to sign, verify, inspect, or transform.
   * @param options - Optional operation-specific settings.
   * @returns The result of the get seal info operation (`Promise<SealInfo | null>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async getSealInfo(
    file: FileLike,
    options?: { mimeType?: string },
  ): Promise<SealInfo | null> {
    try {
      return MajikSignature.getSealInfo(file, options);
    } catch (err) {
      this._emit("error", err, { context: "getSealInfo" });
      throw err;
    }
  }

  /**
   * Returns true if the file has a sealed envelope (structural check, no crypto).
   * @param file - Input file or Blob-like value to sign, verify, inspect, or transform.
   * @param options - Optional operation-specific settings.
   * @returns The result of the is sealed operation (`Promise<boolean>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async isSealed(
    file: FileLike,
    options?: { mimeType?: string },
  ): Promise<boolean> {
    try {
      return MajikSignature.isSealed(file, options);
    } catch (err) {
      this._emit("error", err, { context: "isSealed" });
      throw err;
    }
  }

  // ── Stamps (encrypted reusable assets — signatures, audio, video, text) ────

  /**
   * Creates and persists an encrypted reusable signature stamp asset.
   * @param data - Raw asset bytes to store or stamp.
   * @param kind - Optional asset or stamp kind used to filter or classify the operation.
   * @param name - Human-readable name for the new or existing asset.
   * @param options - Optional operation-specific settings.
   * @returns The result of the create stamp operation (`Promise<MajikSignatureStamp>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async createStamp(
    data: Uint8Array | ArrayBuffer,
    kind: StampAssetKind,
    name: string,
    options?: { mimeType?: string; accountId?: string },
  ): Promise<MajikSignatureStamp> {
    const id = options?.accountId ?? this.getActiveAccount()?.id;
    if (!id)
      throw new Error("No active account — call setActiveAccount() first");

    try {
      await this._keys.ensureUnlocked(id);

      const identity = this._resolveMajikFileIdentity(id);
      const stamp = await this._stamps.create({
        data,
        identity,
        kind,
        name,
        mimeType: options?.mimeType,
      });

      this._recordActivity(identity.fingerprint, {
        reference_id: stamp.id,
        action: AuditActions.STAMP_CREATED, // ⚠️ verify member exists
        metadata: { kind, name },
      });

      this._emit("new-stamp", stamp);
      return stamp;
    } catch (err) {
      this._emit("error", err, { context: "createStamp" });
      throw err;
    }
  }

  /**
   * Lists locally stored signature stamps, optionally filtered by asset kind.
   * @param kind - Optional asset or stamp kind used to filter or classify the operation.
   * @returns The result of the list stamps operation (`MajikSignatureStamp[]`).
   */
  listStamps(kind?: StampAssetKind): MajikSignatureStamp[] {
    return kind ? this._stamps.listByKind(kind) : this._stamps.list();
  }

  /**
   * Hydrates stamp assets belonging to the currently active account.
   * @returns Completes when the operation has finished.
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async hydrateStampsForActiveAccount(): Promise<void> {
    const id = this.getActiveAccount()?.id;
    if (!id)
      throw new Error("No active account — call setActiveAccount() first");
    const key = this._keys.get(id);
    if (!key) throw new Error(`Account not found in keystore: "${id}"`);
    if (key.isLocked) {
      throw new Error(
        `Account "${id}" is locked. Call unlockAccount() before hydrating stamps.`,
      );
    }
    await this._stamps.hydrateForFingerprint(key.fingerprint, key);
  }

  /**
   * Locks in-memory stamp material so encrypted stamp content is no longer available for direct use.
   * @returns Completes when the operation has finished.
   */
  lockStamps(): void {
    this._stamps.lockAll();
  }

  /**
   * Returns decrypted stamp bytes currently available in memory, when present.
   * @param id - Unique identifier of the target entity.
   * @returns The result of the get decrypted stamp bytes operation (`Uint8Array | undefined`).
   */
  getDecryptedStampBytes(id: string): Uint8Array | undefined {
    return this._stamps.get(id)?.decryptedBytes;
  }

  /**
   * Lists stamps associated with the currently active account.
   * @param kind - Optional asset or stamp kind used to filter or classify the operation.
   * @returns The result of the list stamps for active account operation (`MajikSignatureStamp[]`).
   */
  listStampsForActiveAccount(kind?: StampAssetKind): MajikSignatureStamp[] {
    const key = this.getActiveAccountKey();
    if (!key) return [];
    const all = kind ? this._stamps.listByKind(kind) : this._stamps.list();
    return all.filter((s) => s.fingerprint === key.fingerprint);
  }

  /**
   * Returns a persisted stamp by identifier.
   * @param id - Unique identifier of the target entity.
   * @returns The result of the get stamp operation (`Promise<MajikSignatureStamp | null>`).
   */
  async getStamp(id: string): Promise<MajikSignatureStamp | null> {
    return this._stamps.load(id);
  }

  /**
   * Decrypts the content of a stored stamp using the specified or active account.
   * @param id - Unique identifier of the target entity.
   * @param accountId - Account identifier to use. When omitted, the currently active account is used where supported.
   * @returns The result of the decrypt stamp content operation (`Promise<Uint8Array>`).
   */
  async decryptStampContent(
    id: string,
    accountId?: string,
  ): Promise<Uint8Array> {
    const identity = this._resolveMajikFileIdentity(accountId);
    return this._stamps.decryptContent(id, identity);
  }

  /**
   * Renames an existing stamp.
   * @param id - Unique identifier of the target entity.
   * @param newName - Replacement human-readable name for the asset.
   * @returns The result of the rename stamp operation (`Promise<MajikSignatureStamp>`).
   */
  async renameStamp(id: string, newName: string): Promise<MajikSignatureStamp> {
    return this._stamps.rename(id, newName);
  }

  /**
   * Replaces the encrypted payload of an existing stamp.
   * @param id - Unique identifier of the target entity.
   * @param data - Raw asset bytes to store or stamp.
   * @param options - Optional operation-specific settings.
   * @returns The result of the replace stamp content operation (`Promise<MajikSignatureStamp>`).
   */
  async replaceStampContent(
    id: string,
    data: Uint8Array | ArrayBuffer,
    options?: { mimeType?: string; accountId?: string },
  ): Promise<MajikSignatureStamp> {
    const identity = this._resolveMajikFileIdentity(options?.accountId);
    const raw = data instanceof Uint8Array ? data : new Uint8Array(data);
    
    return this._stamps.replaceContent(id, raw, identity, options?.mimeType);
  }

  /**
   * Removes a persisted stamp and reports whether it existed.
   * @param id - Unique identifier of the target entity.
   * @returns The result of the remove stamp operation (`Promise<boolean>`).
   */
  async removeStamp(id: string): Promise<boolean> {
    const existed = await this._stamps.has(id);
    if (!existed) return false;
    await this._stamps.delete(id);

    this._recordActivity(this.getActiveAccountKey()?.fingerprint, {
      reference_id: id,
      action: AuditActions.STAMP_DELETED, // ⚠️
    });

    this._emit("removed-stamp", id);
    return true;
  }

  // ── STAMP (compression-resistant image signing) ───────────────────────────

  /**
   * Creates a signed/stamped image using the supplied key.
   * @param image - Value used by the stamp image operation.
   * @param key - MajikKey used as the cryptographic identity for the operation.
   * @param options - Optional operation-specific settings.
   * @returns The result of the stamp image operation (`Promise<{ blob: Blob; stub: ImageSignatureStub; fullEnvelope: MajikSignatureJSON; }>`).
   */
  static async stampImage(
    image: Blob,
    key: MajikKey,
    options?: ImageSignOptions,
  ): Promise<{
    blob: Blob;
    stub: ImageSignatureStub;
    fullEnvelope: MajikSignatureJSON;
  }> {
    return MajikSignature.stampImage(image, key, options);
  }

  /**
   * Verifies an image stamp and returns the detected signature information.
   * @param image - Value used by the verify stamp operation.
   * @param options - Optional operation-specific settings.
   * @returns The result of the verify stamp operation (`Promise<ImageVerificationResult>`).
   */
  static async verifyStamp(
    image: Blob,
    options?: { hammingThreshold?: number },
  ): Promise<ImageVerificationResult> {
    return MajikSignature.verifyStamp(image, options);
  }

  /**
   * Inspects an image for supported stamp markers without requiring full verification.
   * @param image - Value used by the inspect stamp operation.
   * @returns The result of the inspect stamp operation (`Promise<{ hasPixelRow: boolean; hasDct: boolean; pixelRowMeta?: { signerId: string; timestamp: string }; dctMeta?: { signerId: string; timestamp: string; pHash: string }; }>`).
   */
  static async inspectStamp(image: Blob): Promise<{
    hasPixelRow: boolean;
    hasDct: boolean;
    pixelRowMeta?: { signerId: string; timestamp: string };
    dctMeta?: { signerId: string; timestamp: string; pHash: string };
  }> {
    return MajikSignature.inspectStamp(image);
  }

  /**
   * Checks whether an image contains a recognizable stamp marker.
   * @param image - Value used by the is stamped operation.
   * @returns The result of the is stamped operation (`Promise<boolean>`).
   */
  static async isStamped(image: Blob): Promise<boolean> {
    return MajikSignature.isStamped(image);
  }

  /**
   * Turn whatever the UI has (own accounts, directory contacts, raw
   * ExpectedSigner objects) into ExpectedSigner[]. Position is preserved, so the
   * output is usable both as an allowlist (signFile options.expectedSigners) and
   * as an expected ORDER (verifyFileOrder).
   *
   * Contacts resolve to THEIR OWN stored keys, never anything from an envelope.
   * @param refs - Signer references supplied as keys, expected signer descriptors, or contact identifiers.
   * @returns The result of the build expected signers operation (`ExpectedSigner[]`).
   */
  buildExpectedSigners(refs: readonly SignerRef[]): ExpectedSigner[] {
    return refs.map((ref) => {
      if ("contactId" in ref)
        return this._contactToExpectedSigner(ref.contactId);
      if (typeof (ref as ExpectedSigner).edPublicKey === "string") {
        return ref as ExpectedSigner;
      }
      return MajikSignature.expectedSignerFromKey(ref as MajikKey);
    });
  }

  /**
   * Converts a contact identifier into an ExpectedSigner descriptor.
   * @param contactId - Contact identifier used to resolve and trust a signer.
   * @returns The result of the contact to expected signer operation (`ExpectedSigner`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  private _contactToExpectedSigner(contactId: string): ExpectedSigner {
    // Own accounts: contact id === key id, keys live in the keystore
    const own = this._keys.get(contactId);
    if (own?.hasSigningKeys) return MajikSignature.expectedSignerFromKey(own);

    const contact = this._contacts.getContact(contactId);
    if (!contact) throw new Error(`Contact not found: "${contactId}"`);
    if (!contact.edPublicKeyBase64 || !contact.mlDsaPublicKeyBase64) {
      throw new Error(
        `Contact "${contactId}" has no signing public keys. ` +
          `They may need to share an updated contact card.`,
      );
    }
    return {
      signerId: contact.fingerprint,
      edPublicKey: contact.edPublicKeyBase64,
      mlDsaPublicKey: contact.mlDsaPublicKeyBase64,
    };
  }

  // ══════════════════════════════════════════════════════════════════════════
  // ── MJKSMAP (batch detached signing / verification) ──────────────────────
  // ══════════════════════════════════════════════════════════════════════════

  /**
   * Reads and parses an MJKS map from a blob or byte representation.
   * @param input - Serialized input to parse or inspect.
   * @returns The result of the read mjks map operation (`Promise<MajikSignatureMap>`).
   */
  async readMjksMap(input: MjksMapInput): Promise<MajikSignatureMap> {
    return MajikSignatureMap.from(input);
  }

  /**
   * Checks whether the supplied bytes represent an MJKS map.
   * @param input - Serialized input to parse or inspect.
   * @returns The result of the is mjks map operation (`Promise<boolean>`).
   */
  async isMjksMap(input: Blob | Uint8Array): Promise<boolean> {
    return MajikSignatureMap.isMJKSMAP(input);
  }

  /**
   * Per-file signing status for a loaded map — no crypto, just structure.
   * Feeds a "batch status" table without touching the files.
   * @param input - Serialized input to parse or inspect.
   */
  async describeMjksMap(input: MjksMapInput) {
    const map = await MajikSignatureMap.from(input);
    return {
      createdAt: map.createdAt,
      size: map.size,
      files: map.getAllEnvelopes().map(({ path, envelope }) => ({
        path,
        entry: map.getEntry(path)!,
        info: envelope.getEnvelopeInfo(),
      })),
    };
  }

  /**
   * Sign a batch of files as detached envelopes with the active (or given) account.
   * mode "map" (default) -> one .mjksmap; mode "separate" -> one .mjksig per file.
   * @param files - Collection of files to process as a batch.
   * @param options - Optional operation-specific settings.
   * @param source - History source recorded for the operation.
   * @returns The result of the sign batch detached operation (`ReturnType<typeof MajikSignature.signBatchDetached>`).
   */
  async signBatchDetached(
    files: BatchFileInput[],
    options?: BatchSignOptions & { accountId?: string },
    source: HistorySource = HistorySources.SYSTEM,
  ): ReturnType<typeof MajikSignature.signBatchDetached> {
    const { accountId, ...signOptions } = options ?? {};

    return this._withSigningKey(accountId, "signBatchDetached", async (key) => {
      const result = await MajikSignature.signBatchDetached(
        files,
        key,
        signOptions,
      );
      const identity = this._identityFromKey(key);

      if (result.mode === "map") {
        if (result.map.size > 0) {
          const bytes = result.map.toMJKSMAPBytes();
          const digest = await this._sha256Base64(bytes);
          // ⚠️ consider a dedicated HistoryTypes.BATCH_SIGN
          this._recordHistory(key.fingerprint, {
            reference_id: digest,
            historyType: HistoryTypes.SIGN,
            status: HistoryStatuses.SUCCESS,
            source,
            operation: { digest, detached: true, sealed: false, tsa: false },
            signerCount: 1,
            data: bytes,
            identity,
          }).catch((err) => console.warn(err));
        }
      } else {
        for (const { blob } of result.signatures) {
          const bytes = new Uint8Array(await blob.arrayBuffer());
          const digest = await this._sha256Base64(bytes);
          this._recordHistory(key.fingerprint, {
            reference_id: digest,
            historyType: HistoryTypes.SIGN,
            status: HistoryStatuses.SUCCESS,
            source,
            operation: { digest, detached: true, sealed: false, tsa: false },
            signerCount: 1,
            data: bytes,
            identity,
          }).catch((err) => console.warn(err));
        }
      }

      return result;
    });
  }

  /**
   * Add the active account's signature to EVERY listed file in an existing map.
   * (Core signBatchDetached always starts a fresh map — it has no existingMap
   * option — so multi-signer batches are composed here, entry by entry, through
   * signFileDetached's existingEnvelope.)
   *
   * Refuses to sign any file whose bytes no longer match the map entry.
   * Allowlist / seal rules are enforced per entry by the core; violations land in
   * `failures` (or throw when continueOnError is false).
   * @param mapInput - MJKS map input to read, sign, co-sign, or verify.
   * @param files - Collection of files to process as a batch.
   * @param options - Optional operation-specific settings.
   * @param source - History source recorded for the operation.
   * @returns The result of the cosign mjks map operation (`Promise<{ map: MajikSignatureMap; mapBlob: Blob; failures: { path: string; error: string }[]; }>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async cosignMjksMap(
    mapInput: MjksMapInput,
    files: BatchVerifyInput[],
    options?: {
      accountId?: string;
      validUntil?: string;
      continueOnError?: boolean;
    },
    source: HistorySource = HistorySources.SYSTEM,
  ): Promise<{
    map: MajikSignatureMap;
    mapBlob: Blob;
    failures: { path: string; error: string }[];
  }> {
    let map = await MajikSignatureMap.from(mapInput);

    return this._withSigningKey(
      options?.accountId,
      "cosignMjksMap",
      async (key) => {
        const failures: { path: string; error: string }[] = [];
        let signedCount = 0;

        for (const f of files) {
          try {
            const found = await map.findEntry(f.path, f.blob);
            if (!found.found || !found.entry) {
              throw new Error("path is not in the map");
            }
            if (!found.hashMatches) {
              throw new Error(
                "file no longer matches the map entry — refusing to co-sign",
              );
            }

            const { envelope } = await MajikSignature.signFileDetached(
              f.blob,
              key,
              {
                existingEnvelope: found.entry.envelope,
                mimeType: found.entry.mimeType,
                validUntil: options?.validUntil,
              },
            );

            map = map.withEntry({
              ...found.entry,
              envelope: envelope.toJSON(),
            });
            signedCount++;
          } catch (err) {
            failures.push({
              path: f.path,
              error: err instanceof Error ? err.message : String(err),
            });
            if (!options?.continueOnError) throw err;
          }
        }

        if (signedCount > 0) {
          const bytes = map.toMJKSMAPBytes();
          const digest = await this._sha256Base64(bytes);
          this._recordHistory(key.fingerprint, {
            reference_id: digest,
            historyType: HistoryTypes.SIGN,
            status: HistoryStatuses.SUCCESS,
            source,
            operation: { digest, detached: true, sealed: false, tsa: false },
            signerCount: 1,
            data: bytes,
            identity: this._identityFromKey(key),
          }).catch((err) => console.warn(err));
        }

        return { map, mapBlob: map.toMJKSMAP(), failures };
      },
    );
  }

  /**
   * Verify a set of extracted files against a .mjksmap.
   *
   * TRUSTED mode (contactId / address / key supplied): delegates to the core
   * verifyFilesFromMjksMap against those keys — one signer, no self-reported keys.
   *
   * SELF-REPORTED mode (nothing supplied): every signature in each entry's
   * envelope is checked against the keys embedded in that envelope. Cross-check
   * signerId against your directory (VerifyResult.signerLabel) before trusting.
   *
   * Also reports `missingFromBatch` — map entries with no supplied file — which
   * per-file statuses alone can't show (a deleted file just never appears).
   * @param mapInput - MJKS map input to read, sign, co-sign, or verify.
   * @param files - Collection of files to process as a batch.
   * @param options - Optional operation-specific settings.
   * @param source - History source recorded for the operation.
   * @returns The result of the verify mjks map operation (`Promise<MjksMapVerifyResult>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async verifyMjksMap(
    mapInput: MjksMapInput,
    files: BatchVerifyInput[],
    options?: MjksMapVerifyOptions,
    source: HistorySource = HistorySources.SYSTEM,
  ): Promise<MjksMapVerifyResult> {
    try {
      const map = await MajikSignatureMap.from(mapInput);
      const publicKeys = await this._resolveSignerPublicKeys(options);

      let results: FileVerifyResult[];

      if (publicKeys) {
        results = await MajikSignature.verifyFilesFromMjksMap(
          map,
          files,
          publicKeys,
          {
            expectedSignerId: options?.expectedSignerId,
            now: options?.now,
            requireAllPresent: options?.requireAllPresent,
          },
        );
      } else {
        results = [];
        for (const f of files) {
          const res = await map.resolveEntry(f.path, f.blob);

          if (res.status === "not_found" || !res.entry) {
            results.push({
              path: f.path,
              status: "not_in_map",
              reason: "No map entry matches this path or this content",
            });
            continue;
          }
          if (res.status === "path_tampered") {
            results.push({
              path: f.path,
              status: "tampered",
              reason: "File content no longer matches what was signed",
            });
            continue;
          }

          const perSig = await this.verifyFileDetachedAllSignatures(
            f.blob,
            res.entry.envelope,
            source,
            options?.now,
          );
          const ok = perSig.length > 0 && perSig.every((r) => r.valid);
          results.push({
            path: f.path,
            status: ok ? "verified" : "invalid",
            results: perSig,
            reason: ok
              ? undefined
              : (perSig.find((r) => !r.valid)?.reason ?? "A signature failed"),
            ...(res.status === "relocated"
              ? { relocatedFrom: res.originalPath }
              : {}),
          });
        }

        if (
          options?.requireAllPresent &&
          results.some((r) => r.status === "not_in_map")
        ) {
          throw new Error(
            "verifyMjksMap: one or more files are not in the map",
          );
        }
      }

      const covered = new Set<string>();
      for (const f of files) covered.add(this._normalizeMapPath(f.path));
      for (const r of results) {
        if (r.relocatedFrom)
          covered.add(this._normalizeMapPath(r.relocatedFrom));
      }
      const missingFromBatch = map.entries
        .map((e) => e.path)
        .filter((p) => !covered.has(p));

      return {
        results,
        summary: MajikSignature.summarizeBatchVerification(results),
        missingFromBatch,
        trustedKeys: !!publicKeys,
      };
    } catch (err) {
      this._emit("error", err, { context: "verifyMjksMap" });
      throw err;
    }
  }

  // ══════════════════════════════════════════════════════════════════════════
  // ── ORDER-AWARE VERIFICATION ─────────────────────────────────────────────
  // ══════════════════════════════════════════════════════════════════════════
  //
  // Order verification is trusted-key by construction: each expected signer is
  // verified against the key material in `expectedOrder` (contacts / own keys),
  // never the keys embedded in the envelope. The result already contains
  // allValid, so no separate verifyFile() pass is needed.
  //
  // UI notes:
  //  - Surface result.usesUnattestedTimestamp as a caveat ("order based on
  //    signer-reported clocks"), and result.softTieWarnings.
  //  - Re-signing overwrites a signer's entry and moves their timestamp forward,
  //    so a re-sign can flip an order that previously passed.

  /**
   * Verifies file signatures and checks that signatories follow the expected order.
   * @param file - Input file or Blob-like value to sign, verify, inspect, or transform.
   * @param expectedOrder - Expected signer order to enforce during ordered verification.
   * @param options - Optional operation-specific settings.
   * @param source - History source recorded for the operation.
   * @returns The result of the verify file order operation (`Promise<SignatureOrderResult>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async verifyFileOrder(
    file: FileLike,
    expectedOrder: readonly SignerRef[],
    options?: { mimeType?: string; strict?: boolean },
    source: HistorySource = HistorySources.SYSTEM,
  ): Promise<SignatureOrderResult> {
    try {
      const expected = this.buildExpectedSigners(expectedOrder);
      const result = await MajikSignature.verifyFileOrder(
        file,
        expected,
        options,
      );

      const digest = (await MajikSignature.extractFrom(file, options))[0]
        ?.contentHash;
      if (digest) this._recordOrderHistory(digest, result.valid, false, source);

      return result;
    } catch (err) {
      this._emit("error", err, { context: "verifyFileOrder" });
      throw err;
    }
  }

  /**
   * Verifies a detached envelope and checks signatory order.
   * @param file - Input file or Blob-like value to sign, verify, inspect, or transform.
   * @param envelope - Detached envelope containing the signatures associated with the file.
   * @param expectedOrder - Expected signer order to enforce during ordered verification.
   * @param options - Optional operation-specific settings.
   * @param source - History source recorded for the operation.
   * @returns The result of the verify file detached order operation (`Promise<SignatureOrderResult>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async verifyFileDetachedOrder(
    file: FileLike,
    envelope: EnvelopeInput,
    expectedOrder: readonly SignerRef[],
    options?: { mimeType?: string; strict?: boolean },
    source: HistorySource = HistorySources.SYSTEM,
  ): Promise<SignatureOrderResult> {
    try {
      const expected = this.buildExpectedSigners(expectedOrder);
      const resolved = await MajikSignatureEnvelope.from(envelope);
      const result = await MajikSignature.verifyFileDetachedOrder(
        file,
        resolved,
        expected,
        options,
      );

      const digest = resolved.signatures[0]?.contentHash;
      if (digest) this._recordOrderHistory(digest, result.valid, true, source);

      return result;
    } catch (err) {
      this._emit("error", err, { context: "verifyFileDetachedOrder" });
      throw err;
    }
  }

  /**
   * Order check across a whole .mjksmap. `expectedOrder` may be one order applied
   * to every file, or a function returning a per-path order (different documents
   * in one batch often have different signing chains).
   * @param mapInput - MJKS map input to read, sign, co-sign, or verify.
   * @param files - Collection of files to process as a batch.
   * @param expectedOrder - Expected signer order to enforce during ordered verification.
   * @param options - Optional operation-specific settings.
   * @param source - History source recorded for the operation.
   * @returns The result of the verify mjks map order operation (`Promise<{ results: MjksMapOrderFileResult[]; allOrdered: boolean }>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  async verifyMjksMapOrder(
    mapInput: MjksMapInput,
    files: BatchVerifyInput[],
    expectedOrder:
      | readonly SignerRef[]
      | ((path: string) => readonly SignerRef[]),
    options?: { mimeType?: string; strict?: boolean },
    source: HistorySource = HistorySources.SYSTEM,
  ): Promise<{ results: MjksMapOrderFileResult[]; allOrdered: boolean }> {
    try {
      const map = await MajikSignatureMap.from(mapInput);
      const results: MjksMapOrderFileResult[] = [];

      for (const f of files) {
        const res = await map.resolveEntry(f.path, f.blob);

        if (res.status === "not_found" || !res.entry) {
          results.push({
            path: f.path,
            resolveStatus: res.status,
            reason: "No map entry matches this path or content",
          });
          continue;
        }
        if (res.status === "path_tampered") {
          results.push({
            path: f.path,
            resolveStatus: res.status,
            reason: "File content no longer matches what was signed",
          });
          continue;
        }

        try {
          const refs =
            typeof expectedOrder === "function"
              ? expectedOrder(res.entry.path)
              : expectedOrder;

          const order = await this.verifyFileDetachedOrder(
            f.blob,
            res.entry.envelope,
            refs,
            {
              mimeType: options?.mimeType ?? res.entry.mimeType,
              strict: options?.strict,
            },
            source,
          );
          results.push({
            path: f.path,
            resolveStatus: res.status,
            order,
            reason: order.reason,
          });
        } catch (err) {
          results.push({
            path: f.path,
            resolveStatus: res.status,
            reason: err instanceof Error ? err.message : String(err),
          });
        }
      }

      return {
        results,
        allOrdered:
          results.length > 0 && results.every((r) => r.order?.valid === true),
      };
    } catch (err) {
      this._emit("error", err, { context: "verifyMjksMapOrder" });
      throw err;
    }
  }

  // ── Private: Signer resolution ────────────────────────────────────────────

  /**
   *
   * Callers pass { contactId, publicKeyBase64 } but the old resolver only read
   * { contactID, address }. Result: contactId was silently ignored, the method
   * returned null, and verifyContent/verifyFile/verifyFileDetached/batchVerifyFiles
   * fell back to SELF-REPORTED envelope keys — i.e. "verify against a known
   * contact" wasn't happening. This accepts both spellings.
   *
   * (Assumes publicKeyBase64 is the contact's MajikKeyAddress, as in
   *  getContactByAddress — adjust if not.)
   * @param options - Optional operation-specific settings.
   * @returns The result of the resolve signer public keys operation (`Promise<MajikSignerPublicKeys | null>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  private async _resolveSignerPublicKeys(options?: {
    contactId?: string;
    address?: MajikKeyAddress;
    publicKeyBase64?: string;
    key?: MajikKey;
    expectedSignerId?: string;
  }): Promise<MajikSignerPublicKeys | null> {
    if (!options) return null;

    if (options.key) return MajikSignature.publicKeysFromMajikKey(options.key);
    const contactId = options.contactId;
    const address = options.address ?? options.publicKeyBase64;
    let contact: MajikContact | undefined | null;

    if (contactId) {
      contact = this._contacts.getContact(contactId);
      if (!contact) throw new Error(`No contact found for id "${contactId}"`);

      const own = this._keys.get(contactId);
      if (own?.hasSigningKeys)
        return MajikSignature.publicKeysFromMajikKey(own);
    } else if (address) {
      contact = await this._contacts.getContactByAddress(address);
      if (!contact)
        throw new Error(`No contact found for public key "${address}"`);
    } else {
      return null;
    }

    if (!contact.edPublicKeyBase64 || !contact.mlDsaPublicKeyBase64) {
      throw new Error(
        `Contact "${contact.id}" has no signing public keys. ` +
          `They may need to share an updated contact card.`,
      );
    }

    return {
      signerId: contact.fingerprint,
      edPublicKey: base64ToUint8Array(contact.edPublicKeyBase64),
      mlDsaPublicKey: base64ToUint8Array(contact.mlDsaPublicKeyBase64),
    };
  }

  /**
   * Resolve a MajikFileIdentity from an unlocked account, for stamp
   * encryption/decryption. Requires the account to have ML-KEM keys and
   * to already be unlocked — call ensureIdentityUnlocked() first if needed.
   * @param accountId - Account identifier to use. When omitted, the currently active account is used where supported.
   * @returns The result of the resolve majik file identity operation (`MajikFileIdentity`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  private _resolveMajikFileIdentity(accountId?: string): MajikFileIdentity {
    const id = accountId ?? this.getActiveAccount()?.id;
    if (!id)
      throw new Error("No active account — call setActiveAccount() first");

    const key = this._keys.get(id);
    if (!key) throw new Error(`Account not found in keystore: "${id}"`);
    if (key.isLocked) {
      throw new Error(
        `Account "${id}" is locked. Call unlockAccount() before using stamps.`,
      );
    }

    const mlKemSecretKey = this._keys.getMlKemSecretKey(id);
    if (!mlKemSecretKey) {
      throw new Error(
        `Account "${id}" has no ML-KEM keys. Re-import via ` +
          `importAccountFromMnemonicBackup() to enable stamp encryption.`,
      );
    }

    return {
      publicKey: key.publicKeyBase64,
      fingerprint: key.fingerprint,
      mlKemPublicKey: key.mlKemPublicKey,
      mlKemSecretKey,
    };
  }

  /**
   * One place for unlock -> signing-keys check -> one-time-unlock relock.
   * New methods use this; you can migrate sign()/signFile()/seal() onto it later
   * to delete the copy-pasted boilerplate.
   * @param accountId - Account identifier to use. When omitted, the currently active account is used where supported.
   * @param context - Value used by the _with signing key operation.
   * @param fn - Value used by the _with signing key operation.
   * @returns The result of the with signing key operation (`Promise<T>`).
   * @throws {Error} When validation fails, required local data is unavailable, or the underlying operation cannot be completed.
   */
  private async _withSigningKey<T>(
    accountId: string | undefined,
    context: string,
    fn: (key: MajikKey) => Promise<T>,
  ): Promise<T> {
    const id = accountId ?? this.getActiveAccount()?.id;
    if (!id)
      throw new Error("No active account — call setActiveAccount() first");

    let key: MajikKey | undefined;
    let shouldRelock = false;
    try {
      await this._keys.ensureUnlocked(id);
      key = this._keys.get(id);
      if (!key) throw new Error(`Account not found in keystore: "${id}"`);
      if (!key.hasSigningKeys) {
        throw new Error(
          `Account "${id}" has no signing keys. ` +
            `Re-import via importAccountFromMnemonicBackup() to enable signing.`,
        );
      }
      shouldRelock = !(await this.isOnetimeUnlockEnabled());
      return await fn(key);
    } catch (err) {
      this._emit("error", err, { context });
      throw err;
    } finally {
      if (shouldRelock) key?.lock();
    }
  }

  /**
   * Computes a SHA-256 digest and encodes it as base64.
   * @param bytes - Value used by the _sha256 base64 operation.
   * @returns The result of the sha256 base64 operation (`Promise<string>`).
   */
  private async _sha256Base64(bytes: Uint8Array): Promise<string> {
    const digest = new Uint8Array(
      await crypto.subtle.digest("SHA-256", bytes as BufferSource),
    );
    let bin = "";
    for (let i = 0; i < digest.length; i++)
      bin += String.fromCharCode(digest[i]);
    return btoa(bin);
  }

  /**
   *  Same normalization MajikSignatureMap uses internally (it isn't exported).
   * @param path - Map or storage path used for normalization or lookup.
   * @returns The result of the normalize map path operation (`string`).
   */
  private _normalizeMapPath(path: string): string {
    return path
      .replace(/\\/g, "/")
      .trim()
      .replace(/^[a-zA-Z]:/, "")
      .replace(/^\/+/, "");
  }

  /**
   * Records history for a signature-order verification operation.
   * @param digest - Content digest used as the stable history reference for the operation.
   * @param valid - Whether the associated verification succeeded.
   * @param detached - Whether the operation targets a detached envelope.
   * @param source - History source recorded for the operation.
   * @returns Completes when the operation has finished.
   */
  private _recordOrderHistory(
    digest: string,
    valid: boolean,
    detached: boolean,
    source: HistorySource,
  ): void {
    this._recordHistory(this.getActiveAccountKey()?.fingerprint, {
      reference_id: digest,
      historyType: HistoryTypes.VERIFY,
      status: valid ? HistoryStatuses.SUCCESS : HistoryStatuses.FAILED,
      source,
      operation: { digest, detached, sealed: false, tsa: false },
      valid,
    }).catch((err) => console.warn(err));
  }

  // ==========================================================================
  // ── Backup App Data ───────────────────────────────────────────────────────
  // ==========================================================================

  /**
   * Creates a portable, integrity-protected backup of the contact directory.
   * @returns The result of the backup contacts operation (`Promise<Blob>`).
   */
  async backupContacts(): Promise<Blob> {
    const managerJSON = await this._contacts.toJSON();
    const cj = MajikCompressedJSON.create<MajikContactManagerJSON>(managerJSON);
    const payload = cj.toBinary();
    const stamped = prependMagic(
      MAJIK_SIGNATURE_BACKUP_MAGIC.contacts,
      payload,
    );
    return new Blob([stamped as BlobPart], {
      type: "application/octet-stream",
    });
  }

  /**
   * Creates a portable, integrity-protected backup of stored signature stamps.
   * @returns The result of the backup stamps operation (`Promise<Blob>`).
   */
  async backupStamps(): Promise<Blob> {
    const stampsJSON = await this._stamps.toJSON();
    const cj =
      MajikCompressedJSON.create<MajikSignatureStampJSON[]>(stampsJSON);
    const payload = cj.toBinary();
    const stamped = prependMagic(MAJIK_SIGNATURE_BACKUP_MAGIC.stamps, payload);
    return new Blob([stamped as BlobPart], {
      type: "application/octet-stream",
    });
  }

  /**
   * Validates and parses the internal stamp backup payload.
   * @param input - Serialized input to parse or inspect.
   * @returns The result of the parse stamps backup operation (`Promise<MajikSignatureStampJSON[]>`).
   */
  private async _parseStampsBackup(
    input: Blob | ArrayBufferLike | ArrayBufferView,
  ): Promise<MajikSignatureStampJSON[]> {
    const payload = await readBackupBlob(
      input,
      MAJIK_SIGNATURE_BACKUP_MAGIC.stamps,
      "stamps",
    );
    const cj =
      await MajikCompressedJSON.fromMJKCJSON<MajikSignatureStampJSON[]>(
        payload,
      );
    return cj.payload;
  }

  /**
   * Validates and reads a stamp backup without restoring it.
   * @param input - Serialized input to parse or inspect.
   * @returns The result of the read stamps backup operation (`Promise<MajikSignatureStampJSON[]>`).
   */
  async readStampsBackup(
    input: Blob | ArrayBufferLike | ArrayBufferView,
  ): Promise<MajikSignatureStampJSON[]> {
    return this._parseStampsBackup(input);
  }

  /**
   * Creates a portable backup containing contacts, stamps, and applicable application state.
   * @returns The result of the backup app data operation (`Promise<Blob>`).
   */
  async backupAppData(): Promise<Blob> {
    const contactsJSON = await this._contacts.toJSON();
    const stampsJSON = await this._stamps.toJSON();
    const userPref = await this.getUserAppPreferences();

    const backupJSON: AppBackUpData = {
      contacts: contactsJSON,
      stamps: stampsJSON,
      preferences: userPref ?? undefined,
    };

    const cj = MajikCompressedJSON.create<AppBackUpData>(backupJSON);
    const payload = cj.toBinary();
    const stamped = prependMagic(MAJIK_SIGNATURE_BACKUP_MAGIC.appData, payload);
    return new Blob([stamped as BlobPart], {
      type: "application/octet-stream",
    });
  }

  // ==========================================================================
  // ── Restore App Data ──────────────────────────────────────────────────────
  // ==========================================================================

  /**
   * Validates and parses the internal contact backup payload.
   * @param input - Serialized input to parse or inspect.
   * @returns The result of the parse contacts backup operation (`Promise<ContactManagerSnapshot>`).
   */
  private async _parseContactsBackup(
    input: Blob | ArrayBufferLike | ArrayBufferView,
  ): Promise<ContactManagerSnapshot> {
    const payload = await readBackupBlob(
      input,
      MAJIK_SIGNATURE_BACKUP_MAGIC.contacts,
      "contacts",
    );
    const cj =
      await MajikCompressedJSON.fromMJKCJSON<MajikContactManagerJSON>(payload);

    const managerJSON = cj.payload;

    const tempManager = await MajikContactManager.fromJSON(managerJSON);

    const contacts = tempManager.listContacts(false);
    const groups = tempManager.listGroups(false);

    return { managerJSON, contacts, groups };
  }

  /**
   * Restores stamps from a validated stamp backup.
   * @param input - Serialized input to parse or inspect.
   * @returns The result of the restore stamps operation (`Promise<{ restored: number }>`).
   */
  async restoreStamps(
    input: Blob | ArrayBufferLike | ArrayBufferView,
  ): Promise<{ restored: number }> {
    const stampsJSON = await this._parseStampsBackup(input);
    await Promise.all(
      stampsJSON.map((json) =>
        this._stamps.save(MajikSignatureStamp.fromJSON(json)),
      ),
    );
    return { restored: stampsJSON.length };
  }

  /**
   * Restores contacts (and optionally groups) from a contacts backup blob.
   * @param input - Serialized input to parse or inspect.
   * @param options - Optional operation-specific settings.
   * @returns The result of the restore contacts operation (`Promise<{ contacts: number; groups: number }>`).
   */
  async restoreContacts(
    input: Blob | ArrayBufferLike | ArrayBufferView,
    options: {
      overwriteContacts?: boolean;
      includeGroups?: boolean;
    } = {},
  ): Promise<{ contacts: number; groups: number }> {
    const { overwriteContacts = true, includeGroups = true } = options;

    const { contacts, groups } = await this._parseContactsBackup(input);

    let contactCount = 0;
    for (const contact of contacts) {
      const exists = !!this._contacts.getContact(contact.id);
      if (exists && !overwriteContacts) continue;
      await this.addContact(contact);
      contactCount++;
    }

    let groupCount = 0;
    if (includeGroups) {
      for (const group of groups) {
        if (group.isSystem) continue;

        if (!this._contacts.hasGroup(group.id)) {
          await this._contacts.addGroup(group);
        } else {
          for (const memberId of group.listMemberIds()) {
            if (this._contacts.hasContact(memberId)) {
              await this._contacts.addContactToGroupIfAbsent(
                group.id,
                memberId,
              );
            }
          }
        }
        groupCount++;
      }
    }

    return { contacts: contactCount, groups: groupCount };
  }

  /**
   * Validates and reads a contact backup without restoring it.
   * @param input - Serialized input to parse or inspect.
   * @returns The result of the read contacts backup operation (`Promise<ContactManagerSnapshot>`).
   */
  async readContactsBackup(
    input: Blob | ArrayBufferLike | ArrayBufferView,
  ): Promise<ContactManagerSnapshot> {
    return this._parseContactsBackup(input);
  }

  /**
   * Restores all data from a full backup blob produced by `backupAppData()`.
   * @param blob - Backup or file Blob containing the serialized data.
   * @returns The result of the restore app data operation (`Promise<{ contacts: number; groups: number; }>`).
   */
  async restoreAppData(blob: Blob): Promise<{
    contacts: number;
    groups: number;
    stamps: number;
  }> {
    const payload = await readBackupBlob(
      blob,
      MAJIK_SIGNATURE_BACKUP_MAGIC.appData,
      "app data",
    );
    const cj = await MajikCompressedJSON.fromMJKCJSON<AppBackUpData>(payload);
    const data = cj.payload;

    const tempManager = await MajikContactManager.fromJSON(data.contacts);
    const contacts = tempManager.listContacts(false);
    const groups = tempManager.listGroups(false);

    for (const contact of contacts) {
      await this._contacts.addContact(contact);
    }

    for (const group of groups) {
      if (group.isSystem) continue;
      if (!this._contacts.hasGroup(group.id)) {
        await this._contacts.addGroup(group);
      } else {
        for (const memberId of group.listMemberIds()) {
          if (this._contacts.hasContact(memberId)) {
            await this._contacts.addContactToGroupIfAbsent(group.id, memberId);
          }
        }
      }
    }

    await Promise.all(
      (data.stamps ?? []).map((json) => {
        const stamp = MajikSignatureStamp.fromJSON(json);
        return this._stamps.save(stamp);
      }),
    );

    if (data.preferences) {
      await this.setUserAppPreferences(data.preferences);
    }

    this._recordActivity(this.getActiveAccountKey()?.fingerprint, {
      reference_id: "app-data-restore",
      action: AuditActions.RESTORE_APP_DATA, // ⚠️
      metadata: {
        contactsRestored: contacts.length,
        groupsRestored: groups.filter((g) => !g.isSystem).length,
        stampsRestored: (data.stamps ?? []).length,
      },
    });

    return {
      contacts: contacts.length,
      groups: groups.filter((g) => !g.isSystem).length,
      stamps: data.stamps?.length ?? 0,
    };
  }

  /**
   * Probes the first bytes of a blob and returns which backup type it is,
   * without fully parsing it.
   * @param blob - Backup or file Blob containing the serialized data.
   * @returns The result of the probe backup type operation (`Promise<"stamps" | "contacts" | "appData" | "unknown">`).
   */
  static async probeBackupType(
    blob: Blob,
  ): Promise<"stamps" | "contacts" | "appData" | "unknown"> {
    const header = new Uint8Array(
      await blob.slice(0, MAJIK_SIGNATURE_BACKUP_MAGIC_SIZE).arrayBuffer(),
    );

    for (const [type, magic] of Object.entries(
      MAJIK_SIGNATURE_BACKUP_MAGIC,
    ) as [keyof typeof MAJIK_SIGNATURE_BACKUP_MAGIC, Uint8Array][]) {
      if (magic.every((byte, i) => header[i] === byte)) return type;
    }

    return "unknown";
  }

  /**
   * Validates and parses the internal application backup payload.
   * @param input - Serialized input to parse or inspect.
   * @returns The result of the parse app data backup operation (`Promise<AppDataSnapshot>`).
   */
  private async _parseAppDataBackup(
    input: Blob | ArrayBufferLike | ArrayBufferView,
  ): Promise<AppDataSnapshot> {
    const payload = await readBackupBlob(
      input,
      MAJIK_SIGNATURE_BACKUP_MAGIC.appData,
      "app data",
    );
    const cj = await MajikCompressedJSON.fromMJKCJSON<AppBackUpData>(payload);
    const data = cj.payload;

    const tempManager = await MajikContactManager.fromJSON(data.contacts);
    const contacts = tempManager.listContacts(false);
    const groups = tempManager.listGroups(false);

    return {
      contacts,
      groups,
      stamps: data.stamps ?? [],
      preferences: data.preferences ?? null,
      _contactsManagerJSON: data.contacts,
    };
  }

  /**
   * Validates and reads an application backup without restoring it.
   * @param input - Serialized input to parse or inspect.
   * @returns The result of the read app data backup operation (`Promise<AppDataSnapshot>`).
   */
  async readAppDataBackup(
    input: Blob | ArrayBufferLike | ArrayBufferView,
  ): Promise<AppDataSnapshot> {
    return this._parseAppDataBackup(input);
  }

  /**
   * Restores selected sections from an app data backup snapshot.
   * @param snapshot - Parsed application snapshot containing restorable contacts, groups, stamps, and preferences.
   * @param options - Optional operation-specific settings.
   * @returns The result of the restore app data selective operation (`Promise<{ contacts: number; groups: number; preferences: boolean; }>`).
   */
  async restoreAppDataSelective(
    snapshot: AppDataSnapshot,
    options: {
      stamps?: boolean;
      contacts?: boolean;
      groups?: boolean;
      preferences?: boolean;
      overwriteContacts?: boolean;
    } = {},
  ): Promise<{
    contacts: number;
    groups: number;
    stamps: number;
    preferences: boolean;
  }> {
    const {
      stamps: doStamps = true,
      contacts: doContacts = true,
      groups: doGroups = true,
      preferences: doPreferences = true,
      overwriteContacts = true,
    } = options;

    let stampCount = 0;
    let contactCount = 0;
    let groupCount = 0;
    let defaultsRestored = false;
    let preferencesRestored = false;

    if (doContacts) {
      for (const contact of snapshot.contacts) {
        const exists = !!this._contacts.getContact(contact.id);
        if (exists && !overwriteContacts) continue;
        await this.addContact(contact);
        contactCount++;
      }
    }

    if (doGroups) {
      for (const group of snapshot.groups) {
        if (group.isSystem) continue;
        if (!this._contacts.hasGroup(group.id)) {
          await this.addGroup(group);
        } else {
          for (const memberId of group.listMemberIds()) {
            if (this._contacts.hasContact(memberId)) {
              await this._contacts.addContactToGroupIfAbsent(
                group.id,
                memberId,
              );
            }
          }
        }
        groupCount++;
      }
    }

    if (doStamps) {
      await Promise.all(
        snapshot.stamps.map((json) =>
          this._stamps.save(MajikSignatureStamp.fromJSON(json)),
        ),
      );
      stampCount = snapshot.stamps.length;
    }

    if (doPreferences && snapshot.preferences) {
      await this.setUserAppPreferences(snapshot.preferences);
      preferencesRestored = true;
    }
    const restoredData = {
      stamps: stampCount,
      contacts: contactCount,
      groups: groupCount,
      defaults: defaultsRestored,
      preferences: preferencesRestored,
    };

    this._emit("restore-backup", restoredData);

    return restoredData;
  }
}
