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

import { MajikSignature } from "@majikah/majik-signature";
import type {
  EnvelopeInfo,
  ExpectedSigner,
  MajikSignatureJSON,
  MajikSignerPublicKeys,
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
  MAJIK_MESSAGE_BACKUP_MAGIC_SIZE,
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

// ─── Types ────────────────────────────────────────────────────────────────────

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
  | "contact-group-change";

export interface MajikSignatureClientConfig extends MajikKeyClientConfig {
  clientStateManager?: ClientStateManager; // narrower — OK, interfaces allow this
  contactManager?: MajikContactManager;
  stampsManager?: MajikSignatureStampManager;
  adapters?: MajikKeyClientConfig["adapters"] & {
    contacts?: MajikContactManagerAdapters;
    stamps?: MajikSignatureStampStorageAdapter;
  };
}

export interface SignResult {
  signature: MajikSignature;
  signerId: string;
  contentHash: string;
  timestamp: string;
  contentType?: string;
}

export interface VerifyResult extends VerificationResult {
  signerLabel?: string; // resolved from contact directory if available
}

export interface MajikSignatureClientJSON {
  id: string;
  contacts: MajikContactManagerJSON;
  ownAccounts?: {
    accounts: SerializedMajikContact[];
    order: string[];
  };
}

// ─── MajikSignatureClient ─────────────────────────────────────────────────────

export class MajikSignatureClient extends MajikKeyClient<
  MajikContact,
  MajikContactMeta,
  MajikSignatureClientEvents,
  ClientStateManager
> {
  private _contacts: MajikContactManager;
  private _stamps: MajikSignatureStampManager;

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

    // Base already registers: new-account, removed-account, updated-account,
    // active-account-change, unlock, lock, error, restore-backup.
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
    ]);
  }

  /**
   * Override — without this, MajikKeyClient's constructor falls back to
   * building a plain MajikKeyClientStateManager (ACCOUNT_ORDER only),
   * and every call to getUserAppPreferences() etc. throws at runtime.
   */
  protected _createDefaultStateManager(
    adapter?: ClientStateStorageAdapter,
  ): ClientStateManager {
    return new ClientStateManager(adapter ?? new InMemoryClientStateAdapter());
  }

  /** Expose the stamp manager for direct access if needed. */
  get stampManager(): MajikSignatureStampManager {
    return this._stamps;
  }

  // ==========================================================================
  // ── MajikKeyClient HOOKS ──────────────────────────────────────────────────
  // ==========================================================================

  protected _buildOwnAccountContact(
    key: MajikKey,
    meta?: Partial<MajikContactMeta>,
  ): MajikContact {
    return key.toContact(meta);
  }

  protected async _onAccountRegistered(contact: MajikContact): Promise<void> {
    if (!this._contacts.hasContact(contact.id)) {
      await this._contacts.addContact(contact);
    }
  }

  protected async _onAccountRemoved(id: string): Promise<void> {
    await this._contacts.removeContact(id);
  }

  protected async _onResetKeyData(): Promise<void> {
    await this._contacts.clear();
    await this._stamps.adapter.clear();
    this._stamps = new MajikSignatureStampManager(this._stamps.adapter);
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
   */
  async hydrate(): Promise<void> {
    await this._hydrateKeys();
    await this._contacts.hydrate();
    await this._stamps.hydrate();
    await this._hydrateState();
    await this._hydrateOwnAccounts();
    await this._restoreAccountOrder();
  }

  /**
   * Construct a client and immediately hydrate it.
   */
  static async create<T extends MajikSignatureClient>(
    this: new (config: MajikSignatureClientConfig) => T,
    config: MajikSignatureClientConfig = {},
  ): Promise<T> {
    const client = new this(config);
    await client.hydrate();
    return client;
  }

  // ==========================================================================
  // ── USER APP PREFERENCES ──────────────────────────────────────────────────────
  // ==========================================================================

  /**
   * Retrieve persisted user app prefernces, or `null` if none have been saved.
   */
  async getUserAppPreferences(): Promise<UserAppPreferences> {
    return this.stateManager.getUserAppPreferences();
  }

  /**
   * Persist user app prefernces.
   */
  async setUserAppPreferences(preferences: UserAppPreferences): Promise<void> {
    await this.stateManager.setUserAppPreferences(preferences);
  }

  /**
   * Remove persisted user app prefernces.
   */
  async removeUserAppPreferences(): Promise<void> {
    await this.stateManager.removeUserAppPreferences();
  }

  /**
   * Reset persisted user app prefernces to default settings.
   */
  async resetUserAppPreferences(): Promise<void> {
    await this.stateManager.resetUserAppPreferences();
  }

  async isAnalyticsEnabled(): Promise<boolean> {
    const appPreferences = await this.stateManager.getUserAppPreferences();
    return appPreferences.privacy.shareAnalytics ?? false;
  }

  async isAutoSealEnabled(): Promise<boolean> {
    const appPreferences = await this.stateManager.getUserAppPreferences();
    return appPreferences.signing.autoSeal ?? false;
  }

  async isDefaultToTSAEnabled(): Promise<boolean> {
    const appPreferences = await this.stateManager.getUserAppPreferences();
    return appPreferences.signing.defaultToTSA ?? false;
  }

  async isAutoLockOnMinimizeEnabled(): Promise<boolean> {
    const appPreferences = await this.stateManager.getUserAppPreferences();
    return appPreferences.security?.key?.autoLockOnMinimize ?? false;
  }

  async autoLockInterval(): Promise<number | undefined> {
    const appPreferences = await this.stateManager.getUserAppPreferences();
    return appPreferences.security?.key?.autoLockInterval;
  }

  async isOnetimeUnlockEnabled(): Promise<boolean> {
    const appPreferences = await this.stateManager.getUserAppPreferences();
    return appPreferences.security?.key?.onetimeUnlock ?? true;
  }

  // ==========================================================================
  // ── ACCOUNT MANAGEMENT (overrides / additions on top of MajikKeyClient) ──
  // ==========================================================================

  /**
   * Update the metadata (e.g., label) of an owned account.
   * This updates both the contact directory and the local ownAccounts cache.
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

  async hasOwnIdentity(fingerprint: string): Promise<boolean> {
    return this.keyManager.has(fingerprint);
  }

  // ==========================================================================
  // ── CONTACT MANAGEMENT ────────────────────────────────────────────────────
  // ==========================================================================

  getContactByID(id: string): MajikContact | null {
    if (!id?.trim()) throw new Error("Invalid contact ID");
    return this._contacts.getContact(id) ?? null;
  }

  hasContact(id: string): boolean {
    if (!id?.trim()) throw new Error("Invalid contact ID");
    return this._contacts.hasContact(id);
  }

  async hasContactByAddress(publicKey: MajikKeyAddress): Promise<boolean> {
    if (!publicKey?.trim())
      throw new Error("Invalid contact public key address");
    return await this._contacts.hasContactByAddress(publicKey);
  }

  async getContactByAddress(
    address: MajikKeyAddress,
  ): Promise<MajikContact | null> {
    if (!address?.trim()) throw new Error("Invalid public key address");
    return (await this._contacts.getContactByAddress(address)) ?? null;
  }

  getContactsByID(ids: string[], strict = false): MajikContact[] {
    if (!ids?.length) throw new Error("At least 1 id is required");
    return this._contacts.getContactsByIds(ids, strict);
  }

  async getContactsByPublicKey(publicKeys: string[]): Promise<MajikContact[]> {
    if (!publicKeys?.length)
      throw new Error("At least 1 public key is required");
    return await this._contacts.getContactsByPublicKeys(publicKeys);
  }

  async exportContactAsJSON(id: string): Promise<string | null> {
    if (!id?.trim()) throw new Error("Invalid contact ID");
    return this._contacts.exportContactAsJSON(id);
  }

  async exportContactAsString(id: string): Promise<string | null> {
    if (!id?.trim()) throw new Error("Invalid contact ID");
    return this._contacts.exportContactAsString(id);
  }

  async importContactFromJSON(jsonStr: string): Promise<MAJIK_API_RESPONSE> {
    if (!jsonStr?.trim()) throw new Error("Invalid contact JSON");
    return this._contacts.importContactFromJSON(jsonStr);
  }

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

  async exportContactCompressed(contact: MajikContact): Promise<string> {
    if (!contact?.id?.trim()) throw new Error("Invalid contact");
    return this._contacts.exportContactCompressed(contact);
  }

  async importContactCompressed(base64Str: string): Promise<MajikContact> {
    if (!base64Str?.trim()) throw new Error("Invalid contact string");
    return this._contacts.importContactCompressed(base64Str);
  }

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
    this._emit("new-contact", contact);
  }

  async removeContact(id: string): Promise<void> {
    const result = await this._contacts.removeContact(id);
    if (!result.success) throw new Error(result.message);
    this._emit("removed-contact", id);
  }

  listContacts(
    includeOwnAccounts = false,
    majikahOnly: boolean = false,
  ): MajikContact[] {
    const contacts = this._contacts.listContacts(true, majikahOnly);
    if (includeOwnAccounts) return contacts;
    const ownIds = new Set(this.listOwnAccounts().map((a) => a.id));
    return contacts.filter((c) => !ownIds.has(c.id));
  }

  async updateContactMeta(
    id: string,
    meta: Partial<MajikContactMeta>,
  ): Promise<void> {
    await this._contacts.updateContactMeta(id, meta);
  }

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

  async addGroup(group: MajikContactGroup): Promise<this> {
    await this._contacts.addGroup(group);
    this._emit("new-contact-group", group);
    return this;
  }

  async removeGroup(id: string): Promise<MAJIK_API_RESPONSE> {
    const response = await this._contacts.removeGroup(id);
    this._emit("removed-contact-group", response.data as MajikContactGroup);
    return response;
  }

  getContactGroup(id: string): MajikContactGroup | undefined {
    return this._contacts.getGroup(id);
  }

  getGroupOrThrow(id: string): MajikContactGroup {
    return this._contacts.getGroupOrThrow(id);
  }

  hasGroup(id: string): boolean {
    return this._contacts.hasGroup(id);
  }

  listContactGroups(
    includeSystem = true,
    sortedByName = false,
  ): MajikContactGroup[] {
    return this._contacts.listGroups(includeSystem, sortedByName);
  }

  listUserGroups(sortedByName = true): MajikContactGroup[] {
    return this._contacts.listGroups(false, sortedByName);
  }

  listSystemGroups(): MajikContactGroup[] {
    return this._contacts.listGroups(true).filter((g) => g.isSystem);
  }

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

  async addContactToGroup(groupID: string, contactID: string): Promise<this> {
    const updatedGroup = await this._contacts.addContactToGroup(
      groupID,
      contactID,
    );
    this._emit("contact-group-change", updatedGroup);
    return this;
  }

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

  getContactsInGroup(groupID: string): MajikContact[] {
    return this._contacts.getContactsInGroup(groupID);
  }

  getContactsInGroupSorted(groupID: string): MajikContact[] {
    return this._contacts.getContactsInGroupSorted(groupID);
  }

  isContactInGroup(groupID: string, contactID: string): boolean {
    return this._contacts.isContactInGroup(groupID, contactID);
  }

  getGroupsForContact(contactID: string): MajikContactGroup[] {
    return this._contacts.getGroupsForContact(contactID);
  }

  getGroupIdsForContact(contactID: string): string[] {
    return this._contacts.getGroupIdsForContact(contactID);
  }

  async addContactToFavorites(contactID: string): Promise<this> {
    const updatedGroup = await this._contacts.addToFavorites(contactID);
    this._emit("contact-group-change", updatedGroup);
    return this;
  }

  async removeContactFromFavorites(contactID: string): Promise<this> {
    const updatedGroup = await this._contacts.removeFromFavorites(contactID);
    this._emit("contact-group-change", updatedGroup);
    return this;
  }

  isContactFavorite(contactID: string): boolean {
    return this._contacts.isFavorite(contactID);
  }
  isContactBlocked(contactID: string): boolean {
    return this._contacts.isContactBlocked(contactID);
  }
  getFavoritesGroup(): MajikContactGroup {
    return this._contacts.getFavoritesGroup();
  }
  getBlockedGroup(): MajikContactGroup {
    return this._contacts.getBlockedGroup();
  }

  getFavoriteContacts(): MajikContact[] {
    return this._contacts.getContactsInGroup(
      this._contacts.getFavoritesGroup().id,
    );
  }

  getBlockedContacts(): MajikContact[] {
    return this._contacts.getContactsInGroup(
      this._contacts.getBlockedGroup().id,
    );
  }

  async clearDirectory(): Promise<this> {
    await this._contacts.clear();
    return this;
  }

  resolveSignerLabel(signerId: string): string {
    const ownAccount = this._ownAccounts.get(signerId);
    if (ownAccount?.meta?.label) return ownAccount.meta.label;
    const contact = this._contacts.getContact(signerId);
    if (contact?.meta?.label) return contact.meta.label;
    return `${signerId.slice(0, 16)}…`;
  }

  // ── Signing ───────────────────────────────────────────────────────────────

  async sign(
    content: Uint8Array | string,
    options?: SignOptions,
    accountId?: string,
  ): Promise<SignResult> {
    const id = accountId ?? this.getActiveAccount()?.id;
    if (!id)
      throw new Error("No active account — call setActiveAccount() first");

    let key: ReturnType<typeof this._keys.get> | undefined;
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

      const signature = await MajikSignature.sign(content, key, options);

      const result: SignResult = {
        signature,
        signerId: signature.signerId,
        contentHash: signature.contentHash,
        timestamp: signature.timestamp,
        contentType: signature.contentType,
      };

      this._emit("sign", result);
      return result;
    } catch (err) {
      this._emit("error", err, { context: "sign" });
      throw err;
    } finally {
      if (shouldRelock) key?.lock();
    }
  }

  /**
   * Sign content and immediately serialize to a base64 string.
   * Convenience wrapper around sign() + serialize().
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
   *                      the envelope (self-reported — cross-check signerId
   *                      against a trusted source for full security).
   */
  verify(
    content: Uint8Array | string,
    signature: MajikSignature | MajikSignatureJSON | string,
    publicKeys?: MajikSignerPublicKeys,
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

      const result = MajikSignature.verify(content, sig, keys);

      const verifyResult: VerifyResult = {
        ...result,
        signerLabel: result.signerId?.trim()
          ? this.resolveSignerLabel(result.signerId)
          : undefined,
      };

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
   */
  verifyWithAccount(
    content: Uint8Array | string,
    signature: MajikSignature | MajikSignatureJSON | string,
    accountId: string,
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
    return this.verify(content, signature, publicKeys);
  }

  /**
   * Verify against a contact from the directory by their ID.
   * Useful when you have the signer's contact card stored locally.
   */
  async verifyWithContact(
    content: Uint8Array | string,
    signature: MajikSignature | MajikSignatureJSON | string,
    contactId: string,
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
      };
      this._emit("verify", result);
      return result;
    }

    const edPublicKeyBase64 =
      sig instanceof MajikSignature
        ? sig.signerEdPublicKey
        : (sig as MajikSignatureJSON).signerEdPublicKey;

    const mlDsaPublicKeyBase64 =
      sig instanceof MajikSignature
        ? sig.signerMlDsaPublicKey
        : (sig as MajikSignatureJSON).signerMlDsaPublicKey;

    const publicKeys: MajikSignerPublicKeys = {
      signerId: contact.fingerprint,
      edPublicKey: base64ToUint8Array(edPublicKeyBase64),
      mlDsaPublicKey: base64ToUint8Array(mlDsaPublicKeyBase64),
    };

    return this.verify(content, sig, publicKeys);
  }

  /**
   * Batch verify multiple signatures against the same content.
   * Returns one VerifyResult per signature in the same order.
   */
  verifyBatch(
    content: Uint8Array | string,
    signatures: Array<MajikSignature | MajikSignatureJSON | string>,
    publicKeys?: MajikSignerPublicKeys,
  ): VerifyResult[] {
    return signatures.map((sig) => {
      try {
        return this.verify(content, sig, publicKeys);
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
   *   const sig = await majik.signText("Hello world", { contentType: "text/plain" });
   *   const b64 = sig.serialize(); // store alongside the text
   */
  async signText(
    text: string,
    options?: {
      contentType?: string;
      timestamp?: string;
      accountId?: string;
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
   *   const { serialized } = await majik.signAndDetach(docBytes, {
   *     contentType: "application/pdf",
   *   });
   *   await db.insert({ doc_id, signature: serialized });
   */
  async signAndDetach(
    content: Uint8Array | string,
    options?: {
      contentType?: string;
      timestamp?: string;
      accountId?: string;
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
   *   const result = await majik.verifyText("Hello world", sig, {
   *     contactId: "contact_abc",
   *   });
   *   if (result.valid) console.log("Authentic");
   */
  async verifyText(
    text: string,
    signature: MajikSignature | MajikSignatureJSON | string,
    options?: {
      contactId?: string;
      publicKeyBase64?: string;
      key?: MajikKey;
      expectedSignerId?: string;
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
   *   const row = await db.findOne({ doc_id });
   *   const result = await majik.verifyDetached(docBytes, row.signature, {
   *     contactId: row.signer_contact_id,
   *   });
   *   if (result.valid) console.log("Signed by", result.signerId);
   */
  async verifyDetached(
    content: Uint8Array | string,
    serializedSignature: string,
    options?: {
      contactId?: string;
      publicKeyBase64?: string;
      key?: MajikKey;
      expectedSignerId?: string;
    },
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

    return this.verifyContent(content, sig, options);
  }

  // ── Signature Serialization Helpers ──────────────────────────────────────────

  /**
   * Deserialize a base64 signature string into a MajikSignature client.
   *
   * @example
   *   const sig = majik.deserializeSignature(storedBase64);
   *   console.log(sig.signerId, sig.timestamp);
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
   *   const meta = majik.getSignatureMetadata(storedSig);
   *   if (meta) {
   *     const contact = majik.getContactByID(meta.signerId);
   *     console.log(`Signed by ${contact?.meta?.label ?? meta.signerId} at ${meta.timestamp}`);
   *   }
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
   *   const sig = await majik.signContent(documentBytes, { contentType: "application/pdf" });
   *   const b64 = sig.serialize(); // store alongside the document
   */
  async signContent(
    content: Uint8Array | string,
    options?: {
      contentType?: string;
      timestamp?: string;
      accountId?: string;
    },
  ): Promise<MajikSignature> {
    const id = options?.accountId ?? this.getActiveAccount()?.id;
    if (!id)
      throw new Error("No active account — call setActiveAccount() first");

    let key: ReturnType<typeof this._keys.get> | undefined;
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

      return await MajikSignature.sign(content, key, {
        contentType: options?.contentType,
        timestamp: options?.timestamp,
      });
    } catch (err) {
      this._emit("error", err, { context: "signContent" });
      throw err;
    } finally {
      if (shouldRelock) key?.lock();
    }
  }

  /**
   * Sign a file and embed the signature directly into it using the active account.
   *
   * @example
   *   const { blob: signedPdf } = await majik.signFile(pdfBlob);
   *
   * @example — non-active account
   *   const { blob } = await majik.signFile(wavBlob, { accountId: "acc_xyz" });
   */
  async signFile(
    file: Blob,
    options?: {
      contentType?: string;
      timestamp?: string;
      mimeType?: string;
      accountId?: string;
      expectedSigners?: ExpectedSigner[];
    },
  ): Promise<ReturnType<typeof MajikSignature.signFile>> {
    const id = options?.accountId ?? this.getActiveAccount()?.id;
    if (!id)
      throw new Error("No active account — call setActiveAccount() first");

    let key: ReturnType<typeof this._keys.get> | undefined;
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

      const signedResponse = await MajikSignature.signFile(file, key, {
        contentType: options?.contentType,
        timestamp: options?.timestamp,
        mimeType: options?.mimeType,
        expectedSigners: options?.expectedSigners,
      });

      return signedResponse;
    } catch (err) {
      this._emit("error", err, { context: "signFile" });
      throw err;
    } finally {
      if (shouldRelock) key?.lock();
    }
  }

  /**
   * Sign multiple file blobs with the active (or specified) account in one call.
   *
   * @example
   *   const results = await majik.batchSignFiles([
   *     { file: pdfBlob, contentType: "application/pdf" },
   *     { file: wavBlob, contentType: "audio/wav" },
   *     { file: mp4Blob, contentType: "video/mp4" },
   *   ]);
   *   for (const r of results) {
   *     if (r.error) console.error("Failed:", r.error.message);
   *     else await r2.put(key, await r.blob!.arrayBuffer());
   *   }
   */
  async batchSignFiles(
    files: Array<{
      file: Blob;
      contentType?: string;
      timestamp?: string;
      mimeType?: string;
    }>,
    options?: { accountId?: string },
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
    const id = options?.accountId ?? this.getActiveAccount()?.id;
    if (!id)
      throw new Error("No active account — call setActiveAccount() first");

    await this._keys.ensureUnlocked(id);
    const key = this._keys.get(id);
    if (!key) throw new Error(`Account not found in keystore: "${id}"`);
    if (!key.hasSigningKeys) {
      throw new Error(
        `Account "${id}" has no signing keys. ` +
          `Re-import via importAccountFromMnemonicBackup() to enable signing.`,
      );
    }

    return Promise.all(
      files.map(async ({ file, contentType, timestamp, mimeType }) => {
        try {
          const result = await MajikSignature.signFile(file, key, {
            contentType,
            timestamp,
            mimeType,
          });
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
      }),
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
   *   const result = await majik.verifyContent(docBytes, sig, { contactId: "contact_abc" });
   *   if (result.valid) console.log("Authentic, signed by:", result.signerId);
   */
  async verifyContent(
    content: Uint8Array | string,
    signature: MajikSignature | MajikSignatureJSON,
    options?: {
      contactId?: string;
      publicKeyBase64?: string;
      key?: MajikKey;
      expectedSignerId?: string;
    },
  ): Promise<VerificationResult> {
    try {
      const publicKeys = await this._resolveSignerPublicKeys(options);

      if (publicKeys) {
        return MajikSignature.verify(content, signature, publicKeys);
      }

      // No signer provided — extract keys from envelope (self-reported)
      const sig =
        signature instanceof MajikSignature
          ? signature
          : MajikSignature.fromJSON(signature);

      return MajikSignature.verify(content, sig, sig.extractPublicKeys());
    } catch (err) {
      this._emit("error", err, { context: "verifyContent" });
      throw err;
    }
  }

  /**
   * Verify a file's embedded signature.
   *
   * @example — verify a signed PDF against a known contact
   *   const result = await majik.verifyFile(signedPdf, { contactId: "contact_abc" });
   *   if (result.valid) console.log("Verified:", result.signerId, result.timestamp);
   */
  async verifyFile(
    file: Blob,
    options?: {
      contactId?: string;
      publicKeyBase64?: string;
      key?: MajikKey;
      expectedSignerId?: string;
      mimeType?: string;
    },
  ): Promise<VerificationResult & { handler?: string; reason?: string }> {
    try {
      const publicKeys = await this._resolveSignerPublicKeys(options);

      if (publicKeys) {
        const results = await MajikSignature.verifyFile(
          file,
          publicKeys,
          {
            expectedSignerId: options?.expectedSignerId,
            mimeType: options?.mimeType,
          },
          true,
        );
        return results[0];
      }

      // No signer provided — extract and use self-reported keys from first signature.
      const extracted = await MajikSignature.extractFrom(file, {
        mimeType: options?.mimeType,
      });
      if (!extracted.length) {
        return {
          valid: false,
          signerId: "",
          contentHash: "",
          timestamp: new Date().toISOString(),
          reason: "No embedded signature found",
        };
      }

      const firstSig = extracted[0];
      const results = await MajikSignature.verifyFile(
        file,
        firstSig.extractPublicKeys(),
        {
          expectedSignerId: firstSig.signerId,
          mimeType: options?.mimeType,
        },
        true,
      );
      return results[0];
    } catch (err) {
      this._emit("error", err, { context: "verifyFile" });
      throw err;
    }
  }

  /**
   * Verify multiple files' embedded signatures against the same signer in
   * one call.
   *
   * @example
   *   const results = await majik.batchVerifyFiles(
   *     [pdfBlob, wavBlob, mp4Blob],
   *     { contactId: "contact_abc" },
   *   );
   *   const allValid = results.every(r => r.valid);
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
    },
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

            const firstSig = extracted[0];
            const results = await MajikSignature.verifyFile(
              file,
              firstSig.extractPublicKeys(),
              { mimeType, expectedSignerId: firstSig.signerId },
            );
            result = results[0];
          }

          return {
            ...result,
            handler: result.handler,
            mimeType,
            error: null,
          };
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
   */
  async extractSignature(
    file: Blob,
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
   */
  async stripSignature(
    file: Blob,
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
   */
  async isFileSigned(
    file: Blob,
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
   *   const myKeys = await majik.getSigningPublicKeys();
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
   *   const { blob } = await majik.resignFile(oldSignedPdf);
   *   await r2.put(key, await blob.arrayBuffer());
   */
  async resignFile(
    file: Blob,
    options?: {
      contentType?: string;
      timestamp?: string;
      mimeType?: string;
      accountId?: string;
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
   *   const info = await majik.getFileSignatureInfo(pdfBlob);
   *   if (info) {
   *     const contact = majik.getContactByID(info.signerId);
   *     console.log(`Signed by ${contact?.meta?.label ?? info.signerId}`);
   *   }
   */
  async getFileSignatureInfo(
    file: Blob,
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
   *   const { blob } = await majik.signFile(file, {
   *     expectedSigners: [
   *       MajikSignatureClient.expectedSignerFromKey(aliceKey),
   *       MajikSignatureClient.expectedSignerFromKey(bobKey),
   *     ],
   *   });
   */
  static expectedSignerFromKey(key: MajikKey): ExpectedSigner {
    return MajikSignature.expectedSignerFromKey(key);
  }

  /**
   * Get the allowlist from a file without verifying any signatures.
   * Returns null for open-signing files or unsigned files.
   */
  async getAllowlist(
    file: Blob,
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
   */
  async canSign(
    file: Blob,
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
   */
  async isMultiSig(
    file: Blob,
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
   */
  async getSignatories(
    file: Blob,
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

  async getSignedSignatories(
    file: Blob,
    options?: { mimeType?: string },
  ): Promise<SignatoriesResult | null> {
    try {
      return MajikSignature.getSignedSignatories(file, options);
    } catch (err) {
      this._emit("error", err, { context: "getSignedSignatories" });
      throw err;
    }
  }

  async getPendingSignatories(
    file: Blob,
    options?: { mimeType?: string },
  ): Promise<SignatoriesResult | null> {
    try {
      return MajikSignature.getPendingSignatories(file, options);
    } catch (err) {
      this._emit("error", err, { context: "getPendingSignatories" });
      throw err;
    }
  }

  async getAllSignatories(
    file: Blob,
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
   */
  async getIssuer(
    file: Blob,
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
   */
  async getEnvelopeInfo(
    file: Blob,
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
   *   const { blob, sealInfo } = await majik.seal(signedFile);
   *   console.log("Sealed at", sealInfo.sealTimestamp);
   */
  async seal(
    file: Blob,
    options?: { mimeType?: string; timestamp?: string; accountId?: string },
  ): Promise<ReturnType<typeof MajikSignature.seal>> {
    const id = options?.accountId ?? this.getActiveAccount()?.id;
    if (!id)
      throw new Error("No active account — call setActiveAccount() first");

    let key: ReturnType<typeof this._keys.get> | undefined;
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

      return await MajikSignature.seal(file, key, {
        mimeType: options?.mimeType,
        timestamp: options?.timestamp,
      });
    } catch (err) {
      this._emit("error", err, { context: "seal" });
      throw err;
    } finally {
      if (shouldRelock) key?.lock();
    }
  }

  /**
   * Verify the seal hash against the current signatories and seal timestamp.
   */
  async verifySeal(
    file: Blob,
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
   */
  async getSealInfo(
    file: Blob,
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
   */
  async isSealed(
    file: Blob,
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

  async createStamp(
    data: Uint8Array | ArrayBuffer,
    kind: StampAssetKind,
    name: string,
    options?: { mimeType?: string; accountId?: string },
  ): Promise<MajikSignatureStamp> {
    try {
      const identity = this._resolveStampIdentity(options?.accountId);
      const stamp = await this._stamps.create({
        data,
        identity,
        kind,
        name,
        mimeType: options?.mimeType,
      });
      this._emit("new-stamp", stamp);
      return stamp;
    } catch (err) {
      this._emit("error", err, { context: "createStamp" });
      throw err;
    }
  }

  listStamps(kind?: StampAssetKind): MajikSignatureStamp[] {
    return kind ? this._stamps.listByKind(kind) : this._stamps.list();
  }

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

  lockStamps(): void {
    this._stamps.lockAll();
  }

  getDecryptedStampBytes(id: string): Uint8Array | undefined {
    return this._stamps.get(id)?.decryptedBytes;
  }

  listStampsForActiveAccount(kind?: StampAssetKind): MajikSignatureStamp[] {
    const key = this.getActiveAccountKey();
    if (!key) return [];
    const all = kind ? this._stamps.listByKind(kind) : this._stamps.list();
    return all.filter((s) => s.fingerprint === key.fingerprint);
  }

  async getStamp(id: string): Promise<MajikSignatureStamp | null> {
    return this._stamps.load(id);
  }

  async decryptStampContent(
    id: string,
    accountId?: string,
  ): Promise<Uint8Array> {
    const identity = this._resolveStampIdentity(accountId);
    return this._stamps.decryptContent(id, identity);
  }

  async renameStamp(id: string, newName: string): Promise<MajikSignatureStamp> {
    return this._stamps.rename(id, newName);
  }

  async replaceStampContent(
    id: string,
    data: Uint8Array | ArrayBuffer,
    options?: { mimeType?: string; accountId?: string },
  ): Promise<MajikSignatureStamp> {
    const identity = this._resolveStampIdentity(options?.accountId);
    const raw = data instanceof Uint8Array ? data : new Uint8Array(data);
    return this._stamps.replaceContent(id, raw, identity, options?.mimeType);
  }

  async removeStamp(id: string): Promise<boolean> {
    const existed = await this._stamps.has(id);
    if (!existed) return false;
    await this._stamps.delete(id);
    this._emit("removed-stamp", id);
    return true;
  }

  // ── STAMP (compression-resistant image signing) ───────────────────────────

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

  static async verifyStamp(
    image: Blob,
    options?: { hammingThreshold?: number },
  ): Promise<ImageVerificationResult> {
    return MajikSignature.verifyStamp(image, options);
  }

  static async inspectStamp(image: Blob): Promise<{
    hasPixelRow: boolean;
    hasDct: boolean;
    pixelRowMeta?: { signerId: string; timestamp: string };
    dctMeta?: { signerId: string; timestamp: string; pHash: string };
  }> {
    return MajikSignature.inspectStamp(image);
  }

  static async isStamped(image: Blob): Promise<boolean> {
    return MajikSignature.isStamped(image);
  }

  // ── Private: Signer resolution ────────────────────────────────────────────

  private async _resolveSignerPublicKeys(options?: {
    contactID?: string;
    address?: MajikKeyAddress;
    key?: MajikKey;
    expectedSignerId?: string;
  }): Promise<MajikSignerPublicKeys | null> {
    if (!options) return null;

    // Option A: caller passed a MajikKey instance directly
    if (options.key) {
      return MajikSignature.publicKeysFromMajikKey(options.key);
    }

    // Option B: contact ID looked up from the contact directory
    if (options.contactID) {
      const contact = this._contacts.getContact(options.contactID);
      if (!contact) {
        throw new Error(`No contact found for id "${options.contactID}"`);
      }

      // Own accounts are in the keystore — get their signing keys directly
      const ownAccount = this.getOwnAccountById(options.contactID);
      if (ownAccount) {
        const key = this.keyManager.get(options.contactID);
        if (key?.hasSigningKeys) {
          return MajikSignature.publicKeysFromMajikKey(key);
        }
      }

      // External contact — resolve from their contact card fields
      if (!contact.edPublicKeyBase64 || !contact.mlDsaPublicKeyBase64) {
        throw new Error(
          `Contact "${options.contactID}" has no signing public keys. ` +
            `They may need to share an updated contact card.`,
        );
      }

      return {
        signerId: contact.fingerprint,
        edPublicKey: base64ToUint8Array(contact.edPublicKeyBase64),
        mlDsaPublicKey: base64ToUint8Array(contact.mlDsaPublicKeyBase64),
      };
    }

    // Option C: raw base64 public key — look up via contact directory
    if (options.address) {
      const contact = await this._contacts.getContactByAddress(options.address);
      if (!contact) {
        throw new Error(`No contact found for public key "${options.address}"`);
      }

      if (!contact.edPublicKeyBase64 || !contact.mlDsaPublicKeyBase64) {
        throw new Error(
          `Contact for key "${options.address}" has no signing public keys.`,
        );
      }

      return {
        signerId: contact.fingerprint,
        edPublicKey: base64ToUint8Array(contact.edPublicKeyBase64),
        mlDsaPublicKey: base64ToUint8Array(contact.mlDsaPublicKeyBase64),
      };
    }

    return null;
  }

  /**
   * Resolve a MajikFileIdentity from an unlocked account, for stamp
   * encryption/decryption. Requires the account to have ML-KEM keys and
   * to already be unlocked — call ensureIdentityUnlocked() first if needed.
   */
  private _resolveStampIdentity(accountId?: string): MajikFileIdentity {
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

  // ==========================================================================
  // ── Backup App Data ───────────────────────────────────────────────────────
  // ==========================================================================

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

  async readStampsBackup(
    input: Blob | ArrayBufferLike | ArrayBufferView,
  ): Promise<MajikSignatureStampJSON[]> {
    return this._parseStampsBackup(input);
  }

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

  async readContactsBackup(
    input: Blob | ArrayBufferLike | ArrayBufferView,
  ): Promise<ContactManagerSnapshot> {
    return this._parseContactsBackup(input);
  }

  /**
   * Restores all data from a full backup blob produced by `backupAppData()`.
   */
  async restoreAppData(blob: Blob): Promise<{
    contacts: number;
    groups: number;
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

    return {
      contacts: contacts.length,
      groups: groups.filter((g) => !g.isSystem).length,
    };
  }

  /**
   * Probes the first bytes of a blob and returns which backup type it is,
   * without fully parsing it.
   */
  static async probeBackupType(
    blob: Blob,
  ): Promise<"stamps" | "contacts" | "appData" | "unknown"> {
    const header = new Uint8Array(
      await blob.slice(0, MAJIK_MESSAGE_BACKUP_MAGIC_SIZE).arrayBuffer(),
    );

    for (const [type, magic] of Object.entries(
      MAJIK_SIGNATURE_BACKUP_MAGIC,
    ) as [keyof typeof MAJIK_SIGNATURE_BACKUP_MAGIC, Uint8Array][]) {
      if (magic.every((byte, i) => header[i] === byte)) return type;
    }

    return "unknown";
  }

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

  async readAppDataBackup(
    input: Blob | ArrayBufferLike | ArrayBufferView,
  ): Promise<AppDataSnapshot> {
    return this._parseAppDataBackup(input);
  }

  /**
   * Restores selected sections from an app data backup snapshot.
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
      invoiceDefaults: defaultsRestored,
      preferences: preferencesRestored,
    };

    this._emit("restore-backup", restoredData);

    return restoredData;
  }
}
