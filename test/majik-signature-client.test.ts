import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { MajikKey } from "@majikah/majik-key";
import { MajikContact } from "@majikah/majik-contact";
import {
  MajikSignature,
  MajikSignatureEnvelope,
} from "@majikah/majik-signature";

import {
  MajikSignatureClient,
  type MjksMapVerifyResult,
} from "../src/majik-signature-client";
import { getTestKey } from "./helpers/crypto";
import {
  HistorySources,
  HistoryStatuses,
  HistoryTypes,
} from "../src/core/log/core/enums";
import { arrayToBase64 } from "../src/core/utils/utilities";

// MajikKeyClient uses window.setTimeout/window.clearTimeout for account-order
// persistence. Vitest runs in Node by default, where the timer APIs live on
// globalThis instead of window. This aliases the real global object; it does
// not mock or spy on any API.
const nodeGlobal = globalThis as typeof globalThis & {
  window?: typeof globalThis;
};
if (!("window" in nodeGlobal)) {
  Object.defineProperty(nodeGlobal, "window", {
    configurable: true,
    value: nodeGlobal,
  });
}

const __currentDir = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__currentDir, "fixtures");

const DUMMY_CONTENT = "Hello, post-quantum world!";
const ALICE_LABEL = "Alice";
const BOB_LABEL = "Bob";
const CAROL_LABEL = "Carol";
const DAVE_LABEL = "Dave";

interface FileFixture {
  label: string;
  file: string;
  contentType: string;
}

const FILE_FIXTURES: FileFixture[] = [
  { label: "Plain Text", file: "sample.txt", contentType: "text/plain" },
  { label: "WEBP Image", file: "sample.webp", contentType: "image/webp" },
  { label: "PNG Image", file: "sample.png", contentType: "image/png" },
  { label: "JPEG Image", file: "sample.jpg", contentType: "image/jpg" },
  { label: "MP4 Video", file: "sample.mp4", contentType: "video/mp4" },
  { label: "MOV Video", file: "sample.mov", contentType: "video/mov" },
  { label: "MKV Video", file: "sample.mkv", contentType: "video/x-matroska" },
  { label: "WAV Audio", file: "sample.wav", contentType: "audio/wav" },
  { label: "FLAC Audio", file: "sample.flac", contentType: "audio/flac" },
  { label: "MP3 Audio", file: "sample.mp3", contentType: "audio/mp3" },
  {
    label: "Word Document",
    file: "sample.docx",
    contentType:
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  },
  {
    label: "Excel Spreadsheet",
    file: "sample.xlsx",
    contentType:
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  },
  { label: "CSV File", file: "sample.csv", contentType: "text/csv" },
  { label: "PDF Document", file: "sample.pdf", contentType: "application/pdf" },
];

function loadFixture(filename: string): Uint8Array {
  return new Uint8Array(readFileSync(join(FIXTURES_DIR, filename)));
}

function blobFromText(text: string, type = "text/plain"): Blob {
  return new Blob([text], { type });
}

async function flushAsyncWork(): Promise<void> {
  await new Promise<void>((resolve) => setTimeout(resolve, 0));
}

/**
 * Build a real MajikContact from a real MajikKey.
 *
 * This intentionally uses MajikContact.create() rather than a cast/fake object.
 * The signing public-key strings come from the real expected-signer representation
 * produced by MajikSignature.
 */
function contactFromKey(key: MajikKey, label: string): MajikContact {
  const expected = MajikSignature.expectedSignerFromKey(key);

  return MajikContact.create(
    key.id,
    key.publicKey,
    arrayToBase64(key.mlKemPublicKey),
    key.fingerprint,
    {
      label,
      notes: "",
      blocked: false,
    },
    expected.edPublicKey,
    expected.mlDsaPublicKey,
  );
}

/**
 * Put a real key into the real keystore and register its real contact as
 * an own account. No mocks, spies, or fake key/contact objects are involved.
 */
async function installOwnAccount(
  client: MajikSignatureClient,
  key: MajikKey,
  label: string,
): Promise<MajikContact> {
  await client.keyManager.save(key);

  const contact = contactFromKey(key, label);
  client.addOwnAccount(contact);
  //   await client.addContact(contact);
  await client.setActiveAccount(key.id, true);

  return contact;
}

async function installExternalContact(
  client: MajikSignatureClient,
  key: MajikKey,
  label: string,
): Promise<MajikContact> {
  const contact = contactFromKey(key, label);
  await client.addContact(contact);
  return contact;
}

async function getFirstSignature(
  client: MajikSignatureClient,
  signedFile: Blob,
): Promise<MajikSignature> {
  const signatures = await client.extractSignature(signedFile);
  expect(signatures.length).toBeGreaterThan(0);
  return signatures[0];
}

describe("MajikSignatureClient — comprehensive real-crypto unit/integration suite", () => {
  let keyA: MajikKey;
  let keyB: MajikKey;
  let keyC: MajikKey;
  let keyD: MajikKey;

  beforeAll(async () => {
    [keyA, keyB, keyC, keyD] = await Promise.all([
      getTestKey(),
      getTestKey(),
      getTestKey(),
      getTestKey(),
    ]);
  }, 120000);

  describe("Initialization, hydration, managers & events", () => {
    it("creates and hydrates with default in-memory adapters", async () => {
      const client = await MajikSignatureClient.create({});

      expect(client).toBeInstanceOf(MajikSignatureClient);
      expect(client.keyManager).toBeDefined();
      expect(client.stateManager).toBeDefined();
      expect(client.stampManager).toBeDefined();
      expect(client.historyManager).toBeDefined();
      expect(client.activityManager).toBeDefined();
      expect(await client.getUserAppPreferences()).toBeDefined();
    });

    it("hydrates an already-constructed client without throwing", async () => {
      const client = new MajikSignatureClient({});

      await expect(client.hydrate()).resolves.toBeUndefined();
    });

    it("registers and removes typed domain events through the real event system", async () => {
      const client = await MajikSignatureClient.create({});
      const seen: Array<{ event: string; payload: unknown }> = [];

      client.on("new-contact", (contact) =>
        seen.push({ event: "new-contact", payload: contact }),
      );
      client.on("new-contact-group", (group) =>
        seen.push({ event: "new-contact-group", payload: group }),
      );
      client.on("contact-group-change", (group) =>
        seen.push({ event: "contact-group-change", payload: group }),
      );
      client.on("removed-contact-group", (group) =>
        seen.push({ event: "removed-contact-group", payload: group }),
      );
      client.on("sign", (result) =>
        seen.push({ event: "sign", payload: result }),
      );
      client.on("verify", (result) =>
        seen.push({ event: "verify", payload: result }),
      );

      const contact = await installExternalContact(client, keyD, DAVE_LABEL);
      await client.createGroup("events-group", "Events");
      await client.addContactToGroup("events-group", contact.id);
      await client.removeContactFromGroup("events-group", contact.id);
      await client.removeGroup("events-group");

      expect(seen.map((entry) => entry.event)).toEqual(
        expect.arrayContaining([
          "new-contact",
          "new-contact-group",
          "contact-group-change",
          "removed-contact-group",
        ]),
      );

      await installOwnAccount(client, keyA, ALICE_LABEL);

      await client.sign(DUMMY_CONTENT, { contentType: "text/plain" });
      const signature = await client.signContent(DUMMY_CONTENT, {
        contentType: "text/plain",
      });
      client.verify(DUMMY_CONTENT, signature);

      expect(seen.map((entry) => entry.event)).toEqual(
        expect.arrayContaining(["sign", "verify"]),
      );

      const signEvent = seen.find((entry) => entry.event === "sign");
      expect(signEvent?.payload).toBeDefined();
    });

    it("supports off(event, callback) and off(event) without spies", async () => {
      const client = await MajikSignatureClient.create({});
      let callbackCount = 0;

      const callback = () => {
        callbackCount += 1;
      };

      client.on("new-contact", callback);
      await installExternalContact(client, keyB, BOB_LABEL);
      expect(callbackCount).toBe(1);

      client.off("new-contact", callback);
      await installExternalContact(client, keyC, CAROL_LABEL);
      expect(callbackCount).toBe(1);

      const otherCallback = () => {
        callbackCount += 1;
      };
      client.on("new-contact", otherCallback);
      client.off("new-contact");
      await installExternalContact(client, keyD, DAVE_LABEL);
      expect(callbackCount).toBe(1);
    });
  });

  describe("Account and identity management inherited from MajikKeyClient", () => {
    let client: MajikSignatureClient;

    beforeEach(async () => {
      client = await MajikSignatureClient.create({});
    });

    it("generates a real mnemonic", async () => {
      const mnemonic = await client.generateMnemonic(128, "en");

      expect(typeof mnemonic).toBe("string");
      expect(mnemonic.trim().split(/\s+/)).toHaveLength(12);
    });

    it("creates a real account, exports its mnemonic backup, locks, verifies, and unlocks", async () => {
      const mnemonic = await client.generateMnemonic(128, "en");
      const passphrase = "client-test-passphrase";

      const created = await client.createAccount(
        mnemonic,
        passphrase,
        "Generated Account",
      );

      await client.setActiveAccount(created.id, true);

      expect(created.id).toBeTruthy();
      expect(created.fingerprint).toBeTruthy();
      expect(created.backup).toBeTruthy();
      expect(await client.hasOwnIdentity(created.fingerprint)).toBe(true);

      const ownContact = client.getOwnAccountById(created.id);
      expect(ownContact?.meta.label).toBe("Generated Account");

      const exportedBackup = await client.exportAccountMnemonicBackup(
        created.id,
        mnemonic,
      );
      const parsedCreated = JSON.parse(atob(created.backup));
      const parsedExported = JSON.parse(atob(exportedBackup));

      expect(parsedExported.id).toBe(parsedCreated.id);
      expect(parsedExported.fingerprint).toBe(parsedCreated.fingerprint);
      expect(parsedExported.iv).not.toBe(parsedCreated.iv);

      client.lockAccount(created.id);
      expect(await client.verifyPassphrase(created.id, passphrase)).toBe(true);

      await client.unlockAccount(created.id, passphrase);
      expect(client.getActiveAccountKey()?.isLocked).toBe(false);
    });

    it("imports a mnemonic backup into the real keystore", async () => {
      const sourceClient = await MajikSignatureClient.create({});
      const mnemonic = await sourceClient.generateMnemonic(128, "en");
      const passphrase = "import-passphrase";

      const created = await sourceClient.createAccount(
        mnemonic,
        passphrase,
        "Source",
      );

      const backup = await sourceClient.exportAccountMnemonicBackup(
        created.id,
        mnemonic,
      );

      const target = await MajikSignatureClient.create({});
      const imported = await target.importAccountFromMnemonicBackup(
        backup,
        mnemonic,
        passphrase,
        "Imported",
      );

      expect(imported.id).toBe(created.id);
      expect(imported.fingerprint).toBe(created.fingerprint);
      expect(target.getOwnAccountById(imported.id)?.meta.label).toBe(
        "Imported",
      );
    });

    it("rejects duplicate imported account IDs", async () => {
      const mnemonic = await client.generateMnemonic(128, "en");
      const passphrase = "duplicate-pass";

      const created = await client.createAccount(
        mnemonic,
        passphrase,
        "Original",
      );
      const backup = await client.exportAccountMnemonicBackup(
        created.id,
        mnemonic,
      );

      await expect(
        client.importAccountFromMnemonicBackup(
          backup,
          mnemonic,
          passphrase,
          "Duplicate",
        ),
      ).rejects.toThrow("Account with the same ID already exists");
    });

    it("updates own-account metadata through the contact directory and keystore", async () => {
      const contact = await installOwnAccount(client, keyA, ALICE_LABEL);

      await client.updateOwnAccountMeta(contact.id, {
        label: "Alice Updated",
        notes: "Updated from test",
      });

      expect(client.getOwnAccountById(contact.id)?.meta.label).toBe(
        "Alice Updated",
      );
      expect(client.getContactByID(contact.id)?.meta.notes).toBe(
        "Updated from test",
      );
    });

    it("rejects metadata updates for missing own accounts", async () => {
      await expect(
        client.updateOwnAccountMeta("missing-account", { label: "Nope" }),
      ).rejects.toThrow('Account not found in own accounts: "missing-account"');
    });

    it("resolves own identity existence by fingerprint", async () => {
      await installOwnAccount(client, keyA, ALICE_LABEL);

      expect(await client.hasOwnIdentity(keyA.fingerprint)).toBe(true);
      expect(await client.hasOwnIdentity("missing-fingerprint")).toBe(false);
    });
  });

  describe("Contact directory", () => {
    let client: MajikSignatureClient;
    let contactA: MajikContact;
    let contactB: MajikContact;

    beforeEach(async () => {
      client = await MajikSignatureClient.create({});
      contactA = await installExternalContact(client, keyA, ALICE_LABEL);
      contactB = await installExternalContact(client, keyB, BOB_LABEL);
    });

    it("adds, finds and checks contacts by ID", () => {
      expect(client.hasContact(contactA.id)).toBe(true);
      expect(client.getContactByID(contactA.id)).toBe(contactA);
      expect(client.getContactByID("missing")).toBeNull();
    });

    it("finds contacts by address and public keys", async () => {
      const address = await contactA.getAddress();

      expect(await client.hasContactByAddress(address)).toBe(true);
      expect(await client.getContactByAddress(address)).toBe(contactA);

      const contacts = await client.getContactsByPublicKey([address]);
      expect(contacts.map((c) => c.id)).toContain(contactA.id);
    });

    it("finds contacts by ID list with strict and non-strict modes", () => {
      const ids = [contactA.id, contactB.id];

      expect(client.getContactsByID(ids, false).map((c) => c.id)).toEqual(
        expect.arrayContaining([contactA.id, contactB.id]),
      );

      expect(client.getContactsByID(ids, true).map((c) => c.id)).toEqual([
        contactA.id,
        contactB.id,
      ]);
    });

    it("exports and round-trips contacts through JSON", async () => {
      const json = await client.exportContactAsJSON(contactA.id);
      const serialized = await client.exportContactAsString(contactA.id);

      expect(json).toBeTruthy();
      expect(serialized).toBeTruthy();

      await client.removeContact(contactA.id);
      expect(client.hasContact(contactA.id)).toBe(false);

      const imported = await client.importContactFromJSON(json!);
      expect(imported.success).toBe(true);
      expect(client.hasContact(contactA.id)).toBe(true);

      await client.removeContact(contactA.id);

      const importedString = await client.importContactFromString(serialized!);
      expect(importedString.success).toBe(true);
      expect(client.hasContact(contactA.id)).toBe(true);
    });

    it("exports and round-trips contacts through compressed representation", async () => {
      const compressed = await client.exportContactCompressed(contactA);

      expect(compressed).toBeTruthy();

      await client.removeContact(contactA.id);
      expect(client.hasContact(contactA.id)).toBe(false);

      const imported = await client.importContactCompressed(compressed);
      expect(imported).toBeInstanceOf(MajikContact);
      expect(imported.id).toBe(contactA.id);
      expect(imported.fingerprint).toBe(contactA.fingerprint);

      // `importContactCompressed()` decodes the contact; registering it in the
      // directory is a separate operation exposed by `addContact()`.
      await client.addContact(imported);
      expect(client.hasContact(contactA.id)).toBe(true);
    });

    it("updates contact metadata", async () => {
      await client.updateContactMeta(contactA.id, {
        label: "Renamed Alice",
        notes: "trusted",
      });

      const updated = client.getContactByID(contactA.id)!;
      expect(updated.meta.label).toBe("Renamed Alice");
      expect(updated.meta.notes).toBe("trusted");
    });

    it("lists contacts with and without own accounts", async () => {
      const ownClient = await MajikSignatureClient.create({});
      await installOwnAccount(ownClient, keyC, CAROL_LABEL);
      await installExternalContact(ownClient, keyD, DAVE_LABEL);

      expect(ownClient.listContacts(false).map((c) => c.id)).toEqual([keyD.id]);
      expect(ownClient.listContacts(true).map((c) => c.id)).toEqual(
        expect.arrayContaining([keyC.id, keyD.id]),
      );
    });

    it("rejects invalid contact arguments", async () => {
      expect(() => client.getContactByID(" ")).toThrow("Invalid contact ID");
      expect(() => client.hasContact(" ")).toThrow("Invalid contact ID");

      await expect(client.getContactByAddress(" ")).rejects.toThrow(
        "Invalid public key address",
      );
      await expect(client.hasContactByAddress(" ")).rejects.toThrow(
        "Invalid contact public key address",
      );
      expect(() => client.getContactsByID([])).toThrow(
        "At least 1 id is required",
      );
      await expect(client.getContactsByPublicKey([])).rejects.toThrow(
        "At least 1 public key is required",
      );
      await expect(client.importContactFromString("")).rejects.toThrow(
        "Invalid contact string",
      );
      await expect(client.importContactCompressed("")).rejects.toThrow(
        "Invalid contact string",
      );
    });

    it("removes contacts and clears the directory", async () => {
      await client.removeContact(contactA.id);
      expect(client.hasContact(contactA.id)).toBe(false);

      await client.clearDirectory();
      expect(client.listContacts(true)).toHaveLength(0);
    });
  });

  describe("Contact groups, favorites and blocked directory", () => {
    let client: MajikSignatureClient;
    let contactA: MajikContact;
    let contactB: MajikContact;

    beforeEach(async () => {
      client = await MajikSignatureClient.create({});
      contactA = await installExternalContact(client, keyA, ALICE_LABEL);
      contactB = await installExternalContact(client, keyB, BOB_LABEL);
    });

    it("creates, adds and queries user groups", async () => {
      const returned = await client.createGroup(
        "engineering",
        "Engineering",
        { description: "Developers" },
        [contactA.id],
      );

      expect(returned).toBe(client);
      expect(client.hasGroup("engineering")).toBe(true);
      expect(client.getContactGroup("engineering")?.meta.name).toBe(
        "Engineering",
      );
      expect(
        client.getContactsInGroup("engineering").map((c) => c.id),
      ).toContain(contactA.id);
      expect(
        client.getContactsInGroupSorted("engineering").map((c) => c.id),
      ).toContain(contactA.id);
    });

    it("adds and removes group membership through all public helpers", async () => {
      await client.createGroup("engineering-2", "Engineering 2");

      await client.addContactToGroup("engineering-2", contactA.id);
      await client.addContactsToGroup("engineering-2", [contactB.id]);

      expect(client.isContactInGroup("engineering-2", contactA.id)).toBe(true);
      expect(client.isContactInGroup("engineering-2", contactB.id)).toBe(true);
      expect(
        client.getGroupsForContact(contactA.id).map((g) => g.id),
      ).toContain("engineering-2");
      expect(client.getGroupIdsForContact(contactA.id)).toContain(
        "engineering-2",
      );

      await client.removeContactFromGroup("engineering-2", contactA.id);
      expect(client.isContactInGroup("engineering-2", contactA.id)).toBe(false);

      await client.createGroup("engineering-3", "Engineering 3");
      await client.moveContactBetweenGroups(
        contactB.id,
        "engineering-2",
        "engineering-3",
      );

      expect(client.isContactInGroup("engineering-3", contactB.id)).toBe(true);
      expect(client.isContactInGroup("engineering-2", contactB.id)).toBe(false);
    });

    it("adds/removes arbitrary groups", async () => {
      await client.createGroup("group-4", "Group 4");
      const group = client.getContactGroup("group-4");
      expect(group).toBeDefined();

      await client.removeGroup("group-4");
      expect(client.hasGroup("group-4")).toBe(false);

      await client.addGroup(group!);
      expect(client.hasGroup("group-4")).toBe(true);

      const response = await client.removeGroup("group-4");
      expect(response.success).toBe(true);
      expect(client.hasGroup("group-4")).toBe(false);
    });

    it("updates and lists groups", async () => {
      await client.createGroup("group-5", "Old Name");

      await client.updateGroupMeta("group-5", {
        name: "New Name",
        description: "New Description",
        color: "#EA7F05",
      });

      expect(client.getGroupOrThrow("group-5").meta.name).toBe("New Name");
      expect(
        client.listUserGroups().some((group) => group.id === "group-5"),
      ).toBe(true);
      expect(
        client.listContactGroups().some((group) => group.id === "group-5"),
      ).toBe(true);
      expect(client.listSystemGroups().every((group) => group.isSystem)).toBe(
        true,
      );
    });

    it("manages favorites and blocked contacts", async () => {
      await client.addContactToFavorites(contactA.id);
      expect(client.isContactFavorite(contactA.id)).toBe(true);
      expect(client.getFavoritesGroup().listMemberIds()).toContain(contactA.id);
      expect(client.getFavoriteContacts().map((c) => c.id)).toContain(
        contactA.id,
      );

      await client.removeContactFromFavorites(contactA.id);
      expect(client.isContactFavorite(contactA.id)).toBe(false);

      const blockedContact = MajikContact.create(
        "blocked-contact",
        keyB.publicKey,
        arrayToBase64(keyB.mlKemPublicKey),
        keyB.fingerprint,
        { label: "Blocked", blocked: true },
        MajikSignature.expectedSignerFromKey(keyB).edPublicKey,
        MajikSignature.expectedSignerFromKey(keyB).mlDsaPublicKey,
      );
      await client.addContact(blockedContact);

      const blockedGroup = client.getBlockedGroup();
      expect(blockedGroup.id).toBeDefined();

      // Block status is represented by membership in the system blocked group.
      await client.addContactToGroup(blockedGroup.id, blockedContact.id);

      expect(client.isContactBlocked(blockedContact.id)).toBe(true);
      expect(client.getBlockedContacts().map((c) => c.id)).toContain(
        blockedContact.id,
      );

      await client.removeContactFromGroup(blockedGroup.id, blockedContact.id);
      expect(client.isContactBlocked(blockedContact.id)).toBe(false);
    });
  });

  describe("User app preferences", () => {
    it("persists preference values and exposes all convenience getters", async () => {
      const client = await MajikSignatureClient.create({});

      const defaults = {
        analytics: await client.isAnalyticsEnabled(),
        autoSeal: await client.isAutoSealEnabled(),
        defaultToTSA: await client.isDefaultToTSAEnabled(),
        defaultToDetached: await client.isDefaultToDetachedEnabled(),
        autoLockOnMinimize: await client.isAutoLockOnMinimizeEnabled(),
        autoLockInterval: await client.autoLockInterval(),
        onetimeUnlock: await client.isOnetimeUnlockEnabled(),
        autoSaveAfterSign: await client.isAutoSaveAfterSignEnabled(),
        autoSaveAfterSeal: await client.isAutoSaveAfterSealEnabled(),
        autoSaveAfterNotarize: await client.isAutoSaveAfterNotarizeEnabled(),
      };

      const preferences = await client.getUserAppPreferences();

      preferences.privacy.shareAnalytics = true;
      preferences.signing.autoSeal = true;
      preferences.signing.defaultToTSA = true;
      preferences.signing.defaultToDetached = true;
      preferences.security ??= {};
      preferences.security.key ??= {};
      preferences.security.key.autoLockOnMinimize = true;
      preferences.security.key.autoLockInterval = 30;
      preferences.security.key.onetimeUnlock = false;
      preferences.signing.autosave = {
        afterSign: { enabled: true },
        afterSeal: { enabled: true },
        afterNotary: { enabled: true },
      };

      await client.setUserAppPreferences(preferences);

      expect(await client.isAnalyticsEnabled()).toBe(true);
      expect(await client.isAutoSealEnabled()).toBe(true);
      expect(await client.isDefaultToTSAEnabled()).toBe(true);
      expect(await client.isDefaultToDetachedEnabled()).toBe(true);
      expect(await client.isAutoLockOnMinimizeEnabled()).toBe(true);
      expect(await client.autoLockInterval()).toBe(30);
      expect(await client.isOnetimeUnlockEnabled()).toBe(false);
      expect(await client.isAutoSaveAfterSignEnabled()).toBe(true);
      expect(await client.isAutoSaveAfterSealEnabled()).toBe(true);
      expect(await client.isAutoSaveAfterNotarizeEnabled()).toBe(true);

      await client.removeUserAppPreferences();
      expect(await client.getUserAppPreferences()).toBeDefined();

      await client.resetUserAppPreferences();

      expect(await client.isAnalyticsEnabled()).toBe(defaults.analytics);
      expect(await client.isAutoSealEnabled()).toBe(defaults.autoSeal);
      expect(await client.isDefaultToTSAEnabled()).toBe(defaults.defaultToTSA);
      expect(await client.isDefaultToDetachedEnabled()).toBe(
        defaults.defaultToDetached,
      );
      expect(await client.isAutoLockOnMinimizeEnabled()).toBe(
        defaults.autoLockOnMinimize,
      );
      expect(await client.autoLockInterval()).toBe(defaults.autoLockInterval);
      expect(await client.isOnetimeUnlockEnabled()).toBe(
        defaults.onetimeUnlock,
      );
      expect(await client.isAutoSaveAfterSignEnabled()).toBe(
        defaults.autoSaveAfterSign,
      );
      expect(await client.isAutoSaveAfterSealEnabled()).toBe(
        defaults.autoSaveAfterSeal,
      );
      expect(await client.isAutoSaveAfterNotarizeEnabled()).toBe(
        defaults.autoSaveAfterNotarize,
      );
    });
  });

  describe("History and activity logs", () => {
    let client: MajikSignatureClient;

    beforeEach(async () => {
      client = await MajikSignatureClient.create({});
      await installOwnAccount(client, keyA, ALICE_LABEL);
    });

    it("records history and activity through real signing/contact actions", async () => {
      const external = await installExternalContact(client, keyB, BOB_LABEL);

      await client.sign(DUMMY_CONTENT, { contentType: "text/plain" });
      await client.addContactToFavorites(external.id);

      await flushAsyncWork();

      const history = client.listHistoryForActiveAccount();
      const activity = client.listActivityForActiveAccount();

      expect(history.length).toBeGreaterThan(0);
      expect(activity.length).toBeGreaterThan(0);
      expect(
        history.some((entry) => entry.historyType === HistoryTypes.SIGN),
      ).toBe(true);
      expect(
        history.some((entry) => entry.status === HistoryStatuses.SUCCESS),
      ).toBe(true);
    });

    it("clears and restarts logs for the active account", async () => {
      await client.sign(DUMMY_CONTENT);
      await flushAsyncWork();

      expect(client.listHistoryForActiveAccount().length).toBeGreaterThan(0);

      await client.clearHistoryLogsForActiveAccount();
      await client.clearActivityLogsForActiveAccount();

      expect(client.listHistoryForActiveAccount()).toHaveLength(0);
      expect(client.listActivityForActiveAccount()).toHaveLength(0);

      await client.restartLogsForActiveAccount();
      await flushAsyncWork();

      const activity = client.listActivityForActiveAccount();
      expect(activity).toHaveLength(1);
      expect(activity[0].reference_id).toBe("logs-restarted");
    });

    it("hydrates account-scoped logs after explicit hydration", async () => {
      await client.sign("hydrate logs");
      await flushAsyncWork();

      await expect(
        client.hydrateLogsForActiveAccount(),
      ).resolves.toBeUndefined();
      expect(client.listHistoryForActiveAccount().length).toBeGreaterThan(0);
    });

    it("rejects account-scoped log operations without an active account", async () => {
      const emptyClient = await MajikSignatureClient.create({});

      await expect(emptyClient.hydrateLogsForActiveAccount()).rejects.toThrow(
        "No active account — call setActiveAccount() first",
      );
      await expect(
        emptyClient.clearHistoryLogsForActiveAccount(),
      ).rejects.toThrow("No active account — call setActiveAccount() first");
      await expect(
        emptyClient.clearActivityLogsForActiveAccount(),
      ).rejects.toThrow("No active account — call setActiveAccount() first");
    });
  });

  describe("Core signing", () => {
    let client: MajikSignatureClient;

    beforeEach(async () => {
      client = await MajikSignatureClient.create({});
      await installOwnAccount(client, keyA, ALICE_LABEL);
      await installOwnAccount(client, keyB, BOB_LABEL);
      await client.setActiveAccount(keyA.id, true);
    });

    it("signs string content with real Ed25519 + ML-DSA signatures", async () => {
      const result = await client.sign(DUMMY_CONTENT, {
        contentType: "text/plain",
      });

      expect(result.signature).toBeInstanceOf(MajikSignature);
      expect(result.signerId).toBe(keyA.fingerprint);
      expect(result.contentHash).toBeTruthy();
      expect(result.timestamp).toBeTruthy();
      expect(result.signature.edSignature).toBeDefined();
      expect(result.signature.mlDsaSignature).toBeDefined();
    });

    it("supports signText, signAndSerialize and signToJSON", async () => {
      const textSignature = await client.signText("Hello text");
      expect(textSignature).toBeInstanceOf(MajikSignature);

      const serialized = await client.signAndSerialize("Hello serialized");
      expect(typeof serialized).toBe("string");

      const json = await client.signToJSON("Hello JSON");
      expect(json.signerId).toBe(keyA.fingerprint);

      await expect(client.signText("  ")).rejects.toThrow(
        "signText: text must be a non-empty string",
      );
    });

    it("supports signAndDetach and metadata/deserialize helpers", async () => {
      const detached = await client.signAndDetach("Detached payload");
      expect(detached.signature).toBeInstanceOf(MajikSignature);
      expect(typeof detached.serialized).toBe("string");

      const restored = client.deserializeSignature(detached.serialized);
      expect(restored).toBeInstanceOf(MajikSignature);
      expect(restored.signerId).toBe(keyA.fingerprint);

      const metadata = client.getSignatureMetadata(detached.serialized);
      expect(metadata?.signerId).toBe(keyA.fingerprint);
      expect(metadata?.contentHash).toBe(detached.signature.contentHash);
      expect(client.getSignatureMetadata("not-a-signature")).toBeNull();
    });

    it("signs content with an explicitly selected account", async () => {
      const result = await client.signContent("Signed by Bob", {
        accountId: keyB.id,
        contentType: "text/plain",
      });

      expect(result.signerId).toBe(keyB.fingerprint);
    });

    it("signs a file, extracts metadata, detects signing, and strips the signature", async () => {
      const source = blobFromText("File content", "text/plain");
      const { blob: signedBlob, signature } = await client.signFile(source, {
        contentType: "text/plain",
      });

      expect(signature.signerId).toBe(keyA.fingerprint);
      expect(
        await client.isFileSigned(signedBlob, { mimeType: "text/plain" }),
      ).toBe(true);

      const extracted = await client.extractSignature(signedBlob, {
        mimeType: "text/plain",
      });
      expect(extracted).toHaveLength(1);
      expect(extracted[0].contentHash).toBe(signature.contentHash);

      const info = await client.getFileSignatureInfo(signedBlob, {
        mimeType: "text/plain",
      });
      expect(info[0].signerId).toBe(keyA.fingerprint);

      const stripped = await client.stripSignature(signedBlob, {
        mimeType: "text/plain",
      });
      expect(
        await client.isFileSigned(stripped, { mimeType: "text/plain" }),
      ).toBe(false);
      expect(await stripped.text()).toBe("File content");
    });

    it("resigns an existing signed file", async () => {
      const original = blobFromText("Resign me");
      const first = await client.signFile(original, {
        contentType: "text/plain",
      });

      const second = await client.resignFile(first.blob, {
        contentType: "text/plain",
      });

      const signatures = await client.extractSignature(second.blob);
      expect(signatures).toHaveLength(1);
      expect(signatures[0].signerId).toBe(keyA.fingerprint);
    });

    it("rejects embedded verification after file bytes are tampered", async () => {
      const signed = await client.signFile(blobFromText("Tamper embedded"));

      const bytes = new Uint8Array(await signed.blob.arrayBuffer());
      bytes[0] ^= 0xff;

      const tampered = new Blob([bytes], { type: signed.blob.type });
      const results = await client.verifyFile(tampered, {
        key: keyA,
        mimeType: "text/plain",
      });

      //   expect(results.valid.length).toBeGreaterThan(0);
      expect(results.valid).toBe(false);
    });

    it("batch-signs files and returns isolated results for each file", async () => {
      const fixture1 = FILE_FIXTURES[0];
      const fixture2 = FILE_FIXTURES[4];
      const fixture3 = FILE_FIXTURES[5];

      const fileContent1 = loadFixture(fixture1.file);
      const fileContent2 = loadFixture(fixture2.file);
      const fileContent3 = loadFixture(fixture3.file);

      const blob1 = new Blob([fileContent1 as BlobPart], {
        type: fixture1.contentType,
      });

      const blob2 = new Blob([fileContent2 as BlobPart], {
        type: fixture2.contentType,
      });

      const blob3 = new Blob([fileContent3 as BlobPart], {
        type: fixture3.contentType,
      });

      const files = [
        {
          file: blob1,
          contentType: fixture1.contentType,
        },
        {
          file: blob2,
          contentType: fixture2.contentType,
        },
        {
          file: blob3,
          contentType: fixture3.contentType,
        },
      ];

      const results = await client.batchSignFiles(files);

      expect(results).toHaveLength(3);
      expect(results.every((result) => result.error === null)).toBe(true);
      expect(results.every((result) => result.signature)).toBe(true);

      for (const result of results) {
        expect(result.blob).toBeInstanceOf(Blob);
        expect(result.serialized).toBeTruthy();
      }
    });

    describe("File type signing", () => {
      it.each(FILE_FIXTURES)(
        "should sign $label ($file) content correctly",
        async ({ file, contentType }) => {
          const fileContent = loadFixture(file);
          const blob = new Blob([fileContent as BlobPart], {
            type: contentType,
          });
          const { signature } = await client.signFile(blob, {
            contentType,
          });

          expect(signature).toBeInstanceOf(MajikSignature);
          expect(signature.version).toBe(1);
          expect(signature.signerId).toBe(keyA.fingerprint);
          expect(signature.contentType).toBe(contentType);
          expect(signature.contentHash).toBeDefined();
          expect(signature.edSignature).toBeDefined();
          expect(signature.mlDsaSignature).toBeDefined();
        },
      );
    });
  });

  describe("Verification and trusted signer resolution", () => {
    let client: MajikSignatureClient;

    beforeEach(async () => {
      client = await MajikSignatureClient.create({});
      await installOwnAccount(client, keyA, ALICE_LABEL);
      await installExternalContact(client, keyB, BOB_LABEL);
      await client.setActiveAccount(keyA.id, true);
    });

    it("verifies valid content and rejects tampered content", async () => {
      const signature = await client.signContent(DUMMY_CONTENT);

      const valid = client.verify(DUMMY_CONTENT, signature);
      expect(valid.valid).toBe(true);
      expect(valid.signerId).toBe(keyA.fingerprint);

      const invalid = client.verify("Tampered content", signature);
      expect(invalid.valid).toBe(false);
    });

    it("verifies content through the higher-level verifyContent helper", async () => {
      const signature = await client.signContent("verifyContent payload");

      const result = await client.verifyContent(
        "verifyContent payload",
        signature,
        { contactId: keyA.id },
      );

      expect(result.valid).toBe(true);
      expect(result.signerId).toBe(keyA.fingerprint);
    });

    it("verifies with the local account's trusted public keys", async () => {
      const signature = await client.signContent(DUMMY_CONTENT);

      const result = client.verifyWithAccount(
        DUMMY_CONTENT,
        signature,
        keyA.id,
      );

      expect(result.valid).toBe(true);
      expect(result.signerId).toBe(keyA.fingerprint);
    });

    it("verifies with a real contact and resolves its label", async () => {
      const signature = await MajikSignature.sign(DUMMY_CONTENT, keyB, {
        contentType: "text/plain",
      });

      const result = await client.verifyWithContact(
        DUMMY_CONTENT,
        signature,
        keyB.id,
      );

      expect(result.valid).toBe(true);
      expect(result.signerId).toBe(keyB.fingerprint);
      expect(result.signerLabel).toBe(BOB_LABEL);
    });

    it("rejects a contact verification when envelope signer and contact fingerprint differ", async () => {
      const signature = await MajikSignature.sign(DUMMY_CONTENT, keyB);

      const mismatched = MajikContact.create(
        "mismatched-contact",
        keyA.publicKey,
        arrayToBase64(keyA.mlKemPublicKey),
        keyA.fingerprint,
        { label: "Mismatched" },
        MajikSignature.expectedSignerFromKey(keyA).edPublicKey,
        MajikSignature.expectedSignerFromKey(keyA).mlDsaPublicKey,
      );

      await client.addContact(mismatched);

      const result = await client.verifyWithContact(
        DUMMY_CONTENT,
        signature,
        mismatched.id,
      );

      expect(result.valid).toBe(false);
      expect(result.reason).toBe("Signer does not match contact");
    });

    it("verifies text and detached signatures", async () => {
      const signature = await client.signText("Detached text");

      const textResult = await client.verifyText("Detached text", signature, {
        contactId: keyA.id,
      });
      expect(textResult.valid).toBe(true);

      const serialized = signature.serialize();
      const detachedResult = await client.verifyDetached(
        "Detached text",
        serialized,
        { contactId: keyA.id },
      );
      expect(detachedResult.valid).toBe(true);

      await expect(client.verifyText("", serialized)).rejects.toThrow(
        "verifyText: text must be a non-empty string",
      );
      await expect(client.verifyDetached("content", "")).rejects.toThrow(
        "verifyDetached: serializedSignature must be a non-empty string",
      );
    });

    it("batch-verifies signatures and supports per-file verification inputs", async () => {
      const signed1 = await client.signFile(blobFromText("Batch 1"));
      const signed2 = await client.signFile(blobFromText("Batch 2"));

      const results = await client.batchVerifyFiles(
        [
          signed1.blob,
          {
            file: signed2.blob,
            mimeType: "text/plain",
            expectedSignerId: keyA.fingerprint,
          },
        ],
        { contactId: keyA.id },
      );

      expect(results).toHaveLength(2);
      expect(results.every((result) => result.valid)).toBe(true);
      expect(results.every((result) => result.error === null)).toBe(true);
    });

    it("verifies an embedded signed file through verifyFile", async () => {
      const signed = await client.signFile(blobFromText("direct verifyFile"));

      const results = await client.verifyFile(signed.blob, {
        contactId: keyA.id,
        mimeType: "text/plain",
      });

      //   expect(results.length).toBeGreaterThan(0);
      expect(results.valid).toBe(true);
      expect(results.signerId).toBe(keyA.fingerprint);
    });

    it("returns useful results from verifyBatch", async () => {
      const sig1 = await client.signContent("one");
      const sig2 = await client.signContent("two");

      const results = client.verifyBatch("one", [sig1, sig2]);

      expect(results).toHaveLength(2);
      expect(results[0].valid).toBe(true);
      expect(results[1].valid).toBe(false);
    });

    it("gets signing public keys from the real account", async () => {
      const publicKeys = await client.getSigningPublicKeys(keyA.id);

      expect(publicKeys.signerId).toBe(keyA.fingerprint);
      expect(publicKeys.edPublicKey).toBeInstanceOf(Uint8Array);
      expect(publicKeys.mlDsaPublicKey).toBeInstanceOf(Uint8Array);
    });

    it("resolves signer labels from own accounts and external contacts", async () => {
      expect(client.resolveSignerLabel(keyA.id)).toBe(ALICE_LABEL);
      expect(client.resolveSignerLabel(keyB.id)).toBe(BOB_LABEL);
      expect(client.resolveSignerLabel("12345678901234567890")).toBe(
        "1234567890123456…",
      );
    });
  });

  describe("Detached file signing and verification", () => {
    let client: MajikSignatureClient;

    beforeEach(async () => {
      client = await MajikSignatureClient.create({});
      await installOwnAccount(client, keyA, ALICE_LABEL);
      await installOwnAccount(client, keyB, BOB_LABEL);
      await client.setActiveAccount(keyA.id, true);
    });

    it("signs and verifies a detached text file", async () => {
      const file = blobFromText("Detached file");

      const signed = await client.signFileDetached(file, {
        contentType: "text/plain",
      });

      expect(signed.blob).toBeInstanceOf(Blob);
      expect(signed.envelope).toBeInstanceOf(MajikSignatureEnvelope);
      expect(signed.signature.signerId).toBe(keyA.fingerprint);

      const result = await client.verifyFileDetached(
        signed.blob,
        signed.envelope,
        { key: keyA },
      );

      expect(result.valid).toBe(true);
    });

    it("supports detached multi-signature composition with an existing envelope", async () => {
      const file = blobFromText("Detached multi-sig");

      const first = await client.signFileDetached(file, {
        contentType: "text/plain",
      });

      const second = await client.signFileDetached(first.blob, {
        accountId: keyB.id,
        contentType: "text/plain",
        existingEnvelope: first.envelope,
      });

      expect(second.envelope.signatures).toHaveLength(2);

      const resultsA = await client.verifyFileDetached(
        second.blob,
        second.envelope,
        { key: keyA, expectedSignerId: keyA.fingerprint },
      );
      const resultsB = await client.verifyFileDetached(
        second.blob,
        second.envelope,
        { key: keyB, expectedSignerId: keyB.fingerprint },
      );

      expect(resultsA.valid).toBe(true);
      expect(resultsB.valid).toBe(true);
    });

    it("rejects detached verification after content tampering", async () => {
      const file = blobFromText("Tamper detached");

      const signed = await client.signFileDetached(file, {
        contentType: "text/plain",
      });

      const original = new Uint8Array(await signed.blob.arrayBuffer());
      original[0] ^= 0xff;

      const result = await client.verifyFileDetached(
        new Blob([original], { type: signed.blob.type }),
        signed.envelope,
        { key: keyA },
      );

      expect(result.valid).toBe(false);
    });

    it("extracts and verifies every detached signature", async () => {
      const first = await client.signFileDetached(blobFromText("all sigs"), {
        contentType: "text/plain",
      });
      const second = await client.signFileDetached(first.blob, {
        accountId: keyB.id,
        contentType: "text/plain",
        existingEnvelope: first.envelope,
      });

      const all = await client.verifyFileDetachedAllSignatures(
        second.blob,
        second.envelope,
      );

      expect(all).toHaveLength(2);
      expect(all.every((result) => result.valid)).toBe(true);
      expect(all.map((result) => result.signerId)).toEqual(
        expect.arrayContaining([keyA.fingerprint, keyB.fingerprint]),
      );
    });
  });

  describe("File verification helpers, revisions and multi-signature inspection", () => {
    let client: MajikSignatureClient;

    beforeEach(async () => {
      client = await MajikSignatureClient.create({});
      await installOwnAccount(client, keyA, ALICE_LABEL);
      await installOwnAccount(client, keyB, BOB_LABEL);
      await installOwnAccount(client, keyC, CAROL_LABEL);
      await client.setActiveAccount(keyA.id, true);
    });

    it("verifies every embedded signature and labels known signers", async () => {
      const base = blobFromText("embedded all signatures");
      const first = await client.signFile(base, {
        contentType: "text/plain",
        expectedSigners: [
          MajikSignatureClient.expectedSignerFromKey(keyA),
          MajikSignatureClient.expectedSignerFromKey(keyB),
        ],
      });

      const second = await client.signFile(first.blob, {
        accountId: keyB.id,
        contentType: "text/plain",
      });

      const results = await client.verifyFileAllSignatures(second.blob, {
        mimeType: "text/plain",
      });

      expect(results).toHaveLength(2);
      expect(results.every((result) => result.valid)).toBe(true);
      expect(results.map((r) => r.signerLabel)).toEqual(
        expect.arrayContaining([ALICE_LABEL, BOB_LABEL]),
      );
    });

    it("supports file revision chains and verifies supplied revisions", async () => {
      const v1 = await client.signFile(blobFromText("version one"), {
        contentType: "text/plain",
      });

      const v2Source = blobFromText("version two");
      const v2 = await client.signFile(v2Source, {
        contentType: "text/plain",
        priorSignedFile: v1.blob,
        accountId: keyB.id,
      });

      const v3 = await client.signFile(blobFromText("version three"), {
        contentType: "text/plain",
        priorSignedFile: v2.blob,
        accountId: keyC.id,
      });

      const revisionResult = await client.verifyFileRevisions(
        v3.blob,
        [v1.blob, v2.blob],
        { mimeType: "text/plain" },
      );

      expect(revisionResult.allValid).toBe(true);
      expect(revisionResult.isCompleteSet).toBe(true);

      const chainResult = await client.verifyFileChain(v3.blob, {
        mimeType: "text/plain",
      });

      expect(chainResult.chainValid).toBe(true);
      expect(chainResult.latest.valid).toBe(true);
      expect(chainResult.history.length).toBeGreaterThan(0);
    });

    it("reports file signature metadata and unsigned state correctly", async () => {
      const unsigned = blobFromText("not signed");

      expect(await client.isFileSigned(unsigned)).toBe(false);
      expect(await client.extractSignature(unsigned)).toEqual([]);

      const signed = await client.signFile(unsigned);
      expect(await client.isFileSigned(signed.blob)).toBe(true);

      const signatures = await client.getFileSignatureInfo(signed.blob);
      expect(signatures[0].signerId).toBe(keyA.fingerprint);
    });

    it("builds expected signers from real keys and contacts", async () => {
      const contactC = await installExternalContact(client, keyD, DAVE_LABEL);

      const expectedFromKey = client.buildExpectedSigners([keyA, keyB]);
      expect(expectedFromKey.map((s) => s.signerId)).toEqual([
        keyA.fingerprint,
        keyB.fingerprint,
      ]);

      const expectedFromContact = client.buildExpectedSigners([
        { contactId: contactC.id },
      ]);
      expect(expectedFromContact[0].signerId).toBe(keyD.fingerprint);
    });

    it("builds allowlists and exposes multi-signature status and signatories", async () => {
      const base = blobFromText("allowlist inspection");
      const expectedSigners = [
        MajikSignatureClient.expectedSignerFromKey(keyA),
        MajikSignatureClient.expectedSignerFromKey(keyB),
        MajikSignatureClient.expectedSignerFromKey(keyC),
      ];

      const first = await client.signFile(base, {
        contentType: "text/plain",
        expectedSigners,
      });

      expect(await client.isMultiSig(first.blob)).toBe(true);
      expect(await client.getAllowlist(first.blob)).toHaveLength(3);
      expect((await client.canSign(first.blob, keyB)).permitted).toBe(true);
      expect((await client.canSign(first.blob, keyD)).permitted).toBe(false);

      const signatories = await client.getSignatories(first.blob);
      expect(signatories).toBeDefined();

      const signed = await client.signFile(first.blob, {
        accountId: keyB.id,
        contentType: "text/plain",
      });

      const signedSignatories = await client.getSignedSignatories(signed.blob);
      const pendingSignatories = await client.getPendingSignatories(
        signed.blob,
      );
      const allSignatories = await client.getAllSignatories(signed.blob);
      const issuer = await client.getIssuer(signed.blob);

      expect(
        signedSignatories?.signed.some((s) => s.signerId === keyB.fingerprint),
      ).toBe(true);
      expect(
        pendingSignatories?.pending.some(
          (s) => s.signerId === keyC.fingerprint,
        ),
      ).toBe(true);
      expect(allSignatories?.all.length).toBe(3);
      expect(issuer?.signerId).toBe(keyA.fingerprint);
    });

    it("gets envelope info for a signed file", async () => {
      const signed = await client.signFile(blobFromText("envelope info"));
      const info = await client.getEnvelopeInfo(signed.blob);

      expect(info).toBeDefined();
      expect(info?.signatureCount).toBe(1);
      expect(info?.issuer?.signerId).toBe(keyA.fingerprint);
    });
  });

  describe("Sealing", () => {
    let client: MajikSignatureClient;

    beforeEach(async () => {
      client = await MajikSignatureClient.create({});
      await installOwnAccount(client, keyA, ALICE_LABEL);
      await installOwnAccount(client, keyB, BOB_LABEL);
      await client.setActiveAccount(keyA.id, true);
    });

    it("seals a completed restricted envelope and verifies the seal", async () => {
      const base = blobFromText("seal me");
      const first = await client.signFile(base, {
        contentType: "text/plain",
        expectedSigners: [
          MajikSignatureClient.expectedSignerFromKey(keyA),
          MajikSignatureClient.expectedSignerFromKey(keyB),
        ],
      });

      const second = await client.signFile(first.blob, {
        accountId: keyB.id,
        contentType: "text/plain",
      });

      const sealed = await client.seal(second.blob, {
        accountId: keyA.id,
        mimeType: "text/plain",
      });

      expect(await client.isSealed(sealed.blob)).toBe(true);

      const sealInfo = await client.getSealInfo(sealed.blob);
      expect(sealInfo?.sealedBy).toBe(keyA.fingerprint);
      expect(sealInfo?.sealHash).toBe(sealed.sealInfo.sealHash);

      const verification = await client.verifySeal(sealed.blob, {
        mimeType: "text/plain",
      });
      expect(verification.valid).toBe(true);

      await expect(
        client.signFile(sealed.blob, { accountId: keyB.id }),
      ).rejects.toThrow(/Cannot sign a sealed envelope/);
    });

    it("returns a non-sealed result for an ordinary signed file", async () => {
      const signed = await client.signFile(blobFromText("not sealed"));

      expect(await client.isSealed(signed.blob)).toBe(false);
      expect(await client.getSealInfo(signed.blob)).toBeNull();
    });
  });

  describe("Chronological signature order", () => {
    let client: MajikSignatureClient;

    beforeEach(async () => {
      client = await MajikSignatureClient.create({});
      await installOwnAccount(client, keyA, ALICE_LABEL);
      await installOwnAccount(client, keyB, BOB_LABEL);
      await client.setActiveAccount(keyA.id, true);
    });

    it("verifies embedded signature order using trusted key material", async () => {
      const v1 = await client.signFile(blobFromText("ordered"), {
        contentType: "text/plain",
        timestamp: "2026-08-01T10:00:00.000Z",
      });

      const v2 = await client.signFile(v1.blob, {
        accountId: keyB.id,
        contentType: "text/plain",
        timestamp: "2026-08-01T10:05:00.000Z",
      });

      const result = await client.verifyFileOrder(v2.blob, [keyA, keyB], {
        mimeType: "text/plain",
        strict: true,
      });

      expect(result.valid).toBe(true);
      expect(result.allValid).toBe(true);
    });

    it("verifies detached signature order using an envelope", async () => {
      const v1 = await client.signFileDetached(
        blobFromText("ordered detached"),
        {
          contentType: "text/plain",
          timestamp: "2026-08-01T10:00:00.000Z",
        },
      );

      const v2 = await client.signFileDetached(v1.blob, {
        accountId: keyB.id,
        contentType: "text/plain",
        timestamp: "2026-08-01T10:05:00.000Z",
        existingEnvelope: v1.envelope,
      });

      const result = await client.verifyFileDetachedOrder(
        v2.blob,
        v2.envelope,
        [keyA, keyB],
        { mimeType: "text/plain", strict: true },
      );

      expect(result.valid).toBe(true);
      expect(result.allValid).toBe(true);
    });
  });

  describe("Encrypted reusable stamps", () => {
    let client: MajikSignatureClient;

    beforeEach(async () => {
      client = await MajikSignatureClient.create({});
      await installOwnAccount(client, keyA, ALICE_LABEL);
      await client.setActiveAccount(keyA.id, true);
    });

    it("creates, lists, decrypts, renames, replaces and removes a stamp", async () => {
      const source = new TextEncoder().encode("stamp bytes");

      const created = await client.createStamp(
        source,
        "image",
        "Primary Signature",
        { mimeType: "image/png" },
      );

      expect(created.id).toBeTruthy();
      expect(created.name).toBe("Primary Signature");
      expect(client.listStamps()).toHaveLength(1);
      expect(await client.getStamp(created.id)).toBeDefined();

      const decrypted = await client.decryptStampContent(created.id);
      expect(decrypted).toEqual(source);

      const renamed = await client.renameStamp(created.id, "Renamed Signature");
      expect(renamed.name).toBe("Renamed Signature");

      const replacement = new TextEncoder().encode("replacement bytes");
      const replaced = await client.replaceStampContent(
        created.id,
        replacement,
        { mimeType: "image/png" },
      );

      const decryptedReplacement = await client.decryptStampContent(
        replaced.id,
      );

      expect(decryptedReplacement).toEqual(replacement);

      // Hydration is the operation that populates the in-memory decrypted cache.
      await client.hydrateStampsForActiveAccount();

      expect(client.getDecryptedStampBytes(replaced.id)).toEqual(replacement);

      expect(client.listStamps("image")).toHaveLength(1);
      expect(client.listStampsForActiveAccount()).toHaveLength(1);

      client.lockStamps();

      expect(client.getDecryptedStampBytes(replaced.id)).toBeUndefined();

      expect(await client.removeStamp(created.id)).toBe(true);
      expect(await client.removeStamp(created.id)).toBe(false);
      expect(await client.getStamp(created.id)).toBeNull();
    });

    it("hydrates account-scoped stamps after they are persisted", async () => {
      const created = await client.createStamp(
        new TextEncoder().encode("hydrate stamp"),
        "text",
        "Hydrate Me",
        { mimeType: "text/plain" },
      );

      client.lockStamps();
      expect(client.getDecryptedStampBytes(created.id)).toBeUndefined();

      await client.hydrateStampsForActiveAccount();
      const decrypted = await client.decryptStampContent(created.id);

      expect(decrypted).toEqual(new TextEncoder().encode("hydrate stamp"));
    });

    it("throws for stamp hydration/decryption without an active account", async () => {
      const empty = await MajikSignatureClient.create({});

      await expect(empty.hydrateStampsForActiveAccount()).rejects.toThrow(
        "No active account — call setActiveAccount() first",
      );
    });
  });

  describe("MJKS map batch operations", () => {
    let client: MajikSignatureClient;
    let files: Array<{ path: string; blob: Blob }>;

    beforeEach(async () => {
      client = await MajikSignatureClient.create({});
      await installOwnAccount(client, keyA, ALICE_LABEL);
      await installOwnAccount(client, keyB, BOB_LABEL);
      await client.setActiveAccount(keyA.id, true);

      files = [
        {
          path: "docs/one.txt",
          blob: blobFromText("one", "text/plain"),
        },
        {
          path: "docs/two.txt",
          blob: blobFromText("two", "text/plain"),
        },
      ];
    });

    it("signs batch files into an MJKS map, reads and describes the map", async () => {
      const result = await client.signBatchDetached(files);

      expect(result.mode).toBe("map");

      if (result.mode !== "map") {
        throw new Error("Expected map batch result");
      }

      expect(result.map.size).toBe(2);
      expect(await client.isMjksMap(result.mapBlob)).toBe(true);

      const map = await client.readMjksMap(result.mapBlob);
      expect(map.size).toBe(2);

      const described = await client.describeMjksMap(result.mapBlob);
      expect(described.size).toBe(2);
      expect(described.files).toHaveLength(2);
    });

    it("supports separate detached batch output", async () => {
      const result = await client.signBatchDetached(files, {
        mode: "separate",
      });

      expect(result.mode).toBe("separate");

      if (result.mode !== "separate") {
        throw new Error("Expected separate batch result");
      }

      expect(result.signatures).toHaveLength(2);
      expect(result.failures).toHaveLength(0);
      expect(
        result.signatures.every((entry) => entry.blob instanceof Blob),
      ).toBe(true);
    });

    it("verifies an MJKS map in trusted-key mode", async () => {
      const signed = await client.signBatchDetached(files);

      if (signed.mode !== "map") {
        throw new Error("Expected map batch result");
      }

      const result: MjksMapVerifyResult = await client.verifyMjksMap(
        signed.mapBlob,
        files,
        { key: keyA, requireAllPresent: true },
      );

      expect(result.trustedKeys).toBe(true);
      expect(result.missingFromBatch).toHaveLength(0);
      expect(result.results).toHaveLength(2);
      expect(result.results.every((r) => r.status === "verified")).toBe(true);
      expect(result.summary).toBeDefined();
    });

    it("verifies an MJKS map in self-reported mode and reports missing files", async () => {
      const signed = await client.signBatchDetached(files);

      if (signed.mode !== "map") {
        throw new Error("Expected map batch result");
      }

      const result = await client.verifyMjksMap(signed.mapBlob, [files[0]]);

      expect(result.trustedKeys).toBe(false);
      expect(result.missingFromBatch).toEqual(["docs/two.txt"]);
      expect(result.results[0].status).toBe("verified");
    });

    it("reports map path/content tampering instead of falsely verifying", async () => {
      const signed = await client.signBatchDetached(files);

      if (signed.mode !== "map") {
        throw new Error("Expected map batch result");
      }

      const tampered = blobFromText("tampered", "text/plain");

      const result = await client.verifyMjksMap(signed.mapBlob, [
        { path: files[0].path, blob: tampered },
      ]);

      expect(result.results[0].status).toBe("tampered");
      expect(result.results[0].reason).toContain(
        "File content no longer matches what was signed",
      );
    });

    it("co-signs an existing map with another real account", async () => {
      const initial = await client.signBatchDetached(files);

      if (initial.mode !== "map") {
        throw new Error("Expected map batch result");
      }

      const result = await client.cosignMjksMap(initial.mapBlob, files, {
        accountId: keyB.id,
      });

      expect(result.failures).toHaveLength(0);
      expect(result.map.size).toBe(2);

      const verified = await client.verifyMjksMap(result.mapBlob, files, {
        key: keyB,
        expectedSignerId: keyB.fingerprint, // <--- Add expectedSignerId
        requireAllPresent: true,
      });

      expect(verified.results.every((r) => r.status === "verified")).toBe(true);
    });

    it("round-trips map order verification", async () => {
      const first = await client.signBatchDetached(files);
      if (first.mode !== "map") {
        throw new Error("Expected map batch result");
      }

      const result = await client.verifyMjksMapOrder(
        first.mapBlob,
        files,
        [keyA],
        { strict: true },
      );

      expect(result.results).toHaveLength(2);
      expect(result.allOrdered).toBe(true);
    });

    it("rejects invalid MJKS map input", async () => {
      const invalid = new TextEncoder().encode("not an mjks map");

      expect(await client.isMjksMap(invalid)).toBe(false);
      await expect(client.readMjksMap(invalid)).rejects.toThrow();
    });
  });

  describe("Backups and restore", () => {
    let client: MajikSignatureClient;
    let contact: MajikContact;

    beforeEach(async () => {
      client = await MajikSignatureClient.create({});
      await installOwnAccount(client, keyA, ALICE_LABEL);
      await client.setActiveAccount(keyA.id, true);

      contact = await installExternalContact(client, keyB, BOB_LABEL);
      await client.createGroup(
        "backup-group",
        "Backup Group",
        { description: "Persist me" },
        [contact.id],
      );

      const preferences = await client.getUserAppPreferences();
      preferences.privacy.shareAnalytics = true;
      preferences.signing.autoSeal = true;
      await client.setUserAppPreferences(preferences);

      await client.createStamp(
        new TextEncoder().encode("backup stamp"),
        "text",
        "Backup Stamp",
        { mimeType: "text/plain" },
      );
    });

    it("creates typed contact, stamp and app-data backups", async () => {
      const contactBackup = await client.backupContacts();
      const stampBackup = await client.backupStamps();
      const appBackup = await client.backupAppData();

      expect(await MajikSignatureClient.probeBackupType(contactBackup)).toBe(
        "contacts",
      );
      expect(await MajikSignatureClient.probeBackupType(stampBackup)).toBe(
        "stamps",
      );
      expect(await MajikSignatureClient.probeBackupType(appBackup)).toBe(
        "appData",
      );

      expect(
        await MajikSignatureClient.probeBackupType(new Blob(["not a backup"])),
      ).toBe("unknown");
    });

    it("reads backup payloads without mutating the client", async () => {
      const contactBackup = await client.backupContacts();
      const stampBackup = await client.backupStamps();
      const appBackup = await client.backupAppData();

      const contactsSnapshot = await client.readContactsBackup(contactBackup);
      const stampsSnapshot = await client.readStampsBackup(stampBackup);
      const appSnapshot = await client.readAppDataBackup(appBackup);

      expect(contactsSnapshot.contacts.length).toBeGreaterThan(0);
      expect(contactsSnapshot.groups.some((g) => g.id === "backup-group")).toBe(
        true,
      );
      expect(stampsSnapshot).toHaveLength(1);
      expect(appSnapshot.contacts.length).toBeGreaterThan(0);
      expect(appSnapshot.groups.some((g) => g.id === "backup-group")).toBe(
        true,
      );
      expect(appSnapshot.stamps).toHaveLength(1);
      expect(appSnapshot.preferences?.privacy.shareAnalytics).toBe(true);
    });

    it("restores contacts and groups from a contacts backup", async () => {
      const backup = await client.backupContacts();

      await client.clearDirectory();
      expect(client.listContacts(true)).toHaveLength(0);

      const restored = await client.restoreContacts(backup, {
        includeGroups: true,
      });

      expect(restored.contacts).toBeGreaterThan(0);
      expect(restored.groups).toBeGreaterThan(0);
      expect(client.hasContact(contact.id)).toBe(true);
      expect(client.hasGroup("backup-group")).toBe(true);
    });

    it("restores stamps from a stamp backup", async () => {
      const backup = await client.backupStamps();
      const originalIds = client.listStamps().map((stamp) => stamp.id);

      for (const id of originalIds) {
        await client.removeStamp(id);
      }

      expect(client.listStamps()).toHaveLength(0);

      const restored = await client.restoreStamps(backup);
      expect(restored.restored).toBe(1);
      expect(client.listStamps()).toHaveLength(1);
    });

    it("restores full application state and preferences", async () => {
      const backup = await client.backupAppData();

      const fresh = await MajikSignatureClient.create({});

      const restored = await fresh.restoreAppData(backup);

      expect(restored.contacts).toBeGreaterThan(0);
      expect(restored.groups).toBeGreaterThan(0);
      expect(fresh.hasContact(contact.id)).toBe(true);
      expect(fresh.hasGroup("backup-group")).toBe(true);
      expect((await fresh.getUserAppPreferences()).privacy.shareAnalytics).toBe(
        true,
      );
      expect(fresh.listStamps()).toHaveLength(1);
    });

    it("restores selected application-data sections", async () => {
      const backup = await client.backupAppData();
      const snapshot = await client.readAppDataBackup(backup);

      const fresh = await MajikSignatureClient.create({});
      const restored = await fresh.restoreAppDataSelective(snapshot, {
        contacts: true,
        groups: true,
        stamps: false,
        preferences: true,
      });

      expect(restored.contacts).toBeGreaterThan(0);
      expect(restored.groups).toBeGreaterThan(0);
      expect(restored.stamps).toBe(0);
      expect(restored.preferences).toBe(true);
      expect(fresh.hasContact(contact.id)).toBe(true);
      expect(fresh.hasGroup("backup-group")).toBe(true);
    });

    it("rejects a backup with invalid magic bytes", async () => {
      const invalid = new Blob(["not a valid backup"]);

      await expect(client.readContactsBackup(invalid)).rejects.toThrow();
      await expect(client.readStampsBackup(invalid)).rejects.toThrow();
      await expect(client.readAppDataBackup(invalid)).rejects.toThrow();
    });
  });

  describe("Reset and data lifecycle", () => {
    it("resets key/domain data while preserving the audit managers themselves", async () => {
      const client = await MajikSignatureClient.create({});
      await installOwnAccount(client, keyA, ALICE_LABEL);
      await installExternalContact(client, keyB, BOB_LABEL);
      await client.createStamp(
        new TextEncoder().encode("reset me"),
        "text",
        "Reset Stamp",
        { mimeType: "text/plain" },
      );
      await client.sign("before reset");

      await flushAsyncWork();

      expect(client.listContacts(true).length).toBeGreaterThan(0);
      expect(client.listStamps().length).toBeGreaterThan(0);

      await client.resetData();

      expect(client.listOwnAccounts()).toHaveLength(0);
      expect(client.listContacts(true)).toHaveLength(0);
      expect(client.listStamps()).toHaveLength(0);
      expect(client.historyManager).toBeDefined();
      expect(client.activityManager).toBeDefined();
    });
  });

  describe("Negative-path validation without mocks", () => {
    it("rejects signing without an active account", async () => {
      const client = await MajikSignatureClient.create({});

      await expect(client.sign("no active account")).rejects.toThrow(
        "No active account — call setActiveAccount() first",
      );
      await expect(
        client.signFile(blobFromText("no active account")),
      ).rejects.toThrow("No active account — call setActiveAccount() first");
    });

    it("rejects trusted verification against a missing account/contact", async () => {
      const client = await MajikSignatureClient.create({});
      const signature = await MajikSignature.sign(DUMMY_CONTENT, keyA);

      expect(() =>
        client.verifyWithAccount(DUMMY_CONTENT, signature, "missing-account"),
      ).toThrow('Account not found: "missing-account"');

      await expect(
        client.verifyWithContact(DUMMY_CONTENT, signature, "missing-contact"),
      ).rejects.toThrow('Contact not found: "missing-contact"');
    });

    it("rejects sealing when there is no active account", async () => {
      const client = await MajikSignatureClient.create({});

      await expect(client.seal(blobFromText("seal"))).rejects.toThrow(
        "No active account — call setActiveAccount() first",
      );
    });

    it("rejects stamp creation without an active account", async () => {
      const client = await MajikSignatureClient.create({});

      await expect(
        client.createStamp(
          new TextEncoder().encode("stamp"),
          "text",
          "No Account",
        ),
      ).rejects.toThrow("No active account — call setActiveAccount() first");
    });

    it("reports unsigned-file multi-sig inspection safely", async () => {
      const client = await MajikSignatureClient.create({});
      const file = blobFromText("unsigned");

      expect(await client.getAllowlist(file)).toBeNull();
      expect(await client.isMultiSig(file)).toBe(false);
      expect(await client.getSignatories(file)).toBeNull();
      expect(await client.getIssuer(file)).toBeNull();
      expect(await client.getEnvelopeInfo(file)).toBeNull();
      expect(await client.isSealed(file)).toBe(false);
    });
  });
});
