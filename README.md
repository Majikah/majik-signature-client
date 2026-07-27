# Majik Signature Client

**Majik Signature Client** is a high-level TypeScript wrapper for `MajikSignature`, built directly on top of `MajikKeyClient`. 

Designed to be used natively within the Majikah ecosystem, it inherits all core `MajikKey` account management—such as creation, lock/unlock states, and active-account tracking—while introducing domain-specific functionality for file signing, contact management, and encrypted reusable stamps.

## Core Capabilities

*   **Integrated Key & Account Management**: Extends `MajikKeyClient` to seamlessly handle account lifecycles and cryptographic unlocking. Accounts can easily be shared alongside `MajikMessage`.
*   **Contact & Group Directory**: Utilizes `MajikContactManager` for full contact CRUD operations, including system/user groups, favorites, and blocked lists.
*   **Post-Quantum Signing & Verification**: Provides intuitive methods (`signFile`, `verifyFile`, `batchSignFiles`) for text, raw bytes, and file blobs. Verifications automatically resolve public keys from the internal contact directory or active keystore.
*   **Multi-sig & Envelope Sealing**: Built-in support for restricted allowlists (`expectedSigners`), multi-sig pending states, and cryptographic sealing to prevent further modifications to a file.
*   **Encrypted Stamp Assets**: Uses `MajikSignatureStampManager` to securely create, encrypt, and manage reusable assets (signatures, audio, text) bound to the user's ML-KEM keys.
*   **Data Backup & Restore**: Robust export and hydration capabilities for contacts, stamps, and user preferences utilizing `MajikCompressedJSON` and protected by strict magic byte headers.

---

## Initialization

You can instantiate and fully hydrate the client and its storage adapters in a single call using the static `create` method.

```typescript
import { MajikSignatureClient } from "your-path-here"; // Update with actual package export

// 1. Initialize and hydrate the client state, keys, contacts, and stamps
const client = await MajikSignatureClient.create({
  adapters: {
    // Inject your target storage adapters here (e.g., IndexedDB)
    contacts: myContactsAdapter,
    stamps: myStampsAdapter
  }
});
```

---

## Quick Usage API

### 1. File Signing & Sealing

Sign a file using the currently active unlocked account, then restrict future signers and seal it.

```typescript
// Sign a file blob
const { blob: signedBlob, signature } = await client.signFile(myFile, {
  contentType: "application/pdf"
});

// Optionally seal a multi-sig file to lock the envelope
const { sealInfo } = await client.seal(signedBlob);
console.log("Sealed at:", sealInfo.sealTimestamp);
```

### 2. File Verification

Verify a file's embedded signature automatically using your contact directory to resolve the signer's identity.

```typescript
// Verifies against known contacts or extracts self-reported keys
const result = await client.verifyFile(signedBlob, { 
    contactId: "expected_contact_id" 
});

if (result.valid) {
    console.log(`Authentic. Signed by: ${result.signerLabel || result.signerId}`);
}
```

### 3. Contact Management

Add external contacts and organize them into groups for streamlined verification.

```typescript
// Import a contact from a compressed base64 string
const contact = await client.importContactCompressed(base64ContactString);

// Add the contact to a custom group
const myGroup = await client.createGroup("group_1", "Trusted Signers");
await client.addContactToGroup(myGroup.id, contact.id);
```

### 4. Encrypted Stamps

Create an encrypted asset (like an image signature) that is safely stored at rest and decrypted on the fly using ML-KEM.

```typescript
// Create a new image stamp
const stamp = await client.createStamp(
    imageBytes, 
    "image", 
    "My Primary Signature", 
    { mimeType: "image/png" }
);

// Decrypt content later for injection into a document
const decryptedBytes = await client.decryptStampContent(stamp.id);
```

### 5. App Data Backups

Export or restore the entire application state—including contacts, stamps, and preferences—into a `.MJKB` portable blob.

```typescript
// Export
const backupBlob = await client.backupAppData();

// Restore
const restoreResults = await client.restoreAppData(backupBlob);
console.log(`Restored ${restoreResults.contacts} contacts.`);
```