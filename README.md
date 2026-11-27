# Majik Signature Client

**Majik Signature Client** is a high-level TypeScript wrapper for `MajikSignature`, built directly on top of `MajikKeyClient`. 

Designed to be used natively within the Majikah ecosystem, it inherits all core `MajikKey` account management—such as creation, lock/unlock states, and active-account tracking—while introducing domain-specific functionality for file signing, contact management, and encrypted reusable stamps.

## Core Capabilities

*   **Integrated Key & Account Management**: Extends `MajikKeyClient` to seamlessly handle account lifecycles and cryptographic unlocking. 
*   **Contact & Group Directory**: Utilizes `MajikContactManager` for full contact CRUD operations, including system/user groups, favorites, and blocked lists.
*   **Post-Quantum Signing & Verification**: Provides intuitive methods (`signFile`, `verifyFile`, `batchSignFiles`) for text, raw bytes, and file blobs. Verification can use explicitly trusted keys, local accounts, or contacts. Self-reported envelope keys are a separate mode and do not, by themselves, establish signer identity.
*   **Multi-sig & Envelope Sealing**: Built-in support for restricted allowlists (`expectedSigners`), multi-sig pending states, and cryptographic sealing to prevent further modifications to a file.
*   **Encrypted Stamp Assets**: Uses `MajikSignatureStampManager` to securely create, encrypt, and manage reusable assets (signatures, audio, text) bound to the user's ML-KEM keys.
*   **Data Backup & Restore**: Export and restore helpers for contacts, stamps, and supported application data using `MajikCompressedJSON` and format-specific magic headers.

---

## Initialization

You can instantiate and fully hydrate the client and its storage adapters in a single call using the static `create` method.

```typescript
import { MajikSignatureClient } from "@majikah/majik-signature-client";

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

### 2a. Streaming Batch Signing & Verification

The 1.6.0 client exposes the core streaming batch APIs without changing the
existing buffered methods. Pass one-shot byte sources (for example
`Blob.stream()`) and the known source length so the core can detect truncated
or overlong input.

```typescript
const signed = await client.signBatchDetachedStream(
  selectedFiles.map((file) => ({
    path: file.relativePath,
    source: file.blob.stream(),
    totalBytes: file.blob.size,
    mimeType: file.blob.type,
  })),
  {
    mode: "map",
    continueOnError: true,
    onProgress(progress) {
      console.log(progress.path, progress.bytesProcessed, progress.totalBytes);
    },
  },
);

if (signed.mode === "map") {
  await saveFile("batch.mjksmap", signed.mapBlob);
}

const verified = await client.verifyMjksMapStream(
  signed.mapBlob,
  selectedFiles.map((file) => ({
    path: file.relativePath,
    source: file.blob.stream(),
    totalBytes: file.blob.size,
  })),
  { key: trustedSignerKey },
);
```

Streaming MJKSMAP verification requires a trusted `key`, `contactId`, or
`address`. This keeps the streaming verification path anchored to a resolved
public-key identity. Use the existing `verifyMjksMap()` method when self-reported
envelope-key verification is required.

Files are consumed sequentially. These detached batch APIs sign or verify the
exact canonical bytes supplied; they do not strip embedded signatures or apply
native format-aware rewrites. Keep using `signFile()`, `signFileDetached()`,
and the existing Rust/Tauri path-streaming APIs for format-aware file handling.

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

Export or restore supported application state—including contacts, stamps, and preferences—using the client's portable backup format.

```typescript
// Export
const backupBlob = await client.backupAppData();

// Restore
const restoreResults = await client.restoreAppData(backupBlob);
console.log(`Restored ${restoreResults.contacts} contacts.`);
```



## Input bounds and streaming behavior

The 1.6.0 streaming batch wrappers apply client-side checks before unlocking a signing account or consuming a source:

- Up to 10,000 files per batch, matching the core MJKSMAP entry limit.
- Manifest paths are limited to 4,096 UTF-16 code units and reject unsafe control characters and `..` path segments after core-compatible normalization.
- Optional MIME metadata is limited to 1,024 UTF-16 code units and rejects control characters.
- Optional `totalBytes` declarations must be non-negative safe integers. The core hasher checks the actual stream against that declared length.
- `streaming.maxBytes`, when supplied, must be a non-negative safe integer and is enforced per file by the core streaming hasher.
- Sources are consumed sequentially. The core streaming policy defaults to 1 MiB chunks and supports its documented 64 KiB–64 MiB chunk range.

The core library remains responsible for MJKSMAP/MJKSIG parsing, envelope validation, cryptographic input checks, and stream hashing. The client deliberately does not duplicate those parsers. The MJKSMAP format has separate core limits, including a 16 MiB CBOR payload and a 10,000-entry manifest.

## Security and trust boundaries

Signature verification establishes that bytes verify against the supplied public keys; it does not independently establish who controls those keys. Resolve keys through a trusted channel or local contact directory and check the signer identity before making authorization decisions. Streaming MJKSMAP verification therefore requires a trusted signer key/contact/address. Buffered verification retains its separate self-reported-key mode.

These APIs do not make untrusted files safe to open, render, extract, or execute. Apply application-level file-type, size, and authorization policy before processing. Keep private keys and recovery phrases secret, and avoid logging source contents or key material. The TypeScript streaming batch API signs the exact canonical bytes supplied by the caller; it does not strip embedded signature metadata or perform format-aware rewriting.

See [SECURITY.md](SECURITY.md) for vulnerability reporting guidance and [CHANGELOG.md](CHANGELOG.md) for release notes.

## License

[Apache-2.0](LICENSE) — free for personal and commercial use.

---
## Author

Developed by **Josef Elijah Fabian (Zelijah)** | [Majikah Solutions OPC](https://majikah.solutions/about)

## About the Developer

- **Developer**: Josef Elijah Fabian
- **GitHub**: [https://github.com/jedlsf](https://github.com/jedlsf)
- **Project Repository**: [https://github.com/Majikah/majik-signature-client](https://github.com/Majikah/majik-signature-client)

---

## Contact

- **Business Email**: [business@thezelijah.world](mailto:business@thezelijah.world)
- **Official Website**: [https://www.thezelijah.world](https://www.thezelijah.world)