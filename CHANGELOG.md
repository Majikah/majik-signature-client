# Changelog

## 1.6.0 - 2026-11-28

- Align the client package version with the TypeScript and Rust Majik Signature 1.6.0 core releases.
- Upgrade `@majikah/majik-signature` to `^1.6.0`.
- Add `signBatchDetachedStream()` for sequential, bounded-memory detached signing of byte streams into MJKSMAP or separate MJKSIG outputs.
- Add `verifyMjksMapStream()` for sequential streaming manifest verification using a trusted signer key/contact/address.
- Preserve buffered batch APIs and self-reported-key verification behavior for compatibility.
- Add client-level history recording for successful streaming detached batch outputs.
- Add tests for streaming map signing, trusted-key verification, relocation, progress, separate outputs, and trusted-key requirements.

