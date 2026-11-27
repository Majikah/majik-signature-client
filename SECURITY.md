# Security Policy

## Scope

This repository contains the TypeScript application-client layer for Majik Signature. It composes `@majikah/majik-signature` with Majik Key account management, contact resolution, local application state, storage adapters, and client-side history.

The client layer is not a substitute for a security review of the core cryptographic implementation, runtime, storage adapters, host application, or deployment. A reported issue may affect this repository, a dependency, or an integration boundary.

## Reporting a vulnerability

Please do not disclose suspected vulnerabilities in a public issue, pull request, discussion, or commit.

Use GitHub private vulnerability reporting for this repository when available (open the repository's **Security** tab and select **Report a vulnerability**). Include the affected version or commit, runtime/environment, impact, and a minimal reproduction where practical. Redact personal data and operational secrets.

Never include private keys, mnemonic/recovery phrases, authentication tokens, unredacted user documents, or production credentials in a report.

If private vulnerability reporting is unavailable, contact the repository maintainers through GitHub and request a private reporting channel before sending technical details.

## Security assumptions and safe use

- Treat files, detached envelopes, MJKSMAP manifests, contact cards, backups, and metadata received from outside the application as untrusted input.
- Use trusted public keys obtained through an independently trusted channel for identity-sensitive verification. A valid signature made by a self-reported key does not, by itself, establish the signer's real-world identity.
- Keep private keys, mnemonic/recovery phrases, and unlocked account state under application control. Do not expose them in logs, crash reports, analytics, or support bundles.
- Apply application-specific file-type, total-size, and workflow authorization rules. Streaming reduces source-file buffering; it does not make arbitrary input safe to render, extract, or execute.
- Use maintained versions of this client and its dependencies. This project does not claim an independent third-party cryptographic audit or certification.

## Supported versions

Reports are assessed against the latest maintained release or development branch. This project does not currently publish a guaranteed security-support window for older versions; upgrading to the latest maintained version is recommended.

## Coordinated disclosure

Please allow maintainers a reasonable opportunity to investigate, prepare a fix, and coordinate an update before public disclosure. Reporter identity and submitted sensitive material will not be published without permission.
