# Changelog

All notable changes to Roll2Seed are documented in this file.

## [0.1.0] - 2026-08-02

Initial private release.

### Added

- Exact d6-to-BIP39 rejection sampling with entropy recycling for 12-, 15-, 18-, 21-, and 24-word English mnemonics.
- BIP39 SHA-256 checksum generation, official 2,048-word English list, pinned wordlist integrity check, and fail-closed startup self-tests.
- Guarded phrase and roll review, correction-safe recomputation, wall-clock reveal limits, lifecycle concealment, session erasure, and paper-backup verification flow.
- Hardened local static server with restrictive browser headers and explicit opt-in for non-loopback container exposure.
- Automated tests for official BIP39 vectors, sampler boundaries, uniformity, entropy recycling, invalid input, and correction transitions.
- Detailed entropy, dice, operational-safety, and threat-boundary documentation.

### Security

- No runtime backend, network requests, analytics, persistent browser storage, clipboard, QR, download, or print path.
- Network listening remains loopback-only unless `ROLL2SEED_EXPOSE=1` is deliberately configured behind a trusted TLS-terminating proxy.
