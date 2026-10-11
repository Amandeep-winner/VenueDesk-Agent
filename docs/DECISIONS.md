# Architectural & Engineering Decisions Log

This document tracks all architectural, design, and implementation decisions made during the development of VenueDesk Agent.

| Date | Decision | Reason |
|---|---|---|
| 2026-10-11 | Standalone Monorepo Architecture (Option A) | Sibling Campus-Booking-Management-System detected. Selected standalone monorepo in VenueDesk-Agent to preserve operational isolation, provide clean CI/CD pipelines, prevent schema regressions, and simplify packaging. |
| 2026-10-11 | Workspace Root Monorepo Layout | Placed venuedesk-backend, venuedesk-agent, docs, and tools directly at root rather than nesting inside another venuedesk folder to keep paths predictable and clean. |
| 2026-10-11 | Ed25519 Cryptographic Signatures | Followed spec §1 to use Ed25519 via Python cryptography library for asymmetric request signing and device authentication. |
| 2026-10-11 | FileKeyStore with ACL/DPAPI protection | Default key store implements local filesystem storage with restricted permissions (0600 on POSIX, ACL/DPAPI on Windows), with a stub for TpmKeyStore. |
| 2026-10-11 | Phase 3 Canonicalization and Degrading Collectors | Implemented FINGERPRINT_VERSION=1 SHA-256 fingerprinting, HMAC field hashes, SQLite local state, and hardware collectors with graceful fallback to None. |
| 2026-10-11 | Phase 4 Enrollment and Pairing Token Architecture | Built transactional enrollment with proof of possession, atomic pairing token consumption, rate limiting, and fake endpoint test suite. |
