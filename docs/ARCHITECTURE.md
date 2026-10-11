# VenueDesk Architecture Specification

## 1. Core Principles and Identity Semantics

Institutional identity and physical device identity are strictly decoupled in VenueDesk.

An **Asset** represents institutional inventory (e.g. `VD-ASSET-000421`), which carries purchase records, room location, department assignment, and warranty metadata.
Institutional metadata is managed solely by administrative authorities and the campus asset register.
The endpoint agent is never permitted to overwrite institutional metadata such as asset tags, rooms, or department assignments.

A **Physical Device** represents a specific computing motherboard and cryptographic identity (e.g. `VD-DEVICE-A8123F00`).
The device identity is anchored cryptographically by an asymmetric Ed25519 key pair generated on the machine upon first boot.
Private keys are strictly non-exportable and never leave the endpoint.

An **Asset-Device Link** establishes an active mapping between an institutional Asset and a Physical Device.
At any point in time, an Asset can have at most one ACTIVE link, and a Physical Device can be linked to at most one Asset.
Replacing a faulty motherboard or PC preserves the Asset record while closing the previous link and creating a new one.

## 2. Cryptographic Security Model

Every request originating from an enrolled agent to the control plane must include cryptographic headers:
- `X-Device-ID`: Identifier of the physical device.
- `X-Timestamp`: Unix epoch seconds (UTC). Requests outside the allowable clock skew window are rejected.
- `X-Nonce`: Single-use random identifier per request to prevent replay attacks.
- `X-Key-Version`: Current registered credential version.
- `X-Signature`: Base64-encoded Ed25519 signature across the canonicalized request string.

The canonical string format is deterministic:
`{METHOD}\n{PATH_AND_QUERY}\n{TIMESTAMP}\n{NONCE}\n{BODY_SHA256_HEX}`

Pairing tokens (`PAIR-...`) are ephemeral, high-entropy, asset-scoped tokens.
Tokens are stored solely as SHA-256 hashes in the database.
They are revealed exactly once upon creation and consumed atomically during enrollment.

## 3. Hardware Fingerprinting & Reconciliation

Hardware identity evidence consists of primary anchors (`machine_uuid`, `motherboard_serial`, `bios_serial`, `tpm_identity`) and secondary hardware (`cpu`, `gpus`, `disks`, `nics`).
Before transmission, individual sensitive identifiers are hashed using `HMAC-SHA256` with a deployment salt.
A canonical fingerprint is calculated across sorted, normalized, and trimmed evidence.

Dynamic hardware changes (such as adding RAM, swapping a GPU, or replacing an SSD) trigger low or medium severity change events without disrupting device identity.
Simultaneous alterations of two or more strong hardware anchors place the device into `PENDING_REVERIFICATION` status for administrative review.
Similarity scores are utilized solely to rank candidate devices during manual verification or OS recovery; a similarity score alone never authorizes an asset mapping.

## 4. Dual-Boot and Operating System Lifecycle

Operating system installations are modeled independently from the underlying physical hardware.
A dual-boot endpoint hosts two distinct `OSInstallation` records mapped to a single `PhysicalDevice` record.
Reinstalling an operating system triggers an authenticated recovery workflow that closes the former OS installation and transitions the device back to active service upon approval.
