# Security policy

## Report privately

Open a private security advisory on the repository, or contact the maintainer through the private channel listed in the repository profile. Do not open a public issue for an unpatched vulnerability. Do not attach private keys, credentials, tokens, private recordings, or other sensitive captures; use synthetic reproducers where possible.

There is no bug bounty. Response times depend on maintainer availability and are not guaranteed.

## Scope

In scope:

- plaintext audio or diagnostics uploaded where ciphertext was expected;
- Cloudflare Worker authentication/authorization defects;
- path traversal, symlink following, object-key confusion, or cross-device identity merging;
- unconfirmed or unauthenticated protocol data reported as verified;
- credential, signing-key, token, or private-key disclosure.

Out of scope for this repository:

- defects solely in device firmware or third-party apps/services;
- attacks requiring physical access without an SDK-specific additional impact;
- the inherent effect of a stolen owner private key decrypting recordings encrypted to it.

## Security invariants to preserve

| Invariant | Primary implementation area |
|---|---|
| Storage accepts supported enpt ciphertext or explicitly caller-encrypted diagnostics | `storage.py`, `cloudflare/` |
| Plaintext diagnostics and unknown content stay local and are reported | `ingest_files`, `ingest_outer`, CLI `sync --store` |
| Stable storage identity is distinct from host BLE UUID | `resolve_storage_identity`; CLI preflight |
| Pairing and owner private keys are not sent to storage | provisioning, config, storage APIs |
| Files publish only after size/digest sealing and peer completion | protocol sync/file transfer |
| Range and INIT verification are distinct from writes or acceptance | client and protocol outcome handling |
| Decryption requires an explicit owner key and authenticated GCM | `decrypt_enpt` |
| Generic signing remains caller-supplied; no embedded private identity | `Signer`, `Pkcs8Signer`, external adapters |
| Worker and clients verify content hashes | Worker, storage, mirror sync |

A diagnostic encryption label is metadata, not independent cryptographic attestation. Structural ciphertext validation is not proof of authenticity. Documentation and ignore rules reduce exposure but do not guarantee secrecy, legal compliance, or secure operation.

Before release, complete the provenance, secrets/history, ignore-rule, licence, artifact, and documentation checks in [CONTRIBUTING.md](CONTRIBUTING.md#release-checklist). Public refs are built from a single sanitized root commit; earlier objects may still exist in clones, forks, caches, or provider retention, and rewriting refs does not guarantee deletion everywhere.
