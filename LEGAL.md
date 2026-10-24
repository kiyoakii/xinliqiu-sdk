# Legal and publication notice

The MIT licence in [LICENSE](LICENSE) applies to the source code in this repository only. It grants no rights in third-party trademarks, protocols, or hardware.

This is an independent, unofficial interoperability project. It is not affiliated with, endorsed by, sponsored by, or supported by OPPO or its affiliates. “OPPO” and “心力球” are trademarks of their respective owners and are used descriptively; no trademark licence is implied.

## Authorized use

Use the SDK only with devices, credentials, keys, signing material, and data you own or are authorized to use. You are responsible for applicable law, agreements, privacy duties, and the consequences of device operations, including data loss, malfunction, warranty effects, and service disruption.

The intended implementation uses normal pairing and authorization exchanges and requires caller-supplied credentials for decryption. It does not disable or weaken device authentication, provide a universal key, flash firmware, or grant access to another person's recordings: INIT requires operator-supplied signing material and an owner key that the SDK verifies before radio use and again by readback. These statements describe project scope, not a legal determination or a guarantee about every use.

INIT will erase existing device content and requires separate informed confirmation, matching backed-up owner keys, and authorized signing material. It cannot recover lost private keys or old ciphertext and must not be repeated to obtain missing confirmation.

## Publication policy

The public source tree is intended to contain original code, generic protocol/signing interfaces, synthetic tests, and appropriately scoped observations from authorized hardware. Do not publish:

- vendor firmware, binaries, extracted/decompiled source, proprietary pseudocode, or analysis artifacts;
- private keys, reconstructed signing keys, secret key material, device credentials, account tokens, or private captures; public certificate fingerprints used only to verify genuine vendor artifacts are acceptable;
- instructions or artifacts whose publication you are not authorized to make;
- content that disables authentication, authorization, or integrity checks.

Private external signing adapters may contain sensitive provenance or reconstruction logic and must remain outside the public tree unless separately reviewed and explicitly approved for publication. The README Agent instruction is public guidance for an operator's private workflow; the APK, extracted material, and any recovered key must remain private. The instruction is not a zero-risk safe harbor or a licence to redistribute vendor material.

Releases are published from a single sanitized root commit. Earlier objects may still exist in clones, forks, caches, or provider backups; rewriting or deleting refs does not guarantee deletion everywhere. Review provenance, secrets, licences, and external copies before each release.

## Privacy

The SDK has no intended telemetry or maintainer phone-home path. Data goes to backends only when configured by the operator or caller. Default storage ingestion keeps plaintext diagnostics and unknown content local; caller-encrypted diagnostic upload is explicit opt-in. Operators remain responsible for protecting local data, logs, tokens, keys, backups, cloud accounts, and anything their own code exports.

See [Security and privacy](docs/security.md) for the threat model and [CONTRIBUTING.md](CONTRIBUTING.md) for release checks.

## Licence and warranty

Source code is available under the [MIT Licence](LICENSE), which does not grant rights in third-party trademarks, hardware, services, or proprietary materials.

The software is provided **“as is”, without warranty of any kind**, to the extent stated in that licence. Nothing in this notice guarantees legality, non-infringement, device safety, continued service compatibility, or recoverability of data.

Rights holders may open an issue describing a specific publication concern without including private material. Security reports should follow [SECURITY.md](SECURITY.md).
