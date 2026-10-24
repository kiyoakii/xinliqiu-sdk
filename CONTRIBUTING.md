# Contributing

Keep changes original, useful, explicit, and verifiable offline. Do not remove generic protocol, signing, parsing, or retrieval functionality merely to make publication checks easier.

## Publication policy

Submit original interoperability code, generic adapters, synthetic tests, concise documentation, and appropriately scoped observations from authorized hardware. Device claims must identify their evidence limits; one observation is not a universal hardware rule.

Do not submit:

- vendor firmware, binaries, extracted/decompiled/reconstructed source, proprietary pseudocode, symbol/address tables, or analysis artifacts;
- private keys, reconstructed signing keys, secret key material, credentials, account tokens, private recordings/captures, or real device identifiers; public certificate fingerprints used only to verify genuine vendor artifacts are acceptable;
- ready-to-publish private adapter implementations containing sensitive provenance;
- anything that disables authentication, authorization, or integrity checks;
- links to sibling private tools or private evidence stores.

Use `Signer` and `Pkcs8Signer` as the generic INIT seam. The [README Agent instruction](README.md#给-agent准备-init-签名材料) lets operators privately prepare authorized signing material from the official APK. Keep the APK, recovered keys, and private implementation outside the public tree and test only with synthetic secrets. Public instructions are not a guarantee of zero legal or security risk.

Firmware flashing is out of scope. INIT remains supported and will erase existing content: it needs separate explicit authorization, matching backed-up owner keys, authorized signing material, and must never be repeated for missing confirmation.

## Engineering rules

1. Keep file transaction, container validity, range completion, and INIT verification distinct.
2. Return structured errors and safe `retry` guidance; empty or partial output is not automatically success.
3. Keep secrets and private capture contents out of logs, tests, fixtures, docs, and commit messages.
4. Keep storage ciphertext-only by default; caller-encrypted diagnostic upload is explicit opt-in.
5. Use synthetic credentials/payloads and no hardware or external service in tests.
6. Keep docs consistent with the actual CLI/API, including finite device-time examples and pending-pairing recovery.

## Offline development

Python 3.10+ and Node.js 22+ are required for the full suite. `cryptography` is a base dependency; BLE is not needed offline. WAV tests use `ffmpeg` when available; some audio tests may use OpenSSL.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e "python[dev]"
cd python
python -m pytest -q
cd ..
```

Standalone Python suites:

```bash
python tests/test_sdk.py
python tests/test_protocol.py
python tests/test_fixes_audio.py
python tests/test_fixes_storage.py
python tests/test_fixes_transfer.py
```

Worker and shell checks:

```bash
node --test cloudflare/test/
node --check cloudflare/src/index.js
bash -n cloudflare/setup.sh
```

The integration suite uses a local loopback server with mocked D1/R2. Do not deploy or connect hardware for tests.

## Release checklist

Complete and record every applicable check before publication:

- [ ] **Source/provenance:** review every added file and observation; confirm original code, authorized evidence scope, no vendor binaries/source/analysis artifacts, and no private sibling-tool links.
- [ ] **Commit attribution:** verify every reachable commit message is free of `Co-Authored-By`, agent names, and generated-with trailers (`git log --all --format=%B | grep -iE "co-author|claude|generated with"` must be empty). Rewrite history and recreate public refs if any survive.
- [ ] **Secrets and history:** scan tracked content, diffs, fixtures, logs, and full reachable git history for keys, tokens, credentials, private captures, real identifiers, and sensitive signing material. Confirm the release is built from the intended sanitized commit; remember that clones, forks, caches, and provider backups may retain older objects.
- [ ] **Exact ignore rules:** verify `.gitignore` covers `pairing*.json`, credential/capture/recording directories, APK and extracted-source outputs, caches, `.wrangler/`, `.dev.vars`, SPKI and private-key forms. Inspect `git status --ignored --short` and tracked files; ignore rules do not untrack existing files or clean history.
- [ ] **Third-party licences:** inventory Python and Node dependencies and bundled assets; retain required licence/notices and confirm no proprietary material is bundled.
- [ ] **Tests:** run the complete offline Python, standalone, Worker, and shell checks above with Node.js 22+.
- [ ] **Clean wheel/sdist:** remove prior build outputs, build both from a clean checkout, install/test the wheel in a fresh environment, and inspect both archives for only intended source, metadata, licences, and docs—no credentials, captures, vendor material, caches, or build leftovers.
- [ ] **Docs-to-CLI consistency:** compare commands/options/environment/exit codes with `python/aipin_sdk/cli.py`; check API names against exports; validate all local Markdown links and anchors; ensure examples use finite `<past-device-time-ms>` and pending recovery names `pairing.pending.json` explicitly.
- [ ] **Destructive/privacy warnings:** retain INIT authorization and no-repeat rules, owner-key backup, no-blind-retry, unverified-outcome, ciphertext-storage, and private-data warnings.
- [ ] **Final publication review:** inspect repository size and generated files, then have a reviewer assess legal/security uncertainty. No checklist eliminates legal risk.

Commit messages should identify the contract changed and why. Never commit generated credentials, captures, build outputs, deployment state, or secrets.
