# Sequoia ↔ PQ Mail YubiKey 6 PIV adapter

Experimental external-key integration for Sequoia OpenPGP. It implements
`crypto::Signer` and `crypto::Decryptor`, reusing PQ Mail's existing PKCS#11
Python adapters and single-process native helpers. No changes to Sequoia's
parser, packet types, or cryptographic backend are required. This local crate
has not been submitted to or accepted by Sequoia.

The implementation has inline API and implementation comments describing the
cryptographic inputs, packet boundaries, slot mapping, cleanup, and failure
handling. It contains no provisioning or on-key write interface.

## Supported profile

| OpenPGP operation | Component | PIV slot |
| --- | --- | --- |
| Level 3 hybrid signing | ML-DSA-65, external μ | `9c` |
| Level 3 hybrid signing | Ed25519 | `84` |
| Level 3 hybrid decryption | ML-KEM-768 decapsulation | `9d` |
| Level 3 hybrid decryption | X25519 agreement | `85` |

This is RFC 9980 OpenPGP, whose classical components differ from the P-384
components used by PQ Mail's Level 3 S/MIME profile. Certification slots
`86/87`, classical compatibility slots `88/89`, and S/MIME slots `82/83` are
not used by this adapter. Existing keys and policies are retained.

`Level3Signer` signs the digest provided by Sequoia. It computes pure ML-DSA's
external μ with an empty context, signs the same OpenPGP digest with Ed25519,
and verifies the complete composite signature before returning it.
`Level3Decryptor` obtains the two component shared secrets, applies RFC 9980's
SHA3-256 combiner, and uses Sequoia's authenticated AES key unwrapping.

There is no classical fallback. Wrong public keys, component lengths,
unsupported algorithms, an all-zero X25519 result, damaged signatures, and
failed unwrapping stop the operation.

## Backend and PIN handling

Use `process::Config` with absolute paths to the bundled Python interpreter,
adapter directory, OpenSSL executable, provider, and Yubico module. Set an
explicit device serial. `Pkcs11Operation::new` takes a wipe-on-drop PIN buffer.
Construct a fresh operation for each signature or message decryption.

The expected component public key is supplied to the existing PKCS#11 helper,
which compares it with the live selected slot before using its private key.
Each component uses one native process/session; a hybrid operation uses two.
The PIN is reused only across those components and cleared afterward, including
on errors. It is sent through anonymous stdin pipes, never command arguments,
environment values, files, or logs. OS/Python internals may make transient
copies; buffer wiping does not guarantee erasure of every such copy.

Inherited slot overrides are cleared. No private operation retries automatically.
The helper respects the token's current PIN/touch policies; it does not change
them. The library's `Signer`/`Decryptor` do not establish certificate trust:
applications must validate certificate bindings, validity, and user trust.

## Build and software tests

From the repository root, use a compiler satisfying the workspace requirements
and a supported, security-patched OpenSSL build with ML-DSA/ML-KEM support:

```sh
export OPENSSL_DIR=/absolute/path/to/openssl-prefix
export PQMAIL_TEST_OPENSSL="$OPENSSL_DIR/bin/openssl"
export PQMAIL_TEST_PYTHON=/absolute/path/to/python3
cargo build --locked -p sequoia-pqmail-piv
cargo test --locked -p sequoia-pqmail-piv
```

The software tests generate temporary OpenSSL keys and substitute a software
implementation of the adapter's pipe protocol. They never load a token module
or access a YubiKey. They check actual external-μ signatures, both signature
components, Sequoia encapsulation/adapter decapsulation for AES-sized session
keys, tampering, malformed output, key mismatches, and PIN cleanup.

Local validation on macOS (2026-11-19): all eight software integration tests
passed, followed by a successful physical YubiKey 6 Beta0 Level 3 test:

| Hardware operation | Result | Elapsed time |
| --- | --- | --- |
| Hybrid signing in `9c/84` | Verified by Sequoia and independently by PQ Mail/Bouncy Castle | 1,285 ms |
| Decrypt Sequoia ciphertext using `9d/85` | AEAD authentication and exact plaintext match | 878 ms |
| Decrypt PQ Mail/Bouncy Castle ciphertext using `9d/85` | AEAD authentication and exact plaintext match | 872 ms |

These are single-run operation durations after PIN entry, not a statistical
benchmark. The four tested component slots had touch policy Never; this run
does not establish touch-required behavior. The adapter preserved those
policies. Before/after snapshots matched for all 24 ordinary PIV slots,
including ten occupied slots' public keys, algorithms, origin, and PIN/touch
policies. The tested backend hashes also matched the installed PKCS#11 files.
No keys, policies, or token certificates were written, and no mail was sent.

## Hardware test

`piv-test inspect CERT OUTPUT_DIRECTORY` validates a public-only v6 certificate
and exports its expected component public SPKIs without requesting a PIN.
The test requires exactly one valid hybrid signing subkey and one valid hybrid
encryption subkey. It does not select the certification primary or classical
compatibility subkeys.

`hardware/run.py` coordinates the complete local test. Compile
`hardware/PqMailInterop.java` against PQ Mail's app JAR and dependencies first,
then provide its classpath, the public certificate, explicit serial, installed
app resources, Java executable, ykman executable, Rust binary, and a new output
directory. Run `python3 hardware/run.py --help` for arguments. The supplied
wrapper currently targets the Mac app's native layout; the Rust adapter's
configuration supports other platforms, which still need testing.

With `--preflight-only`, the wrapper checks all 24 ordinary PIV key slots,
matches the four public components, prepares a PQ Mail ciphertext, and compares
before/after snapshots. No private operations occur.

Without that flag, run in a local Terminal. Expect three hidden PIN prompts:

1. Sequoia/PIV hybrid signature, verified by Sequoia and PQ Mail/Bouncy Castle.
2. Sequoia-encrypted AEAD message decrypted through the PIV adapter.
3. PQ Mail/Bouncy Castle-encrypted AEAD message decrypted through the adapter.

Each decryption compares exact synthetic plaintext. No email is sent or read.
Before/after JSON records every ordinary slot's empty/occupied state, public-key
hash, algorithm, origin, PIN policy, and touch policy. The after comparison runs
on failure too; an incomplete snapshot never produces an unchanged assertion.
Results and public certificates should stay outside this source checkout.

This prototype does not yet replace PQ Mail's desktop backend, integrate into
Sequoia `sq`/IPC key discovery, or implement token certificate provisioning.
An upstream proposal should first agree the external-component interface and
avoid coupling Sequoia core to PQ Mail's subprocess protocol.
