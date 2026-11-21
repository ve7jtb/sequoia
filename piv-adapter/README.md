# Sequoia ↔ PQ Mail YubiKey 6 PIV adapter

Experimental external-key integration for Sequoia OpenPGP. It implements
`crypto::Signer` and `crypto::Decryptor`, reusing PQ Mail's existing PKCS#11
Python adapters and single-process native helpers. No changes to Sequoia's
parser, packet types, or cryptographic backend are required. This local crate
has not been submitted to or accepted by Sequoia.

The implementation has inline API and implementation comments describing the
cryptographic inputs, packet boundaries, slot mapping, cleanup, and failure
handling. It contains no provisioning or on-key write interface.

## Use as a separate library

This crate lives on the dedicated `development/yubikey6-piv` branch of
[ve7jtb/sequoia](https://github.com/ve7jtb/sequoia/tree/development/yubikey6-piv).
It is independent of the
[gws + Sequoia Chat transport](https://github.com/ve7jtb/gws-sequoia-chat).
Neither the adapter library nor its protocol needs a Google account, Chat,
PQ Mail's Java classes, or PQ Mail's identity/credential store.

An application outside this workspace can depend on the crate directly:

```toml
[dependencies]
sequoia-pqmail-piv = { git = "https://github.com/ve7jtb/sequoia", branch = "development/yubikey6-piv" }
```

Pin a reviewed commit with `rev` instead of `branch` for reproducible builds.
If the application also uses `sequoia-openpgp` types directly, select that
package from the same Git revision with `default-features = false` and
`features = ["crypto-openssl", "compression-deflate"]`, so Cargo does not
create incompatible duplicate instances of Sequoia's public types.
The crate is not yet published on crates.io.

The generic `Backend` trait separates the four component operations from
Sequoia packet handling. Use `Level3Signer<B>` and `Level3Decryptor<B>` with
your own backend, or the supplied `process::Pkcs11Operation` implementation.
The latter requires the Python PKCS#11 adapters, native helpers, OpenSSL
provider and Yubico module at explicitly configured paths. Those files can
be deployed separately; an installed PQ Mail GUI is not a runtime requirement.
The Java/PQ Mail references below are only for the optional cross-implementation
hardware test, not for using the Rust library.

Stock `sq` does not discover this adapter automatically. A separate helper or
Sequoia application must instantiate these interfaces. FIDO PRF storage and
local-browser integration are future layers, not functionality of this crate.

## Level 3 hardware profile

| OpenPGP operation | Component | PIV slot |
| --- | --- | --- |
| Level 3 hybrid signing | ML-DSA-65, external μ | `9c` |
| Level 3 hybrid signing | Ed25519 | `84` |
| Level 3 hybrid decryption | ML-KEM-768 decapsulation | `9d` |
| Level 3 hybrid decryption | X25519 agreement | `85` |

This is RFC 9980 OpenPGP, whose classical components differ from the P-384
components used by PQ Mail's Level 3 S/MIME profile. Certification slots
`86/87`, classical compatibility slots `88/89`, and S/MIME slots `82/83` are
not used by these Level 3 signing/decryption operations. Existing keys and
policies are retained.

`Level3Signer` signs the digest provided by Sequoia. It computes pure ML-DSA's
external μ with an empty context, signs the same OpenPGP digest with Ed25519,
and verifies the complete composite signature before returning it.
`Level3Decryptor` obtains the two component shared secrets, applies RFC 9980's
SHA3-256 combiner, and uses Sequoia's authenticated AES key unwrapping.

There is no classical fallback. Wrong public keys, component lengths,
unsupported algorithms, an all-zero X25519 result, damaged signatures, and
failed unwrapping stop the operation.

## Level 5 encrypted software companion

`Level5Signer`, `Level5Decryptor` and `companion::CompanionBackend` provide
RFC 9980 ML-DSA-87 + Ed448 signing and ML-KEM-1024 + X448 decryption when the
card lacks native Ed448/X448 support. ML-DSA-87 certification/signing keys stay
in slots `86/9c`, and ML-KEM-1024 stays in `9d`. Separate software Ed448
certification/signing keys and an X448 key are held in an empty-password PKCS#12
inside an AES-256-GCM companion. Slot `82` supplies P-384 ECDH for HKDF-SHA256
wrapping; no companion password is saved. The signed envelope binds the device
serial, hardware public keys, public OpenPGP certificate and component manifest.

`piv-companion-restore OBJECT_HELPER SERIAL NEW_DIRECTORY [--cache PUBLIC_CERTIFICATE]` reads this separate
companion bank (`5f5200` manifest and `5f5201`–`5f5220` chunks), validates its
signature and certificate bindings, and compares the live hardware keys. It
also rereads the manifest to reject changes during assembly. Full-certificate
restore needs no PIN; ultra restore either validates the supplied public cache
or requests authorization to reconstruct it as described below. It saves only
ciphertext and public information. It does not
grant certificate trust or expose the encrypted private keys. Private
operations then request a local PIN and unwrap the software keys in memory
through the existing PKCS#11 backend. Existing hardware touch policies remain
in force. The Rust/OpenSSL reader is independent of PQ Mail's Java code;
plaintext PFX/key material is exchanged through anonymous pipes, without a
plaintext-key filename.

The stored compression wrapper is eight ASCII bytes `PQMCZ001`, a big-endian
u32 expanded length, and one zlib stream. Stored and expanded sizes are limited
to 65,536 bytes. The parser requires a nonzero exact expanded length, a complete
stream with no trailing/concatenated data, and no nested wrapper. The card
manifest's SHA-256 covers the stored wrapper bytes. `Envelope::parse` expands
full-certificate envelopes before applying their cryptographic checks and also
accepts an unwrapped envelope for explicit compaction/recovery. Applying this
wrapper to a full `PQMCP001` envelope preserves the original signed envelope
**byte for byte**, including its certificate, fingerprints, signature, AAD and
ciphertext. Lossless compression itself never regenerates or re-signs anything.

This is software custody for the Ed448/X448 components, with classical P-384
protection at rest, not native hardware protection for those keys. Runtime
copies, caches, swap, hibernation, crash dumps, side channels or host compromise
can expose them. Clearing buffers is best effort. The message algorithms still
include their ML-DSA-87/ML-KEM-1024 components. These risks differ from the
strength of the message algorithms and from the physical/security assurances
of a particular hardware implementation.

The original companion passed a physical YubiKey 6 Beta0 test on 2026-11-20:
PQ Mail and Sequoia fresh restore, hybrid signing, hybrid decryption and
independent signature verification all passed. Snapshots confirmed unchanged
public keys, PIN/touch policies and empty/occupied states across all 24 ordinary
PIV slots, plus unchanged existing PIV certificates and public-bundle objects.
Only separate companion storage objects were added.

Lossless compression of that existing 46,412-byte companion produces **39,163
bytes** including the wrapper (7,249 bytes saved; 20 chunks instead of 23),
with exact inner-envelope preservation. Three focused tests cover round trips,
size limits, truncation, checksum errors, length mismatch, trailing data and
nesting. The compressed replacement hardware test passed on **2026-11-21**:
fresh card restore, hybrid signing, both implementations' decryption fixtures
and independent signature verification succeeded. Free storage increased from
18.0 to 25.8 KiB, with three fewer objects. All nine hardware keys, PIN/touch
policies, 24 PIV slot states, existing certificates and public-bundle objects
were unchanged. This is lossless storage compression, not certificate-signature
reconstruction. The full adapter software suite also passed all 18 tests.

### Optional ultra format and verified public cache

The adapter also reads explicitly selected `PQMCP002` ultra companions within
the same bounded `PQMCZ001` wrapper. Their certificate field is a reconstruction
template: own ML-DSA-87 + Ed448 signature values, two-byte digest checks and
32-byte v6 salts are zero placeholders, including the embedded signing-subkey
cross-certification. Public-key packet bytes, timestamps, User IDs, algorithm
identifiers, key flags and other supported metadata remain intact. The complete
outer hardware authentication signature remains present. Converting to this
format requires authenticated re-encryption for its changed AAD and a new outer
signature; it is separate from lossless compression.

A template is **not a transferable OpenPGP certificate**. On a fresh host,
`PendingEnvelope` independently validates its bounded packet structure, issuers,
key roles, flags, expiration and component mappings before any private call.
Only one certification primary, 1–5 certified User IDs, one cross-certified
signing subkey and one encryption subkey are supported. Unknown structures,
third-party certifications and revocations are refused for this format; they
must remain in the full-certificate format and are never silently discarded.
The implementation derives every signing digest from validated packets rather
than accepting arbitrary digest/signing requests from the template.

First-host reconstruction requests one hidden Terminal PIN, opens the companion
through P-384 slot `82`, reconstructs the cross-certification using `9c`, and
uses `86` for the certification signatures and enclosing bindings. Every new
signature receives a fresh CSPRNG salt. Existing touch policies apply. Each
signature is verified immediately; the resulting complete certificate also
passes Sequoia's current certificate policy. Exact public-key packets preserve
all primary/subkey fingerprints, although regenerated signatures change the
complete certificate bytes. Only the verified **public certificate** is cached;
software private keys, plaintext PKCS#12, PINs and wrapping secrets are not.

The restore command writes that public cache as `NEW_DIRECTORY/public.pgp`.
Supply it later with `--cache /absolute/path/public.pgp` to restore without
private operations. `Envelope::parse_with_cache` verifies its signatures and
current policies and compares its normalized template to the authenticated
on-card template; a filename, fingerprint alone or previous successful restore
is insufficient. Salt/signature placeholders and packet framing are normalized,
while retained metadata and key bodies must match. Cache use grants no trust.
An absent or invalid cache requires explicit reconstruction, with no silent
fallback to private operations. Normal signing/decryption uses the verified
cache and does not reconstruct certifications again.

For first-host reconstruction, set explicit backend paths in `PQMAIL_PYTHON`,
`PQMAIL_ADAPTERS`, `OPENSSL_BIN`, `PKCS11_PROVIDER` and `PKCS11_MODULE`. The
command's `SERIAL` selects the device; incoming metadata cannot override it.
These private-operation settings are unnecessary for `--cache` restore.

Software validation on **2026-11-21** passed all **22 adapter tests**, covering
compression boundaries, concurrent manifest changes, malformed reconstruction
requests, cache tampering, fresh salts, stable fingerprints and the existing
PKCS#11/public-bundle regressions. Java ↔ Rust interoperability also passed:
fresh ultra restore, independently verified signatures and encrypted messages
in both directions. With two User IDs, fresh restore made one slot-82 unwrap,
five slot-86 certifications and one slot-9c cross-signature. Cached restore
succeeded with private-operation configuration removed and **zero private
calls**; ordinary message operations made no certification calls.

That two-User-ID software fixture shrank from **43,918 to 15,431 stored bytes**
(**64.9%**), comparing the compressed full and ultra companions. This is an
encoded-size measurement, not measured physical card allocation. **Physical
ultra conversion/reconstruction testing is pending.** The successful hardware
results above apply to the original and losslessly compressed full companion.

## Backend and PIN handling

Use `process::Config` with absolute paths to the bundled Python interpreter,
adapter directory, OpenSSL executable, provider, and Yubico module. Set an
explicit device serial. `Pkcs11Operation::new` takes a wipe-on-drop PIN buffer.
Construct a fresh operation for each signature or message decryption.

The expected component public key is supplied to the existing PKCS#11 helper,
which compares it with the live selected slot before using its private key.
Each hardware component uses one native process/session; a Level 3 hybrid
operation uses two. Companion operations additionally unwrap their software
components through slot `82`; first-host ultra reconstruction also authorizes
its bounded certification operations. The PIN is reused only within that
logical operation and cleared afterward, including on errors. It is sent
through anonymous stdin pipes, never command arguments,
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
