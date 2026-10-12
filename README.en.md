# QualiaDeviceIdentityKit

A device identity toolkit: **P-256 device identity primitives** plus **platform-native
hardware keystores**.

It wraps "generate an ECDSA P-256 key inside the device hardware, read its public key, let
the hardware sign a message" in a safe Rust interface, and provides the **public-key side**
as well — representation, fingerprints and verification — so that callers never touch a
platform API and never reimplement the curve arithmetic.

The private key **never leaves the hardware** and never enters this process's address
space.

中文版见 [README.md](README.md).

## Two halves, one concept

| Module | Does | Holds the private key |
|--------|------|-----------------------|
| `device` | Public key representation, device fingerprint (`DeviceId`), verification | No |
| `keystore` | Key generation, public key lookup, signing | Yes (inside the hardware) |

Both halves share one error type. They are separate for a practical reason: **a device has
to be able to verify somebody else's signature while holding no hardware key of its own**
(a desktop machine without a TPM is exactly that).

```rust
use qualia_dik::{DeviceKeyStore, device};

let signer = store.open_or_create("account-1")?;

// The public key is not a secret and may be shared freely.
println!("device id: {}", signer.public_key().device_id());

let message = b"a message to sign";
let signature = signer.sign(message)?;

// Verification needs neither a keystore nor a private key.
device::verify(signer.public_key(), message, &signature)?;
```

## Status

Implemented:

- The abstraction: `DeviceKeyStore` / `DeviceSigner`, plus backend capability queries
- **Windows**: CNG `NCrypt*` + TPM 2.0 (`MS_PLATFORM_CRYPTO_PROVIDER`)
- **Windows without a TPM**: the CNG software key store path
- An in-memory backend for tests (the `mock` feature, **off by default**)

Not implemented: macOS (Secure Enclave), Linux (TPM 2.0), Android (Keystore / StrongBox),
iOS (Secure Enclave).

> `DeviceKeyStore::backend` reports the backend a key store is **actually** using at run
> time. On a Windows machine without a TPM it returns `Backend::Software`: the private key
> is stored in software and protected only by the operating system user account. **This
> layer never downgrades silently**; an unimplemented platform returns
> `UnsupportedPlatform`, and whether to accept a software key is the caller's decision,
> which means the user's.

> **`PlatformKeyStore` has different constructor signatures on the two platforms**: on
> Windows `open_best_available()` returns a `Result` (it really can fail: no TPM, disabled
> by group policy, key store in use), elsewhere it returns `Self` (the stub backend does
> nothing and cannot fail). That is deliberate — a `Result` there would only make callers
> write an error branch that is never taken.

## Using it in your own project

```toml
[dependencies]
qualia-dik = "0.1"
```

To use the in-memory backend in your own tests (for example to test protocol logic on a CI
machine without a TPM):

```toml
[dev-dependencies]
qualia-dik = { version = "0.1", features = ["mock"] }
```

```rust
use qualia_dik::{DeviceKeyStore, MockKeyStore};

let store = MockKeyStore::new();
let signer = store.create("test-device")?;
```

The "hardware" of the `mock` backend is a `HashMap`, and it **does not persist**. It is for
tests only: code that used it on a production path would fail immediately after a restart
(the key is gone) instead of running on with a key that has no hardware protection.

## Interface contracts

- **`label` is the persistent name of an identity** and accepts only ASCII letters, digits,
  `-`, `_` and `.`. It goes into the system key store's namespace, which is why a NUL or
  similar character is not allowed: `"a\0b"` and `"a"` are the same name to a C string, and
  two different identities would collide.
- **`create` never overwrites an existing key**; it returns `KeyAlreadyExists` instead. For
  "open it if it exists, create it otherwise", use `open_or_create`.
- **`delete` is irreversible**: that device can never prove it is the same device again,
  and the identities recorded on peer devices become unverifiable orphans. Ask the user
  before calling it.
- **`sign` takes a message, `sign_digest` takes a digest.** Signing and verification need
  exactly one answer to "who hashes", so message mode always uses SHA-256;
  `device::verify` follows the same convention.

## Contributing

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo test --doc --features mock   # the doc examples only have a backend under mock
cargo doc --no-deps                # no warnings (with RUSTDOCFLAGS="-D warnings")
cargo check --features mock        # the feature combinations have to compile too
cargo +1.89 check --all-targets --features mock
cargo deny check
```

Design and safety contracts:

- **This crate is the only place in the project where `unsafe` may appear**, and the only
  one that touches platform APIs. It exists so that the layers above can keep
  `#![forbid(unsafe_code)]`. Do **not** put protocol logic, cryptographic primitives or
  anything expressible in pure Rust in here.
- **Every `unsafe` block needs a `// SAFETY:` note** saying why its invariants hold.
- **The signing algorithm is fixed to ECDSA P-256.** That is a hard constraint rather than
  a preference: Android KeyMint has no EdDSA and Apple's Secure Enclave only supports NIST
  P-256.
- **No input may cause a panic.**
- **No secret material in errors.** This layer only handles public keys, messages and key
  names, so there is no secret to leak — do not break that property when adding a backend.
- **Never downgrade to a software key silently.** It would make the user believe hardware
  protection is in place when it is not.
- When adding a platform backend, add it to `platform_backend_is_implemented` as well and
  register it in the table in `src/keystore/platform.rs`.

### MSRV policy

The minimum supported Rust version is **1.89**. The MSRV moves with what the dependencies
actually need, and every move is verified in CI with a real toolchain
(`cargo +1.89 check --all-targets`).

## Releasing

Pushing a `v*` tag triggers the release workflow. It first verifies the packaged result
with `cargo publish --dry-run` on **every** target platform, publishes only once that
passes, and creates the matching git tag afterwards.

The `CRATES_IO_PUBLISH_KEY` secret (a crates.io API token with the `publish-new` and
`publish-update` scopes) has to be available to this repository.

## License

LGPL-3.0-or-later; see [LICENSE](LICENSE) and [COPYING.LESSER](COPYING.LESSER).

LGPL rather than MIT/Apache is deliberate: this crate handles the private keys behind a
device identity, so any modification should come back as source that can be audited.
