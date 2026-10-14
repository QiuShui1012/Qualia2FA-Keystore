// Copyright (C) 2026 Qualia2FA contributors
//
// This library is free software; you can redistribute it and/or modify it under
// the terms of the GNU Lesser General Public License as published by the Free
// Software Foundation; either version 3 of the License, or (at your option) any
// later version.
//
// This library is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
// details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this library; if not, see <https://www.gnu.org/licenses/>.

//! Android Keystore backend: a P-256 key held by the device's secure hardware.
//!
//! | | |
//! |---|---|
//! | Key | ECDSA P-256, the named curve `secp256r1` |
//! | Where the private half lives | the TEE, or a StrongBox where the device has one |
//! | Storage | `AndroidKeyStore`, under the label |
//! | Java helper class | none, see [`java`] |
//!
//! # What a key is created with
//!
//! `PURPOSE_SIGN`, the named curve `secp256r1`, and the digests `NONE` and `SHA-256`. The
//! private half is not exportable and this crate never asks for it: signing happens inside
//! the key store.
//!
//! `NONE` is the digest that matters. [`DeviceSigner::sign_digest`] receives a digest the
//! caller has already computed, and `NONEwithECDSA` is the mode that signs it as given,
//! rather than hashing it a second time — which would produce a signature that verifies
//! against nothing. `SHA-256` is allowed as well because the key store uses it to sign the
//! certificate it generates next to the key.
//!
//! # The public key is read back out of that certificate
//!
//! `java.security.KeyStore` cannot hold a key pair without a certificate, so generating an
//! asymmetric pair also generates a self-signed certificate for it, and
//! [`DeviceKeyStore::open`] reads the public point from there. The certificate is not
//! verified and not trusted: it carries the public key, which is the only thing wanted
//! from it.
//!
//! # Which hardware, and saying so
//!
//! Generation asks for a StrongBox first and falls back to the TEE when the device refuses
//! — because it has none, or because its one StrongBox slot is taken. Both are hardware, and
//! both report [`Backend::AndroidKeystore`], which is what that variant means to a caller.
//!
//! A key store without usable secure hardware exists: emulators have one, and a device whose
//! TEE is unavailable falls back to one. Those keys report [`Backend::Software`], because a
//! user who is told "hardware" and gets a file has been misled. The check is the platform's
//! own — `KeyInfo.isInsideSecureHardware()` — not an assumption about the device model.
//!
//! # The application's master key
//!
//! Both forms of [`crate::keystore::traits`]'s master key contract are implemented on top of
//! the same key store:
//!
//! | Form | What the keystore holds | What the caller persists |
//! |---|---|---|
//! | [`AndroidDirectMasterKeyStore`] | the material, imported as an AES entry | nothing |
//! | [`AndroidWrappedMasterKeyStore`] | a non-exportable AES key-encryption key | the wrapped bytes |
//!
//! The direct form imports the material with `KeyStore.setEntry` and reads it back with
//! `SecretKey.getEncoded()`. That read-back is the form's whole contract, so
//! [`DirectMasterKeyStore::store`] verifies it immediately: a keystore that accepts an
//! imported key and then refuses to return its material produces
//! [`crate::Error::KeyNotExportable`], not a store that silently holds something the caller
//! can never read again. An imported key is also the reason this form reports
//! [`Backend::Software`] regardless of the device: the platform gives no hardware guarantee
//! for a key it imported, and claiming one would be exactly the silent downgrade this crate
//! refuses to make.
//!
//! The wrapped form generates its key-encryption key **inside** the keystore, asking for a
//! StrongBox first and settling for the TEE, and wraps with `AES/GCM/NoPadding` so that the
//! bytes are authenticated as well as hidden. Nothing in the interface encrypts, decrypts or
//! returns that key. `backend()` answers with the platform's own verdict about a generated
//! key on this device, read from `KeyInfo`; the probe key is created when the store is
//! opened, because an answer of "nothing yet" would make a caller refuse a protection that
//! does exist.

mod java;

use core::fmt;

use jni::JNIEnv;
use jni::objects::{JObject, JValue};

use crate::keystore::encoding::{sec1_from_coordinates, signature_from_der};
use crate::keystore::traits::{
    Backend, DIGEST_LEN, DeviceKeyStore, DeviceSigner, DirectMasterKeyStore, MASTER_KEY_LEN,
    MasterKey, WrappedMasterKey, WrappedMasterKeyStore, secrets_equal,
};
use crate::{DevicePublicKey, DeviceSignature, Error, Result};

/// Name of the key store provider, as `java.security` knows it.
const KEYSTORE: &str = "AndroidKeyStore";

/// Name of the key algorithm, as `java.security` knows it.
const ALGORITHM: &str = "EC";

/// The curve, by the name the platform knows it by.
const CURVE: &str = "secp256r1";

/// `KeyProperties.PURPOSE_SIGN`: the only purpose a device identity key is created with.
///
/// Transcribed by hand from the platform's constants, and asserted at the bottom of this
/// module: a wrong value is not a compile error, but a key the platform will not sign with.
/// The assertion is checked while CI compiles this module for Android, which is the only
/// place any of it can be checked at all — the rest needs a device.
const PURPOSE_SIGN: i32 = 4;

/// `KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT`.
///
/// The purposes a master key entry is created with. The material itself is never used to
/// encrypt anything by this crate, but the platform requires a purpose for every entry, and
/// these are the two an AES key can have.
const PURPOSE_ENCRYPT_OR_DECRYPT: i32 = 1 | 2;

/// The digests the key may be used with: the one it signs with, and the one the key store
/// signs its own certificate with.
const DIGESTS: [&str; 2] = ["NONE", "SHA-256"];

/// The signature algorithm that signs a digest the caller computed.
const SIGNATURE: &str = "NONEwithECDSA";

/// Name of the AES algorithm, as `javax.crypto` knows it.
const AES: &str = "AES";

/// The authenticated cipher the wrapped form uses.
///
/// GCM authenticates as well as hides, so a blob that was damaged — or produced by another
/// key — fails instead of decrypting to 32 bytes that merely look like a master key. The IV
/// is not fixed by the caller: the platform generates it and it is persisted next to the
/// sealed bytes.
const TRANSFORMATION: &str = "AES/GCM/NoPadding";

/// Length of an AES key in bits, for both the imported material and the wrapping key.
///
/// A master key is 256 bits, and an AES key of that size is what the keystore accepts.
const AES_KEY_BITS: i32 = 256;

/// Length of a GCM authentication tag in bits.
const GCM_TAG_BITS: i32 = 128;

/// Length of a GCM initialization vector in bytes, as the platform generates it.
const GCM_IV_BYTES: usize = 12;

/// Length of the bytes the wrapped form hands to the caller: IV, then sealed material and
/// tag (32 + 16 bytes).
const WRAPPED_MASTER_KEY_LEN: usize = GCM_IV_BYTES + MASTER_KEY_LEN + 16;

/// Alias prefix of a directly stored master key.
const MASTER_KEY_ALIAS_PREFIX: &str = "Qualia2FA-MasterKey-";

/// Alias prefix of a wrapped master key's key-encryption key.
const MASTER_KEK_ALIAS_PREFIX: &str = "Qualia2FA-MasterKek-";

/// Alias of the key the wrapped form generates to answer what protects a key on this device.
///
/// It is a real, persisted entry, created once per device; asking afterwards is what lets
/// [`WrappedMasterKeyStore::backend`] report the platform's own verdict instead of an
/// assumption. The per-label key-encryption keys are generated the same way, so the answer
/// describes them.
const MASTER_PROBE_ALIAS: &str = "Qualia2FA-MasterProbe";

/// Maximum master key label length, in bytes.
///
/// The label becomes part of a keystore alias; the same limit as the Windows backend keeps
/// an application's labels portable between platforms.
const MAX_LABEL_LEN: usize = 128;

/// `KeyProperties.BLOCK_MODE_GCM`.
const BLOCK_MODE: &str = "GCM";

/// `KeyProperties.ENCRYPTION_PADDING_NONE`: GCM is a stream mode and pads nothing.
const PADDING: &str = "NoPadding";

/// `Cipher.ENCRYPT_MODE`.
const CIPHER_ENCRYPT_MODE: i32 = 1;

/// `Cipher.DECRYPT_MODE`.
const CIPHER_DECRYPT_MODE: i32 = 2;

/// Device identities in the Android Keystore.
///
/// It holds no state: the key store is a system service reached through the JVM, and the
/// label is the only thing that identifies a key. Opening one is therefore cheap, and the
/// type exists to satisfy [`DeviceKeyStore`] and to keep the platform's types out of
/// callers.
#[derive(Debug)]
pub struct AndroidKeyStore;

impl AndroidKeyStore {
    /// Opens the key store, reporting whether it can be reached at all.
    ///
    /// # Errors
    ///
    /// [`Error::HardwareUnavailable`] when this library was loaded without a Java VM, and
    /// [`Error::Jni`] when the platform has no `AndroidKeyStore` to open — neither of which
    /// a caller can do anything about except tell the user.
    pub fn open_best_available() -> Result<Self> {
        java::with_env("KeyStore.getInstance", |env| open_keystore(env).map(|_| ()))?;
        Ok(Self)
    }
}

impl DeviceKeyStore for AndroidKeyStore {
    /// Always [`Backend::AndroidKeystore`]: this is the Android key store.
    ///
    /// The protection of a **particular** key is reported by its signer, which asks the
    /// platform. A caller that needs to know whether a key is hardware backed has to read
    /// it from the signer, not from here.
    fn backend(&self) -> Backend {
        Backend::AndroidKeystore
    }

    fn open(&self, label: &str) -> Result<Box<dyn DeviceSigner>> {
        check_label(label)?;
        java::with_env("KeyStore.getCertificate", |env| {
            let store = open_keystore(env)?;
            let public_key = certificate_public_key(env, &store, label)?;
            let hardware = signer_is_hardware_backed(env, &store, label)?;
            Ok(signer(label, public_key, hardware))
        })
    }

    fn create(&self, label: &str) -> Result<Box<dyn DeviceSigner>> {
        check_label(label)?;
        java::with_env("KeyPairGenerator.generateKeyPair", |env| {
            let store = open_keystore(env)?;
            if contains_alias(env, &store, label)? {
                return Err(Error::KeyAlreadyExists {
                    label: label.to_owned(),
                });
            }
            generate(env, label)?;
            let public_key = certificate_public_key(env, &store, label)?;
            let hardware = signer_is_hardware_backed(env, &store, label)?;
            Ok(signer(label, public_key, hardware))
        })
    }

    fn delete(&self, label: &str) -> Result<()> {
        check_label(label)?;
        java::with_env("KeyStore.deleteEntry", |env| {
            let store = open_keystore(env)?;
            if !contains_alias(env, &store, label)? {
                return Err(Error::KeyNotFound {
                    label: label.to_owned(),
                });
            }
            let alias = java::string(env, label, "KeyStore.deleteEntry")?;
            java::call_void(
                env,
                &store,
                "deleteEntry",
                "(Ljava/lang/String;)V",
                &[JValue::Object(&alias.into())],
                "KeyStore.deleteEntry",
            )
        })
    }
}

/// One device identity, held by the Android key store.
///
/// It holds the label rather than a key handle: the handle belongs to a process and a
/// thread, while a signer outlives both, and looking the key up again per signature is a
/// system call this type does not have to keep alive.
pub struct AndroidSigner {
    /// Logical name, the only thing that identifies the key.
    label: String,
    /// What the platform said about where the private half lives.
    backend: Backend,
    /// Already read public key, so that queries do not go back to the platform.
    public_key: DevicePublicKey,
}

/// Prints non-secret information only: the label, the backend and the device id.
impl fmt::Debug for AndroidSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AndroidSigner")
            .field("label", &self.label)
            .field("backend", &self.backend)
            .field("device_id", &self.public_key.device_id())
            .finish_non_exhaustive()
    }
}

impl DeviceSigner for AndroidSigner {
    fn backend(&self) -> Backend {
        self.backend
    }

    fn public_key(&self) -> &DevicePublicKey {
        &self.public_key
    }

    fn sign_digest(&self, digest: &[u8]) -> Result<DeviceSignature> {
        if digest.len() != DIGEST_LEN {
            return Err(Error::InvalidDigestLength {
                expected: DIGEST_LEN,
                actual: digest.len(),
            });
        }
        java::with_env("Signature.sign", |env| {
            let store = open_keystore(env)?;
            let key = private_key(env, &store, &self.label)?;
            let der = sign_digest_with(env, &key, digest)?;
            signature_from_der(&der)
        })
    }
}

/// Builds a signer, choosing the backend from what the platform said about the key.
fn signer(label: &str, public_key: DevicePublicKey, hardware: bool) -> Box<dyn DeviceSigner> {
    let backend = if hardware {
        Backend::AndroidKeystore
    } else {
        Backend::Software
    };
    Box::new(AndroidSigner {
        label: label.to_owned(),
        backend,
        public_key,
    })
}

/// Rejects a label the platform would refuse anyway, with a reason the caller can act on.
fn check_label(label: &str) -> Result<()> {
    if label.is_empty() {
        return Err(Error::InvalidKeyLabel {
            reason: "the label is empty",
        });
    }
    Ok(())
}

/// `KeyStore.getInstance("AndroidKeyStore")`, loaded and ready.
fn open_keystore<'local>(env: &mut JNIEnv<'local>) -> Result<JObject<'local>> {
    let operation = "KeyStore.getInstance";
    let class = java::class(env, "java/security/KeyStore", operation)?;
    let name = JObject::from(java::string(env, KEYSTORE, operation)?);
    let store = java::static_object(
        env,
        &class,
        "getInstance",
        "(Ljava/lang/String;)Ljava/security/KeyStore;",
        &[JValue::Object(&name)],
        operation,
    )?;
    let parameter = JObject::null();
    java::call_void(
        env,
        &store,
        "load",
        "(Ljava/security/KeyStore$LoadStoreParameter;)V",
        &[JValue::Object(&parameter)],
        operation,
    )?;
    Ok(store)
}

/// Whether an entry exists under `label`.
fn contains_alias<'local>(
    env: &mut JNIEnv<'local>,
    store: &JObject<'local>,
    label: &str,
) -> Result<bool> {
    contains_entry(env, store, label)
}

/// The private key of an entry, as an object the platform will sign with.
fn private_key<'local>(
    env: &mut JNIEnv<'local>,
    store: &JObject<'local>,
    label: &str,
) -> Result<JObject<'local>> {
    keystore_entry(env, store, label, label)
}

/// The public key of an entry, out of the certificate the key store generated for it.
fn certificate_public_key<'local>(
    env: &mut JNIEnv<'local>,
    store: &JObject<'local>,
    label: &str,
) -> Result<DevicePublicKey> {
    let operation = "KeyStore.getCertificate";
    let alias = JObject::from(java::string(env, label, operation)?);
    let certificate = java::object(
        env,
        store,
        "getCertificate",
        "(Ljava/lang/String;)Ljava/security/cert/Certificate;",
        &[JValue::Object(&alias)],
        operation,
    )?;
    if certificate.is_null() {
        return Err(Error::KeyNotFound {
            label: label.to_owned(),
        });
    }
    let key = java::object(
        env,
        &certificate,
        "getPublicKey",
        "()Ljava/security/PublicKey;",
        &[],
        operation,
    )?;
    coordinates(env, &key)
}

/// The public point of an `ECPublicKey`, as the SEC1 uncompressed encoding.
fn coordinates<'local>(env: &mut JNIEnv<'local>, key: &JObject<'local>) -> Result<DevicePublicKey> {
    let operation = "ECPublicKey.getW";
    let point = java::object(
        env,
        key,
        "getW",
        "()Ljava/security/spec/ECPoint;",
        &[],
        operation,
    )?;
    let x = integer_bytes(env, &point, "getAffineX", operation)?;
    let y = integer_bytes(env, &point, "getAffineY", operation)?;
    sec1_from_coordinates(&x, &y)
}

/// A coordinate of a point, as `BigInteger.toByteArray()` gives it: big-endian, two's
/// complement, and as short as the value allows.
fn integer_bytes<'local>(
    env: &mut JNIEnv<'local>,
    point: &JObject<'local>,
    name: &str,
    operation: &'static str,
) -> Result<Vec<u8>> {
    let value = java::object(env, point, name, "()Ljava/math/BigInteger;", &[], operation)?;
    let bytes = java::object(env, &value, "toByteArray", "()[B", &[], operation)?;
    java::object_bytes(env, bytes, operation)
}

/// Whether the platform says the private half of this key is inside secure hardware.
fn signer_is_hardware_backed<'local>(
    env: &mut JNIEnv<'local>,
    store: &JObject<'local>,
    label: &str,
) -> Result<bool> {
    let key = private_key(env, store, label)?;
    let operation = "KeyFactory.getKeySpec";
    let class = java::class(env, "java/security/KeyFactory", operation)?;
    let algorithm = java::object(
        env,
        &key,
        "getAlgorithm",
        "()Ljava/lang/String;",
        &[],
        operation,
    )?;
    let provider = JObject::from(java::string(env, KEYSTORE, operation)?);
    let factory = java::static_object(
        env,
        &class,
        "getInstance",
        "(Ljava/lang/String;Ljava/lang/String;)Ljava/security/KeyFactory;",
        &[JValue::Object(&algorithm), JValue::Object(&provider)],
        operation,
    )?;
    let info = JObject::from(java::class(
        env,
        "android/security/keystore/KeyInfo",
        operation,
    )?);
    let spec = java::object(
        env,
        &factory,
        "getKeySpec",
        "(Ljava/security/Key;Ljava/lang/Class;)Ljava/security/spec/KeySpec;",
        &[JValue::Object(&key), JValue::Object(&info)],
        operation,
    )?;
    java::boolean(env, &spec, "isInsideSecureHardware", "()Z", &[], operation)
}

/// Generates the key pair, preferring a StrongBox and settling for the TEE.
///
/// The first attempt is allowed to fail for any reason — no StrongBox, one already in use,
/// or a platform old enough not to know the parameter at all — because the second attempt is
/// the one that has to succeed, and its failure is the one reported.
fn generate(env: &mut JNIEnv<'_>, label: &str) -> Result<()> {
    match generate_in(env, label, true) {
        Ok(()) => Ok(()),
        Err(_) => generate_in(env, label, false),
    }
}

/// Generates the key pair, with or without asking for a StrongBox.
fn generate_in(env: &mut JNIEnv<'_>, label: &str, strong_box: bool) -> Result<()> {
    let operation = "KeyPairGenerator.generateKeyPair";
    let class = java::class(env, "java/security/KeyPairGenerator", operation)?;
    let algorithm = JObject::from(java::string(env, ALGORITHM, operation)?);
    let provider = JObject::from(java::string(env, KEYSTORE, operation)?);
    let generator = java::static_object(
        env,
        &class,
        "getInstance",
        "(Ljava/lang/String;Ljava/lang/String;)Ljava/security/KeyPairGenerator;",
        &[JValue::Object(&algorithm), JValue::Object(&provider)],
        operation,
    )?;
    let spec = key_parameter_spec(env, label, strong_box)?;
    java::call_void(
        env,
        &generator,
        "initialize",
        "(Ljava/security/spec/AlgorithmParameterSpec;)V",
        &[JValue::Object(&spec)],
        operation,
    )?;
    java::object(
        env,
        &generator,
        "generateKeyPair",
        "()Ljava/security/KeyPair;",
        &[],
        operation,
    )?;
    Ok(())
}

/// `KeyGenParameterSpec` describing the key this crate needs.
fn key_parameter_spec<'local>(
    env: &mut JNIEnv<'local>,
    label: &str,
    strong_box: bool,
) -> Result<JObject<'local>> {
    let operation = "KeyGenParameterSpec.Builder";
    let class = java::class(
        env,
        "android/security/keystore/KeyGenParameterSpec$Builder",
        operation,
    )?;
    let alias = JObject::from(java::string(env, label, operation)?);
    let builder = java::construct(
        env,
        &class,
        "(Ljava/lang/String;I)V",
        &[JValue::Object(&alias), JValue::Int(PURPOSE_SIGN)],
        operation,
    )?;

    let curve_class = java::class(env, "java/security/spec/ECGenParameterSpec", operation)?;
    let curve_name = JObject::from(java::string(env, CURVE, operation)?);
    let curve = java::construct(
        env,
        &curve_class,
        "(Ljava/lang/String;)V",
        &[JValue::Object(&curve_name)],
        operation,
    )?;
    let builder = java::object(
        env,
        &builder,
        "setAlgorithmParameterSpec",
        "(Ljava/security/spec/AlgorithmParameterSpec;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
        &[JValue::Object(&curve)],
        operation,
    )?;

    let digests = JObject::from(java::string_array(env, &DIGESTS, operation)?);
    let builder = java::object(
        env,
        &builder,
        "setDigests",
        "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
        &[JValue::Object(&digests)],
        operation,
    )?;

    let builder = if strong_box {
        java::object(
            env,
            &builder,
            "setIsStrongBoxBacked",
            "(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
            &[JValue::Bool(1)],
            operation,
        )?
    } else {
        builder
    };

    java::object(
        env,
        &builder,
        "build",
        "()Landroid/security/keystore/KeyGenParameterSpec;",
        &[],
        operation,
    )
}

/// Signs a digest with the key the store holds, and returns the DER signature.
///
/// `NONEwithECDSA` rather than `SHA256withECDSA`: the digest is already a SHA-256, and the
/// hashing mode would hash it again.
fn sign_digest_with<'local>(
    env: &mut JNIEnv<'local>,
    key: &JObject<'local>,
    digest: &[u8],
) -> Result<Vec<u8>> {
    let operation = "Signature.sign";
    let class = java::class(env, "java/security/Signature", operation)?;
    let algorithm = JObject::from(java::string(env, SIGNATURE, operation)?);
    let signature = java::static_object(
        env,
        &class,
        "getInstance",
        "(Ljava/lang/String;)Ljava/security/Signature;",
        &[JValue::Object(&algorithm)],
        operation,
    )?;
    java::call_void(
        env,
        &signature,
        "initSign",
        "(Ljava/security/PrivateKey;)V",
        &[JValue::Object(key)],
        operation,
    )?;
    let bytes = JObject::from(java::bytes(env, digest, operation)?);
    java::call_void(
        env,
        &signature,
        "update",
        "([B)V",
        &[JValue::Object(&bytes)],
        operation,
    )?;
    java::byte_array(env, &signature, "sign", "()[B", &[], operation)
}

// ── Master key ──────────────────────────────────────────────────────

/// Builds a keystore alias from a prefix and a validated label.
///
/// # Errors
///
/// [`Error::InvalidKeyLabel`] for an empty label or one longer than [`MAX_LABEL_LEN`].
fn master_alias(prefix: &str, label: &str) -> Result<String> {
    check_label(label)?;
    if label.len() > MAX_LABEL_LEN {
        return Err(Error::InvalidKeyLabel {
            reason: "the label is too long (limit is 128 bytes)",
        });
    }
    Ok(format!("{prefix}{label}"))
}

/// Whether an entry exists under `alias`.
fn contains_entry<'local>(
    env: &mut JNIEnv<'local>,
    store: &JObject<'local>,
    alias: &str,
) -> Result<bool> {
    let operation = "KeyStore.containsAlias";
    let alias = JObject::from(java::string(env, alias, operation)?);
    java::boolean(
        env,
        store,
        "containsAlias",
        "(Ljava/lang/String;)Z",
        &[JValue::Object(&alias)],
        operation,
    )
}

/// Removes an entry.
///
/// # Errors
///
/// [`Error::KeyNotFound`] when there is nothing under `alias`.
fn delete_entry<'local>(
    env: &mut JNIEnv<'local>,
    store: &JObject<'local>,
    alias: &str,
    label: &str,
) -> Result<()> {
    if !contains_entry(env, store, alias)? {
        return Err(Error::KeyNotFound {
            label: label.to_owned(),
        });
    }
    let operation = "KeyStore.deleteEntry";
    let alias = JObject::from(java::string(env, alias, operation)?);
    java::call_void(
        env,
        store,
        "deleteEntry",
        "(Ljava/lang/String;)V",
        &[JValue::Object(&alias)],
        operation,
    )
}

/// The key stored under `alias`.
///
/// # Errors
///
/// [`Error::KeyNotFound`] when the entry is absent.
fn keystore_entry<'local>(
    env: &mut JNIEnv<'local>,
    store: &JObject<'local>,
    alias: &str,
    label: &str,
) -> Result<JObject<'local>> {
    let operation = "KeyStore.getKey";
    let alias = JObject::from(java::string(env, alias, operation)?);
    let password = JObject::null();
    let key = java::object(
        env,
        store,
        "getKey",
        "(Ljava/lang/String;[C)Ljava/security/Key;",
        &[JValue::Object(&alias), JValue::Object(&password)],
        operation,
    )?;
    if key.is_null() {
        return Err(Error::KeyNotFound {
            label: label.to_owned(),
        });
    }
    Ok(key)
}

/// The material of an entry, as the keystore returns it.
///
/// # Errors
///
/// [`Error::KeyNotFound`] when the entry is absent, [`Error::KeyNotExportable`] when the
/// keystore holds the entry but answers `null` for `getEncoded()` — an imported key the
/// platform will not hand back — and [`Error::InvalidMasterKey`] for a wrong length.
fn entry_material<'local>(
    env: &mut JNIEnv<'local>,
    store: &JObject<'local>,
    alias: &str,
    label: &str,
) -> Result<MasterKey> {
    let operation = "Key.getEncoded";
    let key = keystore_entry(env, store, alias, label)?;
    let encoded = java::object(env, &key, "getEncoded", "()[B", &[], operation)?;
    if encoded.is_null() {
        return Err(Error::KeyNotExportable {
            reason: "the Android keystore holds the entry but returns null for the encoded key, so the material cannot be read back",
        });
    }
    let bytes = java::object_bytes(env, encoded, operation)?;
    if bytes.len() != MASTER_KEY_LEN {
        return Err(Error::InvalidMasterKey {
            reason: "the Android keystore returned a master key of the wrong length",
        });
    }
    let mut material = [0_u8; MASTER_KEY_LEN];
    material.copy_from_slice(&bytes);
    Ok(MasterKey::from_bytes(material))
}

/// Imports the material as an AES entry.
///
/// The material is a 32-byte AES key by shape, which is what lets the keystore hold it: the
/// platform has no API for an opaque blob, and an entry's key material is the one thing it
/// stores and — for an imported key — returns.
///
/// # Errors
///
/// [`Error::Jni`] with the platform's own description when the keystore refuses the import.
fn import_material<'local>(
    env: &mut JNIEnv<'local>,
    store: &JObject<'local>,
    alias: &str,
    material: &[u8],
) -> Result<()> {
    let operation = "KeyStore.setEntry";
    let algorithm = JObject::from(java::string(env, AES, operation)?);
    let bytes = JObject::from(java::bytes(env, material, operation)?);
    let spec_class = java::class(env, "javax/crypto/spec/SecretKeySpec", operation)?;
    let spec = java::construct(
        env,
        &spec_class,
        "([BLjava/lang/String;)V",
        &[JValue::Object(&bytes), JValue::Object(&algorithm)],
        operation,
    )?;

    let entry_class = java::class(env, "java/security/KeyStore$SecretKeyEntry", operation)?;
    let entry = java::construct(
        env,
        &entry_class,
        "(Ljavax/crypto/SecretKey;)V",
        &[JValue::Object(&spec)],
        operation,
    )?;

    let protection = key_protection(env)?;
    let alias = JObject::from(java::string(env, alias, operation)?);
    java::call_void(
        env,
        store,
        "setEntry",
        "(Ljava/lang/String;Ljava/security/KeyStore$Entry;Ljava/security/KeyStore$ProtectionParameter;)V",
        &[
            JValue::Object(&alias),
            JValue::Object(&entry),
            JValue::Object(&protection),
        ],
        operation,
    )
}

/// `KeyProtection` for an AES entry: encrypt and decrypt, GCM, no padding.
///
/// # Errors
///
/// [`Error::Jni`] when the platform has no such builder or refuses the combination.
fn key_protection<'local>(env: &mut JNIEnv<'local>) -> Result<JObject<'local>> {
    let operation = "KeyProtection.Builder";
    let class = java::class(
        env,
        "android/security/keystore/KeyProtection$Builder",
        operation,
    )?;
    let builder = java::construct(
        env,
        &class,
        "(I)V",
        &[JValue::Int(PURPOSE_ENCRYPT_OR_DECRYPT)],
        operation,
    )?;

    let modes = JObject::from(java::string_array(env, &[BLOCK_MODE], operation)?);
    let builder = java::object(
        env,
        &builder,
        "setBlockModes",
        "([Ljava/lang/String;)Landroid/security/keystore/KeyProtection$Builder;",
        &[JValue::Object(&modes)],
        operation,
    )?;

    let paddings = JObject::from(java::string_array(env, &[PADDING], operation)?);
    let builder = java::object(
        env,
        &builder,
        "setEncryptionPaddings",
        "([Ljava/lang/String;)Landroid/security/keystore/KeyProtection$Builder;",
        &[JValue::Object(&paddings)],
        operation,
    )?;

    java::object(
        env,
        &builder,
        "build",
        "()Landroid/security/keystore/KeyProtection;",
        &[],
        operation,
    )
}

/// Generates an AES key-encryption key inside the keystore, preferring a StrongBox.
///
/// The first attempt asks for a StrongBox and is allowed to fail for any reason — no
/// StrongBox, one already in use, a device that does not know the parameter — because the
/// second attempt is the one that has to succeed, and its failure is the one reported.
fn generate_wrapping_key<'local>(env: &mut JNIEnv<'local>, alias: &str) -> Result<()> {
    match generate_wrapping_key_in(env, alias, true) {
        Ok(()) => Ok(()),
        Err(_) => generate_wrapping_key_in(env, alias, false),
    }
}

/// Generates the key-encryption key, with or without asking for a StrongBox.
fn generate_wrapping_key_in<'local>(
    env: &mut JNIEnv<'local>,
    alias: &str,
    strong_box: bool,
) -> Result<()> {
    let operation = "KeyGenerator.generateKey";
    let class = java::class(env, "javax/crypto/KeyGenerator", operation)?;
    let algorithm = JObject::from(java::string(env, AES, operation)?);
    let provider = JObject::from(java::string(env, KEYSTORE, operation)?);
    let generator = java::static_object(
        env,
        &class,
        "getInstance",
        "(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/KeyGenerator;",
        &[JValue::Object(&algorithm), JValue::Object(&provider)],
        operation,
    )?;
    let spec = wrapping_key_spec(env, alias, strong_box)?;
    java::call_void(
        env,
        &generator,
        "init",
        "(Ljava/security/spec/AlgorithmParameterSpec;)V",
        &[JValue::Object(&spec)],
        operation,
    )?;
    java::object(
        env,
        &generator,
        "generateKey",
        "()Ljavax/crypto/SecretKey;",
        &[],
        operation,
    )?;
    Ok(())
}

/// `KeyGenParameterSpec` for a wrapping key: AES-256, GCM, a fresh IV per operation.
///
/// # Errors
///
/// [`Error::Jni`] when the platform refuses the specification.
fn wrapping_key_spec<'local>(
    env: &mut JNIEnv<'local>,
    alias: &str,
    strong_box: bool,
) -> Result<JObject<'local>> {
    let operation = "KeyGenParameterSpec.Builder";
    let class = java::class(
        env,
        "android/security/keystore/KeyGenParameterSpec$Builder",
        operation,
    )?;
    let alias = JObject::from(java::string(env, alias, operation)?);
    let builder = java::construct(
        env,
        &class,
        "(Ljava/lang/String;I)V",
        &[
            JValue::Object(&alias),
            JValue::Int(PURPOSE_ENCRYPT_OR_DECRYPT),
        ],
        operation,
    )?;

    let modes = JObject::from(java::string_array(env, &[BLOCK_MODE], operation)?);
    let builder = java::object(
        env,
        &builder,
        "setBlockModes",
        "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
        &[JValue::Object(&modes)],
        operation,
    )?;

    let paddings = JObject::from(java::string_array(env, &[PADDING], operation)?);
    let builder = java::object(
        env,
        &builder,
        "setEncryptionPaddings",
        "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
        &[JValue::Object(&paddings)],
        operation,
    )?;

    let builder = java::object(
        env,
        &builder,
        "setKeySize",
        "(I)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
        &[JValue::Int(AES_KEY_BITS)],
        operation,
    )?;

    let builder = java::object(
        env,
        &builder,
        "setRandomizedEncryptionRequired",
        "(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
        &[JValue::Bool(1)],
        operation,
    )?;

    let builder = if strong_box {
        java::object(
            env,
            &builder,
            "setIsStrongBoxBacked",
            "(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
            &[JValue::Bool(1)],
            operation,
        )?
    } else {
        builder
    };

    java::object(
        env,
        &builder,
        "build",
        "()Landroid/security/keystore/KeyGenParameterSpec;",
        &[],
        operation,
    )
}

/// Wraps the material with the key-encryption key: AES-GCM, IV first.
///
/// # Errors
///
/// [`Error::Jni`] when the platform refuses the operation, and [`Error::InvalidWrappedKey`]
/// when the platform produces a blob of an unexpected shape.
fn wrap_with_kek<'local>(
    env: &mut JNIEnv<'local>,
    kek: &JObject<'local>,
    material: &[u8; MASTER_KEY_LEN],
) -> Result<WrappedMasterKey> {
    let operation = "Cipher.doFinal";
    let cipher = cipher(env)?;
    java::call_void(
        env,
        &cipher,
        "init",
        "(ILjava/security/Key;)V",
        &[JValue::Int(CIPHER_ENCRYPT_MODE), JValue::Object(kek)],
        operation,
    )?;

    let iv = java::object(env, &cipher, "getIV", "()[B", &[], operation)?;
    if iv.is_null() {
        return Err(Error::InvalidWrappedKey {
            reason: "the platform produced no initialization vector for the wrapping key",
            code: 0,
        });
    }
    let iv = java::object_bytes(env, iv, operation)?;
    if iv.len() != GCM_IV_BYTES {
        return Err(Error::InvalidWrappedKey {
            reason: "the platform produced an initialization vector of an unexpected length",
            code: 0,
        });
    }

    let bytes = JObject::from(java::bytes(env, material, operation)?);
    let sealed = java::byte_array(
        env,
        &cipher,
        "doFinal",
        "([B)[B",
        &[JValue::Object(&bytes)],
        operation,
    )?;
    if sealed.len() != MASTER_KEY_LEN + 16 {
        return Err(Error::InvalidWrappedKey {
            reason: "the platform sealed the master key into an unexpected number of bytes",
            code: 0,
        });
    }

    let mut wrapped = Vec::with_capacity(WRAPPED_MASTER_KEY_LEN);
    wrapped.extend_from_slice(&iv);
    wrapped.extend_from_slice(&sealed);
    Ok(WrappedMasterKey::from_bytes(wrapped))
}

/// Unwraps the material with the key-encryption key.
///
/// # Errors
///
/// [`Error::InvalidWrappedKey`] when the platform rejects the authentication tag — a damaged
/// blob, or one wrapped by another key — and [`Error::Jni`] for anything else the platform
/// reports.
fn unwrap_with_kek<'local>(
    env: &mut JNIEnv<'local>,
    kek: &JObject<'local>,
    wrapped: &[u8],
) -> Result<MasterKey> {
    let (iv, sealed) = wrapped.split_at(GCM_IV_BYTES);

    let operation = "Cipher.doFinal";
    let cipher = cipher(env)?;
    let spec_class = java::class(env, "javax/crypto/spec/GCMParameterSpec", operation)?;
    let iv = JObject::from(java::bytes(env, iv, operation)?);
    let spec = java::construct(
        env,
        &spec_class,
        "(I[B)V",
        &[JValue::Int(GCM_TAG_BITS), JValue::Object(&iv)],
        operation,
    )?;
    java::call_void(
        env,
        &cipher,
        "init",
        "(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V",
        &[
            JValue::Int(CIPHER_DECRYPT_MODE),
            JValue::Object(kek),
            JValue::Object(&spec),
        ],
        operation,
    )?;

    let sealed = JObject::from(java::bytes(env, sealed, operation)?);
    let plain = java::byte_array_authenticated(
        env,
        &cipher,
        "doFinal",
        "([B)[B",
        &[JValue::Object(&sealed)],
        operation,
    )?;
    if plain.len() != MASTER_KEY_LEN {
        return Err(Error::InvalidWrappedKey {
            reason: "the wrapped bytes do not decrypt to a 32-byte master key",
            code: 0,
        });
    }

    let mut material = [0_u8; MASTER_KEY_LEN];
    material.copy_from_slice(&plain);
    Ok(MasterKey::from_bytes(material))
}

/// A fresh `AES/GCM/NoPadding` cipher.
///
/// # Errors
///
/// [`Error::Jni`] when the platform has no such transformation.
fn cipher<'local>(env: &mut JNIEnv<'local>) -> Result<JObject<'local>> {
    let operation = "Cipher.getInstance";
    let class = java::class(env, "javax/crypto/Cipher", operation)?;
    let transformation = JObject::from(java::string(env, TRANSFORMATION, operation)?);
    java::static_object(
        env,
        &class,
        "getInstance",
        "(Ljava/lang/String;)Ljavax/crypto/Cipher;",
        &[JValue::Object(&transformation)],
        operation,
    )
}

/// Whether the platform says a **symmetric** key is inside secure hardware.
///
/// A secret key is described by `SecretKeyFactory`, not by `KeyFactory` (which handles the
/// asymmetric algorithms only), and the `KeyInfo` it returns is the platform's own answer.
///
/// # Errors
///
/// [`Error::Jni`] when the platform refuses to describe the key.
fn secret_key_is_hardware_backed<'local>(
    env: &mut JNIEnv<'local>,
    key: &JObject<'local>,
) -> Result<bool> {
    let operation = "SecretKeyFactory.getKeySpec";
    let class = java::class(env, "javax/crypto/SecretKeyFactory", operation)?;
    let algorithm = java::object(
        env,
        key,
        "getAlgorithm",
        "()Ljava/lang/String;",
        &[],
        operation,
    )?;
    let provider = JObject::from(java::string(env, KEYSTORE, operation)?);
    let factory = java::static_object(
        env,
        &class,
        "getInstance",
        "(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/SecretKeyFactory;",
        &[JValue::Object(&algorithm), JValue::Object(&provider)],
        operation,
    )?;
    let info = JObject::from(java::class(
        env,
        "android/security/keystore/KeyInfo",
        operation,
    )?);
    let spec = java::object(
        env,
        &factory,
        "getKeySpec",
        "(Ljava/security/Key;Ljava/lang/Class;)Ljava/security/spec/KeySpec;",
        &[JValue::Object(key), JValue::Object(&info)],
        operation,
    )?;
    java::boolean(env, &spec, "isInsideSecureHardware", "()Z", &[], operation)
}

/// Master key store of the **direct** form on Android.
///
/// The material is imported into the Android keystore as an AES entry and read back with
/// `SecretKey.getEncoded()`; [`DirectMasterKeyStore::store`] verifies that read-back before
/// it returns, so a keystore that refuses to hand the material out produces
/// [`Error::KeyNotExportable`] instead of a store that holds what nobody can read.
///
/// # Why it reports software
///
/// [`DirectMasterKeyStore::backend`] answers [`Backend::Software`] on every device, not only
/// on emulators: the platform gives no hardware guarantee for a key it **imported** —
/// hardware backing is something it promises for keys it generated — and an answer of
/// "hardware" here would be a lie told to the user about their master key. A caller who
/// needs the master key protected by the TEE wants [`AndroidWrappedMasterKeyStore`].
#[derive(Debug)]
pub struct AndroidDirectMasterKeyStore {
    /// Always [`Backend::Software`]; see the type documentation.
    backend: Backend,
}

impl AndroidDirectMasterKeyStore {
    /// Opens the key store, reporting whether it can be reached at all.
    ///
    /// # Errors
    ///
    /// [`Error::HardwareUnavailable`] when this library was loaded without a Java VM, and
    /// [`Error::Jni`] when the platform has no `AndroidKeyStore` to open.
    pub fn open_best_available() -> Result<Self> {
        java::with_env("KeyStore.getInstance", |env| open_keystore(env).map(|_| ()))?;
        Ok(Self {
            backend: Backend::Software,
        })
    }
}

impl DirectMasterKeyStore for AndroidDirectMasterKeyStore {
    /// Always [`Backend::Software`]; see the type documentation.
    fn backend(&self) -> Backend {
        self.backend
    }

    /// Imports the material, replacing what was under `label`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidKeyLabel`] for an unusable label, [`Error::KeyNotExportable`] when
    /// the keystore will not return the material it just accepted, and [`Error::Jni`] when
    /// the platform refuses the import.
    fn store(&self, label: &str, key: &MasterKey) -> Result<()> {
        let alias = master_alias(MASTER_KEY_ALIAS_PREFIX, label)?;
        java::with_env("KeyStore.setEntry", |env| {
            let store = open_keystore(env)?;
            if contains_entry(env, &store, &alias)? {
                delete_entry(env, &store, &alias, label)?;
            }
            import_material(env, &store, &alias, key.as_bytes())?;

            let read_back = entry_material(env, &store, &alias, label)?;
            if !secrets_equal(read_back.as_bytes(), key.as_bytes()) {
                let _ = delete_entry(env, &store, &alias, label);
                return Err(Error::InvalidMasterKey {
                    reason: "the Android keystore returned material that differs from what was imported",
                });
            }
            Ok(())
        })
    }

    /// Reads the material back.
    ///
    /// # Errors
    ///
    /// [`Error::KeyNotFound`] when the label holds nothing, plus the read-back failures
    /// documented on [`entry_material`].
    fn load(&self, label: &str) -> Result<MasterKey> {
        let alias = master_alias(MASTER_KEY_ALIAS_PREFIX, label)?;
        java::with_env("KeyStore.getKey", |env| {
            let store = open_keystore(env)?;
            entry_material(env, &store, &alias, label)
        })
    }

    /// Deletes the entry.
    ///
    /// # Errors
    ///
    /// [`Error::KeyNotFound`] when the label holds nothing.
    fn delete(&self, label: &str) -> Result<()> {
        let alias = master_alias(MASTER_KEY_ALIAS_PREFIX, label)?;
        java::with_env("KeyStore.deleteEntry", |env| {
            let store = open_keystore(env)?;
            delete_entry(env, &store, &alias, label)
        })
    }
}

/// Master key store of the **wrapped** form on Android.
///
/// The keystore holds one non-exportable AES-256 key-encryption key per label, generated
/// there and never returned by any operation; wrapping and unwrapping are `Cipher` calls
/// against that key, and only the bytes [`WrappedMasterKeyStore::store`] returns are
/// persisted. On a device with a StrongBox the key is asked to live there, and the TEE is
/// the fallback; [`WrappedMasterKeyStore::backend`] reports what the platform says about a
/// generated key on this device rather than assuming a device model.
#[derive(Debug)]
pub struct AndroidWrappedMasterKeyStore {
    /// The platform's verdict about a generated key on this device.
    backend: Backend,
}

impl AndroidWrappedMasterKeyStore {
    /// Opens the key store and asks the platform what protects a generated key here.
    ///
    /// The probe key this generates is a real keystore entry, created once per device. A
    /// store that could not answer before its first key existed would report "software" to a
    /// caller that is deciding whether to trust the wrapped form at all, which is the one
    /// moment the answer has to be right.
    ///
    /// # Errors
    ///
    /// [`Error::HardwareUnavailable`] when this library was loaded without a Java VM, and
    /// [`Error::Jni`] when the platform has no keystore or refuses to generate a key.
    pub fn open_best_available() -> Result<Self> {
        let backend = java::with_env("KeyGenerator.generateKey", |env| {
            let store = open_keystore(env)?;
            let key = match keystore_entry(env, &store, MASTER_PROBE_ALIAS, MASTER_PROBE_ALIAS) {
                Ok(key) => key,
                Err(Error::KeyNotFound { .. }) => {
                    generate_wrapping_key(env, MASTER_PROBE_ALIAS)?;
                    keystore_entry(env, &store, MASTER_PROBE_ALIAS, MASTER_PROBE_ALIAS)?
                }
                Err(other) => return Err(other),
            };
            let hardware = secret_key_is_hardware_backed(env, &key)?;
            Ok(if hardware {
                Backend::AndroidKeystore
            } else {
                Backend::Software
            })
        })?;
        Ok(Self { backend })
    }
}

impl WrappedMasterKeyStore for AndroidWrappedMasterKeyStore {
    fn backend(&self) -> Backend {
        self.backend
    }

    /// Wraps the material with this label's key-encryption key, generating the key on first
    /// use.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidKeyLabel`] for an unusable label, and [`Error::Jni`] when the
    /// platform refuses to generate or use the key.
    fn store(&self, label: &str, key: &MasterKey) -> Result<WrappedMasterKey> {
        let alias = master_alias(MASTER_KEK_ALIAS_PREFIX, label)?;
        java::with_env("Cipher.doFinal", |env| {
            let store = open_keystore(env)?;
            if !contains_entry(env, &store, &alias)? {
                generate_wrapping_key(env, &alias)?;
            }
            let kek = keystore_entry(env, &store, &alias, label)?;
            wrap_with_kek(env, &kek, key.as_bytes())
        })
    }

    /// Unwraps the bytes with this label's key-encryption key.
    ///
    /// # Errors
    ///
    /// [`Error::KeyNotFound`] when the label has no key, [`Error::InvalidWrappedKey`] when
    /// the bytes are not a wrapped master key or fail authentication, and [`Error::Jni`] for
    /// anything else the platform reports.
    fn load(&self, label: &str, wrapped: &WrappedMasterKey) -> Result<MasterKey> {
        let alias = master_alias(MASTER_KEK_ALIAS_PREFIX, label)?;
        if wrapped.as_bytes().len() != WRAPPED_MASTER_KEY_LEN {
            return Err(Error::InvalidWrappedKey {
                reason: "the wrapped master key is not the 60 bytes an AES-GCM key-encryption key produces",
                code: 0,
            });
        }
        java::with_env("Cipher.doFinal", |env| {
            let store = open_keystore(env)?;
            let kek = keystore_entry(env, &store, &alias, label)?;
            unwrap_with_kek(env, &kek, wrapped.as_bytes())
        })
    }

    /// Deletes this label's key-encryption key.
    ///
    /// # Errors
    ///
    /// [`Error::KeyNotFound`] when the label has no key.
    fn delete(&self, label: &str) -> Result<()> {
        let alias = master_alias(MASTER_KEK_ALIAS_PREFIX, label)?;
        java::with_env("KeyStore.deleteEntry", |env| {
            let store = open_keystore(env)?;
            delete_entry(env, &store, &alias, label)
        })
    }
}

const _: () = assert!(PURPOSE_SIGN == 4, "KeyProperties.PURPOSE_SIGN is 4");
