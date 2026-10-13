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

mod java;

use core::fmt;

use jni::JNIEnv;
use jni::objects::{JObject, JValue};

use crate::keystore::encoding::{sec1_from_coordinates, signature_from_der};
use crate::keystore::traits::{Backend, DIGEST_LEN, DeviceKeyStore, DeviceSigner};
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

/// The digests the key may be used with: the one it signs with, and the one the key store
/// signs its own certificate with.
const DIGESTS: [&str; 2] = ["NONE", "SHA-256"];

/// The signature algorithm that signs a digest the caller computed.
const SIGNATURE: &str = "NONEwithECDSA";

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
    let operation = "KeyStore.containsAlias";
    let alias = JObject::from(java::string(env, label, operation)?);
    java::boolean(
        env,
        store,
        "containsAlias",
        "(Ljava/lang/String;)Z",
        &[JValue::Object(&alias)],
        operation,
    )
}

/// The private key of an entry, as an object the platform will sign with.
fn private_key<'local>(
    env: &mut JNIEnv<'local>,
    store: &JObject<'local>,
    label: &str,
) -> Result<JObject<'local>> {
    let operation = "KeyStore.getKey";
    let alias = JObject::from(java::string(env, label, operation)?);
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

const _: () = assert!(PURPOSE_SIGN == 4, "KeyProperties.PURPOSE_SIGN is 4");
