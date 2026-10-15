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

//! The Android platform API this crate calls, as the platform declares it.
//!
//! Android's key store has no C API: this crate reaches `java.security` and
//! `android.security.keystore` over JNI, where a method is resolved by **name and
//! descriptor** at the moment of the call. A descriptor the platform does not declare is
//! therefore not a compile error — it is a `NoSuchMethodError` on a device, reported as
//! [`crate::Error::Jni`] — and the JDK's declaration of the same class is not the authority
//! on what Android declares. `SecretKeyFactory.getKeySpec` is where the two differ:
//! Java SE takes a `java.security.Key`, Android takes a `javax.crypto.SecretKey`.
//!
//! The table below transcribes the declarations this crate calls, from the Android SDK's
//! `android.jar` (`javap --system none -cp android.jar -s`, API 35; `--system none` so that
//! the JDK's own classes cannot answer in the platform's place). The tests turn each
//! transcription into a JNI descriptor — a second representation of the same fact — and hold
//! the descriptors written in `android.rs` and `android/java.rs` against the derived set, in
//! both directions.
//!
//! Test-only, and it carries no runtime code: the descriptors themselves stay next to the
//! calls that use them.

use std::collections::BTreeSet;

/// The Android backend, whose JNI descriptors are held against the platform's declarations.
const ANDROID_BACKEND: &str = include_str!("android.rs");

/// The JNI helpers of the Android backend, checked for the same reason.
const ANDROID_HELPERS: &str = include_str!("android/java.rs");

/// One method of the Android platform API this crate calls.
struct PlatformMethod {
    /// Class the method is declared on, as the platform names it.
    class: &'static str,
    /// Method name, as the platform declares it; `"<init>"` for a constructor.
    name: &'static str,
    /// Parameter types in declaration order, as Java names.
    parameters: &'static [&'static str],
    /// Return type as a Java name, or `None` for `void`.
    result: Option<&'static str>,
}

/// Builds a table row, so that the table below reads as one line per method.
const fn method(
    class: &'static str,
    name: &'static str,
    parameters: &'static [&'static str],
    result: Option<&'static str>,
) -> PlatformMethod {
    PlatformMethod {
        class,
        name,
        parameters,
        result,
    }
}

/// Every method of the Android platform API the Android backend calls.
const ANDROID_API: &[PlatformMethod] = &[
    // ── The key store itself ────────────────────────────────────────────
    method(
        "java.security.KeyStore",
        "getInstance",
        &["java.lang.String"],
        Some("java.security.KeyStore"),
    ),
    method(
        "java.security.KeyStore",
        "load",
        &["java.security.KeyStore$LoadStoreParameter"],
        None,
    ),
    method(
        "java.security.KeyStore",
        "containsAlias",
        &["java.lang.String"],
        Some("boolean"),
    ),
    method(
        "java.security.KeyStore",
        "getCertificate",
        &["java.lang.String"],
        Some("java.security.cert.Certificate"),
    ),
    method(
        "java.security.KeyStore",
        "getKey",
        &["java.lang.String", "char[]"],
        Some("java.security.Key"),
    ),
    method(
        "java.security.KeyStore",
        "setEntry",
        &[
            "java.lang.String",
            "java.security.KeyStore$Entry",
            "java.security.KeyStore$ProtectionParameter",
        ],
        None,
    ),
    method(
        "java.security.KeyStore",
        "deleteEntry",
        &["java.lang.String"],
        None,
    ),
    method(
        "java.security.KeyStore$SecretKeyEntry",
        "<init>",
        &["javax.crypto.SecretKey"],
        None,
    ),
    // ── The public half of a generated key pair ─────────────────────────
    method(
        "java.security.cert.Certificate",
        "getPublicKey",
        &[],
        Some("java.security.PublicKey"),
    ),
    method(
        "java.security.interfaces.ECPublicKey",
        "getW",
        &[],
        Some("java.security.spec.ECPoint"),
    ),
    method(
        "java.security.spec.ECPoint",
        "getAffineX",
        &[],
        Some("java.math.BigInteger"),
    ),
    method(
        "java.security.spec.ECPoint",
        "getAffineY",
        &[],
        Some("java.math.BigInteger"),
    ),
    method("java.math.BigInteger", "toByteArray", &[], Some("byte[]")),
    // ── Key material, and what protects it ──────────────────────────────
    method(
        "java.security.Key",
        "getAlgorithm",
        &[],
        Some("java.lang.String"),
    ),
    method("java.security.Key", "getEncoded", &[], Some("byte[]")),
    method(
        "java.security.KeyFactory",
        "getInstance",
        &["java.lang.String", "java.lang.String"],
        Some("java.security.KeyFactory"),
    ),
    method(
        "java.security.KeyFactory",
        "getKeySpec",
        &["java.security.Key", "java.lang.Class"],
        Some("java.security.spec.KeySpec"),
    ),
    method(
        "javax.crypto.SecretKeyFactory",
        "getInstance",
        &["java.lang.String", "java.lang.String"],
        Some("javax.crypto.SecretKeyFactory"),
    ),
    method(
        "javax.crypto.SecretKeyFactory",
        "getKeySpec",
        &["javax.crypto.SecretKey", "java.lang.Class"],
        Some("java.security.spec.KeySpec"),
    ),
    method(
        "android.security.keystore.KeyInfo",
        "isInsideSecureHardware",
        &[],
        Some("boolean"),
    ),
    // ── Generating the device identity ──────────────────────────────────
    method(
        "java.security.KeyPairGenerator",
        "getInstance",
        &["java.lang.String", "java.lang.String"],
        Some("java.security.KeyPairGenerator"),
    ),
    method(
        "java.security.KeyPairGenerator",
        "initialize",
        &["java.security.spec.AlgorithmParameterSpec"],
        None,
    ),
    method(
        "java.security.KeyPairGenerator",
        "generateKeyPair",
        &[],
        Some("java.security.KeyPair"),
    ),
    method(
        "java.security.spec.ECGenParameterSpec",
        "<init>",
        &["java.lang.String"],
        None,
    ),
    // ── The key specification both forms are built from ─────────────────
    method(
        "android.security.keystore.KeyGenParameterSpec$Builder",
        "<init>",
        &["java.lang.String", "int"],
        None,
    ),
    method(
        "android.security.keystore.KeyGenParameterSpec$Builder",
        "setAlgorithmParameterSpec",
        &["java.security.spec.AlgorithmParameterSpec"],
        Some("android.security.keystore.KeyGenParameterSpec$Builder"),
    ),
    method(
        "android.security.keystore.KeyGenParameterSpec$Builder",
        "setDigests",
        &["java.lang.String[]"],
        Some("android.security.keystore.KeyGenParameterSpec$Builder"),
    ),
    method(
        "android.security.keystore.KeyGenParameterSpec$Builder",
        "setBlockModes",
        &["java.lang.String[]"],
        Some("android.security.keystore.KeyGenParameterSpec$Builder"),
    ),
    method(
        "android.security.keystore.KeyGenParameterSpec$Builder",
        "setEncryptionPaddings",
        &["java.lang.String[]"],
        Some("android.security.keystore.KeyGenParameterSpec$Builder"),
    ),
    method(
        "android.security.keystore.KeyGenParameterSpec$Builder",
        "setKeySize",
        &["int"],
        Some("android.security.keystore.KeyGenParameterSpec$Builder"),
    ),
    method(
        "android.security.keystore.KeyGenParameterSpec$Builder",
        "setRandomizedEncryptionRequired",
        &["boolean"],
        Some("android.security.keystore.KeyGenParameterSpec$Builder"),
    ),
    method(
        "android.security.keystore.KeyGenParameterSpec$Builder",
        "setIsStrongBoxBacked",
        &["boolean"],
        Some("android.security.keystore.KeyGenParameterSpec$Builder"),
    ),
    method(
        "android.security.keystore.KeyGenParameterSpec$Builder",
        "build",
        &[],
        Some("android.security.keystore.KeyGenParameterSpec"),
    ),
    // ── Signing a digest ────────────────────────────────────────────────
    method(
        "java.security.Signature",
        "getInstance",
        &["java.lang.String"],
        Some("java.security.Signature"),
    ),
    method(
        "java.security.Signature",
        "initSign",
        &["java.security.PrivateKey"],
        None,
    ),
    method("java.security.Signature", "update", &["byte[]"], None),
    method("java.security.Signature", "sign", &[], Some("byte[]")),
    // ── The direct form: importing the material ─────────────────────────
    method(
        "javax.crypto.spec.SecretKeySpec",
        "<init>",
        &["byte[]", "java.lang.String"],
        None,
    ),
    method(
        "android.security.keystore.KeyProtection$Builder",
        "<init>",
        &["int"],
        None,
    ),
    method(
        "android.security.keystore.KeyProtection$Builder",
        "setBlockModes",
        &["java.lang.String[]"],
        Some("android.security.keystore.KeyProtection$Builder"),
    ),
    method(
        "android.security.keystore.KeyProtection$Builder",
        "setEncryptionPaddings",
        &["java.lang.String[]"],
        Some("android.security.keystore.KeyProtection$Builder"),
    ),
    method(
        "android.security.keystore.KeyProtection$Builder",
        "build",
        &[],
        Some("android.security.keystore.KeyProtection"),
    ),
    // ── The wrapped form: a key-encryption key and an AES-GCM cipher ────
    method(
        "javax.crypto.KeyGenerator",
        "getInstance",
        &["java.lang.String", "java.lang.String"],
        Some("javax.crypto.KeyGenerator"),
    ),
    method(
        "javax.crypto.KeyGenerator",
        "init",
        &["java.security.spec.AlgorithmParameterSpec"],
        None,
    ),
    method(
        "javax.crypto.KeyGenerator",
        "generateKey",
        &[],
        Some("javax.crypto.SecretKey"),
    ),
    method(
        "javax.crypto.Cipher",
        "getInstance",
        &["java.lang.String"],
        Some("javax.crypto.Cipher"),
    ),
    method(
        "javax.crypto.Cipher",
        "init",
        &["int", "java.security.Key"],
        None,
    ),
    method(
        "javax.crypto.Cipher",
        "init",
        &[
            "int",
            "java.security.Key",
            "java.security.spec.AlgorithmParameterSpec",
        ],
        None,
    ),
    method("javax.crypto.Cipher", "getIV", &[], Some("byte[]")),
    method(
        "javax.crypto.Cipher",
        "doFinal",
        &["byte[]"],
        Some("byte[]"),
    ),
    method(
        "javax.crypto.spec.GCMParameterSpec",
        "<init>",
        &["int", "byte[]"],
        None,
    ),
    // ── Describing a failure ────────────────────────────────────────────
    method("java.lang.Class", "getName", &[], Some("java.lang.String")),
    method(
        "java.lang.Throwable",
        "getMessage",
        &[],
        Some("java.lang.String"),
    ),
];

/// The JNI descriptor the platform's declaration of `method` implies.
fn descriptor_of(method: &PlatformMethod) -> String {
    let mut descriptor = String::from("(");
    for parameter in method.parameters {
        descriptor.push_str(&type_descriptor(parameter));
    }
    descriptor.push(')');
    descriptor.push_str(&type_descriptor(method.result.unwrap_or("void")));
    descriptor
}

/// The JNI descriptor of one Java type name, arrays included.
fn type_descriptor(name: &str) -> String {
    if let Some(element) = name.strip_suffix("[]") {
        return format!("[{}", type_descriptor(element));
    }
    match name {
        "void" => "V".to_owned(),
        "boolean" => "Z".to_owned(),
        "byte" => "B".to_owned(),
        "char" => "C".to_owned(),
        "short" => "S".to_owned(),
        "int" => "I".to_owned(),
        "long" => "J".to_owned(),
        "float" => "F".to_owned(),
        "double" => "D".to_owned(),
        class => format!("L{};", class.replace('.', "/")),
    }
}

/// Length in bytes of the JNI type descriptor at the start of `text`, or `None` when there
/// is none.
fn type_length(text: &str) -> Option<usize> {
    let mut index = 0;
    while text[index..].starts_with('[') {
        index += 1;
    }
    match text[index..].chars().next()? {
        'V' | 'Z' | 'B' | 'C' | 'S' | 'I' | 'J' | 'F' | 'D' => Some(index + 1),
        'L' => {
            let end = text[index..].find(';')?;
            Some(index + end + 1)
        }
        _ => None,
    }
}

/// Whether `literal` has the shape of a JNI method descriptor.
///
/// The shape is what tells a descriptor apart from every other string in these files: it
/// begins with `(`, holds a well-formed parameter list, and ends with one return type.
fn is_descriptor(literal: &str) -> bool {
    let Some(body) = literal.strip_prefix('(') else {
        return false;
    };
    let Some((parameters, result)) = body.split_once(')') else {
        return false;
    };
    let mut rest = parameters;
    while !rest.is_empty() {
        match type_length(rest) {
            Some(length) => rest = &rest[length..],
            None => return false,
        }
    }
    type_length(result) == Some(result.len())
}

/// Every double-quoted span on `line`.
fn string_literals(line: &str) -> Vec<&str> {
    let mut literals = Vec::new();
    let mut rest = line;
    while let Some(start) = rest.find('"') {
        let after = &rest[start + 1..];
        match after.find('"') {
            Some(end) => {
                literals.push(&after[..end]);
                rest = &after[end + 1..];
            }
            None => break,
        }
    }
    literals
}

/// Every JNI method descriptor written as a literal in `source`.
///
/// Comment lines are skipped, which is enough for the `//`-only comment style this crate
/// uses; a descriptor written inside a commented-out call is therefore not read as one.
fn descriptors_in(source: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for line in source.lines() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        for literal in string_literals(line) {
            if is_descriptor(literal) {
                found.insert(literal.to_owned());
            }
        }
    }
    found
}

/// Every descriptor the table implies, in the form the backend writes it.
fn declared_descriptors() -> BTreeSet<String> {
    ANDROID_API.iter().map(descriptor_of).collect()
}

/// Every descriptor the Android backend calls with.
fn used_descriptors() -> BTreeSet<String> {
    let mut used = descriptors_in(ANDROID_BACKEND);
    used.extend(descriptors_in(ANDROID_HELPERS));
    used
}

/// Every descriptor the backend calls with is one Android declares, and every declaration in
/// the table is one the backend calls with.
///
/// Both directions matter: the first has to hold or a call fails on a device with
/// `NoSuchMethodError`, and the second keeps the table from outliving the call it was
/// transcribed for.
#[test]
fn the_backend_uses_the_platforms_descriptors_and_only_those() {
    let declared = declared_descriptors();
    let used = used_descriptors();

    let undeclared: Vec<&String> = used.difference(&declared).collect();
    assert!(
        undeclared.is_empty(),
        "the Android platform declares no such method: {undeclared:?}"
    );

    let unused: Vec<&String> = declared.difference(&used).collect();
    assert!(
        unused.is_empty(),
        "the table declares methods this backend never calls: {unused:?}"
    );
}

/// The source scanner finds the calls that are there.
///
/// Without this, a scanner that silently matched nothing would leave the test above holding
/// an empty set against an empty set.
#[test]
fn the_scanner_finds_the_descriptors_that_are_in_the_sources() {
    let used = used_descriptors();

    assert!(
        used.len() > 20,
        "the Android backend calls far more than a handful of JNI methods, found {}",
        used.len()
    );
    for expected in [
        "(Ljava/lang/String;)Ljava/security/KeyStore;",
        "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
        "(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V",
        "()Ljava/security/spec/ECPoint;",
    ] {
        assert!(used.contains(expected), "the scanner missed {expected}");
    }
}

/// The symmetric key description is called with the platform's own first parameter.
///
/// Android declares `SecretKeyFactory.getKeySpec(javax.crypto.SecretKey, java.lang.Class)`
/// where Java SE declares `SecretKeyFactory.getKeySpec(java.security.Key, java.lang.Class)`.
/// The Java SE descriptor resolves on a desktop JVM and nowhere else, so it is pinned here:
/// this is the declaration that decides whether the wrapped master key store can open at all.
#[test]
fn the_symmetric_key_description_takes_a_secret_key() {
    let described = ANDROID_API
        .iter()
        .find(|method| {
            method.class == "javax.crypto.SecretKeyFactory" && method.name == "getKeySpec"
        })
        .expect("the table carries the symmetric key description");

    assert_eq!(
        descriptor_of(described),
        "(Ljavax/crypto/SecretKey;Ljava/lang/Class;)Ljava/security/spec/KeySpec;",
        "Android takes a javax.crypto.SecretKey here, Java SE a java.security.Key"
    );
    assert!(
        descriptors_in(ANDROID_BACKEND)
            .contains("(Ljavax/crypto/SecretKey;Ljava/lang/Class;)Ljava/security/spec/KeySpec;"),
        "the backend has to call it with the platform's descriptor"
    );
}
