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

//! The Java VM this library was loaded into, and the calls that need it.
//!
//! # Why there is no Java helper class
//!
//! Android's key store has no C API: a key is created and used through `java.security` and
//! `android.security.keystore`. Both are on the boot class path, so `FindClass` resolves them
//! from any attached thread, with the application's class loader uninvolved — and therefore
//! with no class loader to find, no helper class of ours to ship, and nothing to keep in step
//! with the code below.
//!
//! # How the VM is found
//!
//! [`JNI_OnLoad`] is called by the runtime when the library is loaded, and that is where the
//! [`JavaVM`] is taken. Every later call attaches the calling thread to it. A library loaded
//! without the runtime noticing — `dlopen` rather than `System.load` — leaves the VM absent,
//! and every key store call then reports
//! [`Error::HardwareUnavailable`](crate::Error::HardwareUnavailable) instead of failing
//! somewhere less obvious.
//!
//! # Errors, not panics
//!
//! Every call here returns a [`Result`]: a Java exception is read, cleared and turned into
//! [`Error::Jni`](crate::Error::Jni) carrying the class and message the platform reported.
//! Nothing indexes, unwraps or asserts on anything a device can influence. The message is the
//! platform's, and the platform does not put key material in it.
//!
//! # Lifetimes
//!
//! Java references are local to the frame that made them, which is what the `'local` lifetime
//! on every wrapper type means. The helpers below therefore take `&mut JNIEnv<'local>` and
//! return objects bound to `'local`, and a caller has to keep the `JObject` it passes as an
//! argument alive for the call — which is why values are bound to a `let` rather than built
//! inside the argument list.

use std::sync::OnceLock;

use jni::objects::{JByteArray, JClass, JObject, JObjectArray, JString, JValue};
use jni::sys::{JNI_VERSION_1_6, JavaVM as RawJavaVM, jint};
use jni::{JNIEnv, JavaVM};

use crate::{Error, Result};

/// The VM the library was loaded into.
///
/// Set once, by [`JNI_OnLoad`], and read for the lifetime of the process.
static VM: OnceLock<JavaVM> = OnceLock::new();

/// Takes the running [`JavaVM`], which the runtime passes when it loads this library.
///
/// # Safety
///
/// Called only by the JVM, which passes a `JavaVM*` that stays valid for the lifetime of the
/// process; nothing else may call it. The pointer is not dereferenced here — it is handed to
/// [`JavaVM::from_raw`], whose own contract it satisfies.
#[unsafe(no_mangle)]
pub extern "system" fn JNI_OnLoad(vm: *mut RawJavaVM, _reserved: *mut core::ffi::c_void) -> jint {
    // SAFETY: the JVM calls this function when it loads the library, and the pointer it passes
    // is a `JavaVM*` that stays valid until the process ends. Nothing else calls it, so the
    // pointer is never one this crate invented.
    if let Ok(vm) = unsafe { JavaVM::from_raw(vm) } {
        let _ = VM.set(vm);
    }
    JNI_VERSION_1_6
}

/// The VM, or the reason this library cannot reach the key store.
fn vm() -> Result<&'static JavaVM> {
    VM.get().ok_or_else(|| Error::HardwareUnavailable {
        reason: "the library was loaded without a Java VM, so the Android key store cannot be \
                 reached from it"
            .to_owned(),
    })
}

/// Runs `f` on a thread attached to the VM.
///
/// The thread is detached again when `f` returns, unless it was already attached; the guard
/// decides that, so a call from a thread the platform owns leaves no attachment behind.
pub(super) fn with_env<T>(
    operation: &'static str,
    f: impl FnOnce(&mut JNIEnv<'_>) -> Result<T>,
) -> Result<T> {
    let mut env = vm()?.attach_current_thread().map_err(|error| Error::Jni {
        operation,
        detail: error.to_string(),
    })?;
    f(&mut env)
}

/// Resolves a class by its JNI name, for example `java/security/KeyStore`.
pub(super) fn class<'local>(
    env: &mut JNIEnv<'local>,
    name: &str,
    operation: &'static str,
) -> Result<JClass<'local>> {
    env.find_class(name)
        .map_err(|error| describe(env, operation, error))
}

/// A Java string holding `value`.
pub(super) fn string<'local>(
    env: &mut JNIEnv<'local>,
    value: &str,
    operation: &'static str,
) -> Result<JString<'local>> {
    env.new_string(value)
        .map_err(|error| describe(env, operation, error))
}

/// A Java `byte[]` holding `value`.
pub(super) fn bytes<'local>(
    env: &mut JNIEnv<'local>,
    value: &[u8],
    operation: &'static str,
) -> Result<JByteArray<'local>> {
    env.byte_array_from_slice(value)
        .map_err(|error| describe(env, operation, error))
}

/// Constructs a Java object.
pub(super) fn construct<'local>(
    env: &mut JNIEnv<'local>,
    class: &JClass<'local>,
    signature: &str,
    args: &[JValue<'local, '_>],
    operation: &'static str,
) -> Result<JObject<'local>> {
    env.new_object(class, signature, args)
        .map_err(|error| describe(env, operation, error))
}

/// A Java `String[]` holding `values`.
pub(super) fn string_array<'local>(
    env: &mut JNIEnv<'local>,
    values: &[&str],
    operation: &'static str,
) -> Result<JObjectArray<'local>> {
    let class = class(env, "java/lang/String", operation)?;
    let array = env
        .new_object_array(values.len() as i32, &class, JObject::null())
        .map_err(|error| describe(env, operation, error))?;
    for (index, value) in values.iter().enumerate() {
        let value = string(env, value, operation)?;
        env.set_object_array_element(&array, index as i32, &value)
            .map_err(|error| describe(env, operation, error))?;
    }
    Ok(array)
}

/// Calls a static method that returns an object.
pub(super) fn static_object<'local>(
    env: &mut JNIEnv<'local>,
    class: &JClass<'local>,
    name: &str,
    signature: &str,
    args: &[JValue<'local, '_>],
    operation: &'static str,
) -> Result<JObject<'local>> {
    env.call_static_method(class, name, signature, args)
        .and_then(|value| value.l())
        .map_err(|error| describe(env, operation, error))
}

/// Calls an instance method that returns an object.
pub(super) fn object<'local>(
    env: &mut JNIEnv<'local>,
    target: &JObject<'local>,
    name: &str,
    signature: &str,
    args: &[JValue<'local, '_>],
    operation: &'static str,
) -> Result<JObject<'local>> {
    env.call_method(target, name, signature, args)
        .and_then(|value| value.l())
        .map_err(|error| describe(env, operation, error))
}

/// Copies a Java `byte[]` into a Rust one.
pub(super) fn object_bytes(
    env: &mut JNIEnv<'_>,
    array: JObject<'_>,
    operation: &'static str,
) -> Result<Vec<u8>> {
    env.convert_byte_array(JByteArray::from(array))
        .map_err(|error| describe(env, operation, error))
}

/// Calls an instance method that returns a `byte[]`, and copies it out.
pub(super) fn byte_array<'local>(
    env: &mut JNIEnv<'local>,
    target: &JObject<'local>,
    name: &str,
    signature: &str,
    args: &[JValue<'local, '_>],
    operation: &'static str,
) -> Result<Vec<u8>> {
    let array = object(env, target, name, signature, args, operation)?;
    object_bytes(env, array, operation)
}

/// Calls an instance method that returns a `boolean`.
pub(super) fn boolean<'local>(
    env: &mut JNIEnv<'local>,
    target: &JObject<'local>,
    name: &str,
    signature: &str,
    args: &[JValue<'local, '_>],
    operation: &'static str,
) -> Result<bool> {
    env.call_method(target, name, signature, args)
        .and_then(|value| value.z())
        .map_err(|error| describe(env, operation, error))
}

/// Calls an instance method that returns nothing.
pub(super) fn call_void<'local>(
    env: &mut JNIEnv<'local>,
    target: &JObject<'local>,
    name: &str,
    signature: &str,
    args: &[JValue<'local, '_>],
    operation: &'static str,
) -> Result<()> {
    env.call_method(target, name, signature, args)
        .map(|_| ())
        .map_err(|error| describe(env, operation, error))
}

/// Reads a Java string into a Rust one. Used for names and messages, never for key material.
pub(super) fn text(
    env: &mut JNIEnv<'_>,
    value: &JString<'_>,
    operation: &'static str,
) -> Result<String> {
    let value = env
        .get_string(value)
        .map_err(|error| describe(env, operation, error))?;
    Ok(value.to_string_lossy().into_owned())
}

/// Turns a JNI failure into this crate's error, with the pending Java exception's own
/// description when there is one.
fn describe(env: &mut JNIEnv<'_>, operation: &'static str, error: jni::errors::Error) -> Error {
    let detail = pending_exception(env).unwrap_or_else(|| error.to_string());
    Error::Jni { operation, detail }
}

/// The exception the platform has thrown, cleared on the way out, or `None` when there is
/// none.
///
/// Reading it *and clearing it* matters: a pending exception makes every later JNI call on
/// this thread fail, so leaving one behind would turn one failure into a cascade.
fn pending_exception(env: &mut JNIEnv<'_>) -> Option<String> {
    if !env.exception_check().ok()? {
        return None;
    }
    let throwable = env.exception_occurred().ok()?;
    let described = describe_throwable(env, &throwable);
    let _ = env.exception_clear();
    described
}

/// `ClassName: message` of a throwable, or just the class name when it carries no message.
///
/// Nothing here reports its own failure: it runs while another failure is being described,
/// and a second error on top of the first would replace a diagnosis with a mystery.
fn describe_throwable<'local>(
    env: &mut JNIEnv<'local>,
    throwable: &JObject<'local>,
) -> Option<String> {
    let class = JObject::from(env.get_object_class(throwable).ok()?);
    let name = object(
        env,
        &class,
        "getName",
        "()Ljava/lang/String;",
        &[],
        "Throwable.getClass",
    )
    .ok()
    .map(JString::from)?;
    let name = text(env, &name, "Throwable.getClass").ok()?;

    let message = object(
        env,
        throwable,
        "getMessage",
        "()Ljava/lang/String;",
        &[],
        "Throwable.getMessage",
    )
    .ok()
    .filter(|value| !value.is_null())
    .map(JString::from);

    match message {
        Some(message) => Some(match text(env, &message, "Throwable.getMessage") {
            Ok(message) => format!("{name}: {message}"),
            Err(_) => name,
        }),
        None => Some(name),
    }
}
