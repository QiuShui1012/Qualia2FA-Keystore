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

//! 平台后端的集成测试。
//!
//! # 这些测试会碰真实硬件
//!
//! 它们在系统密钥库里**创建并删除**密钥。为了让这件事不干扰用户，全部使用
//! 以 `Q2faTest-` 开头的标签，并在每个测试结束时删除。若某个测试中途失败，
//! 可能留下残留密钥——用 `list` 可以看到它们，手动删除即可。
//!
//! **不要**把这里的标签改成不带前缀的名字：那会让测试与真实账号的身份混在
//! 一起，误删就等于用户永久丢失设备身份。
//!
//! # 没有 TPM 的机器上会跳过
//!
//! 涉及 TPM 的测试在硬件不可用时会**打印原因并跳过**，而不是失败。CI 跑在没有
//! TPM 的虚拟机上，若让它们失败，CI 就永远红着，于是没人再看它——那比不测更糟。

#![cfg(target_os = "windows")]

mod common;

use common::{TestLabel, hardware_store, software_store};
// trait 必须显式引入才能调用它的方法。
use qualia_dik::DeviceKeyStore;

/// **最关键的一条**：硬件签出来的签名必须能被 `qualia2fa-core` 的验签函数接受。
///
/// # 为什么这条必须存在
///
/// 签名链路上有三处独立的约定可能不一致，而它们错了以后的表现都是「签名验不过」：
///
/// 1. 哈希：我们做 SHA-256，硬件签的是这个摘要。若哪边换了算法，这里会失败。
/// 2. 签名格式：CNG 返回的是原始 `r||s`（64 字节）；若它其实返回 DER，长度就会
///    浮动，`DeviceSignature::from_bytes` 会拒绝。
/// 3. 公钥编码：CNG 给的是 `BCRYPT_ECCPUBLICBLOB`（头 + X || Y），我们要转成 SEC1
///    未压缩点 `0x04 || X || Y`。转错了公钥就完全对不上。
///
/// 三者任意一处出错，本测试都会失败——而单元测试**不可能**发现它们，因为单元
/// 测试用的是软件密钥。这就是这个文件存在的全部理由。
#[test]
fn tpm_signature_verifies_with_core() {
    let Some(store) = hardware_store() else {
        return;
    };
    let label = TestLabel::new("sign-verify");
    // 清理可能残留的同名密钥。
    let _ = store.delete(label.as_str());

    let signer = store.create(label.as_str()).expect("创建 TPM 密钥");
    let message = b"\x01Qualia2FA pairing challenge";
    let signature = signer.sign(message).expect("TPM 签名");

    // 长度必须是 64（原始 r||s）。DER 会浮动，若这里失败说明格式假设错了。
    assert_eq!(
        signature.as_bytes().len(),
        64,
        "签名长度不是 64 字节，说明后端返回的不是原始 r||s"
    );

    qualia_dik::device::verify(signer.public_key(), message, &signature)
        .expect("Core 必须接受 TPM 签出来的签名");

    // 改一个 bit 的消息必须验不过——否则说明验签根本没在看消息。
    let mut tampered = *message;
    tampered[0] ^= 0x01;
    assert!(
        qualia_dik::device::verify(signer.public_key(), &tampered, &signature).is_err(),
        "被篡改的消息通过了验证"
    );

    store.delete(label.as_str()).expect("清理");
}

/// 关闭再打开后必须是同一份身份。
///
/// 这条覆盖的是**持久化**：若密钥没有真正落进 KSP，每次打开都会得到新身份，
/// 而那意味着设备身份在每次重启后漂移——对方设备会认为这是一台陌生设备。
#[test]
fn identity_is_stable_across_reopen() {
    let Some(store) = hardware_store() else {
        return;
    };
    let label = TestLabel::new("reopen");
    let _ = store.delete(label.as_str());

    let created = store.create(label.as_str()).expect("创建");
    let id_at_create = created.public_key().device_id();
    drop(created);

    let reopened = store.open(label.as_str()).expect("重新打开");
    assert_eq!(
        reopened.public_key().device_id(),
        id_at_create,
        "重新打开后设备身份变了——密钥没有持久化"
    );

    // 用重新打开的句柄也能签，且公钥仍匹配。
    let message = b"reopen test";
    let signature = reopened.sign(message).expect("签名");
    qualia_dik::device::verify(reopened.public_key(), message, &signature)
        .expect("重开后签名仍应验证通过");

    store.delete(label.as_str()).expect("清理");
}

/// 重复创建必须被拒绝，且**不替换**已有身份。
///
/// # 为什么这条重要
///
/// 覆盖会悄悄换掉设备身份。那种 bug 不会当场暴露——它在几天后才表现为「另一台
/// 设备认不出我了」，而那时已经很难回溯到根因。
#[test]
fn duplicate_create_is_rejected_and_preserves_identity() {
    let Some(store) = hardware_store() else {
        return;
    };
    let label = TestLabel::new("duplicate");
    let _ = store.delete(label.as_str());

    let first = store.create(label.as_str()).expect("首次创建");
    let id_first = first.public_key().device_id();
    drop(first);

    let error = store.create(label.as_str()).expect_err("重复创建应被拒绝");
    assert!(
        matches!(error, qualia_dik::KeyStoreError::KeyAlreadyExists { .. }),
        "错误类型不对: {error:?}"
    );

    // 关键：原身份必须完好无损。
    let again = store.open(label.as_str()).expect("打开");
    assert_eq!(
        again.public_key().device_id(),
        id_first,
        "拒绝重复创建的同时身份被换掉了——这是最危险的一种失败"
    );

    store.delete(label.as_str()).expect("清理");
}

/// `open_or_create` 在「已存在」与「不存在」两种情况下都工作。
#[test]
fn open_or_create_works_in_both_cases() {
    let Some(store) = hardware_store() else {
        return;
    };
    let label = TestLabel::new("open-or-create");
    let _ = store.delete(label.as_str());

    let created = store.open_or_create(label.as_str()).expect("首次应创建");
    let id = created.public_key().device_id();
    drop(created);

    let opened = store.open_or_create(label.as_str()).expect("再次应打开");
    assert_eq!(
        opened.public_key().device_id(),
        id,
        "第二次调用不应生成新身份"
    );

    store.delete(label.as_str()).expect("清理");
}

// 这里原本有一条「列举密钥」的测试。`NCryptEnumKeys` 实测对 TPM 提供程序返回
// 成功但空表（详见 `src/windows.rs` 里的说明），因此 `DeviceKeyStore` 不再提供
// `list`，测试也随之删除。
//
// 与此相关的一个教训：那条测试是**唯一**发现这个问题的途径。它失败时看起来像
// 「标签前缀没剥掉」，实际是「这个 API 根本列不出 TPM 密钥」——如果当初因为它
// 「只是个列举功能、不重要」而删掉测试，这个问题就会以「某个账号的身份在列表里
// 神秘消失」的形式留到很久以后。
/// 打开与删除不存在的标签必须明确报 `KeyNotFound`。
#[test]
fn missing_label_reports_not_found() {
    let Some(store) = hardware_store() else {
        return;
    };
    let label = TestLabel::new("definitely-missing");
    let _ = store.delete(label.as_str());

    let error = store.open(label.as_str()).expect_err("应报不存在");
    assert!(
        matches!(error, qualia_dik::KeyStoreError::KeyNotFound { .. }),
        "错误类型不对: {error:?}"
    );

    let error = store.delete(label.as_str()).expect_err("应报不存在");
    assert!(
        matches!(error, qualia_dik::KeyStoreError::KeyNotFound { .. }),
        "错误类型不对: {error:?}"
    );
}

/// 两个不同标签必须是两份独立身份。
#[test]
fn distinct_labels_are_distinct_identities() {
    let Some(store) = hardware_store() else {
        return;
    };
    let a = TestLabel::new("distinct-a");
    let b = TestLabel::new("distinct-b");
    let _ = store.delete(a.as_str());
    let _ = store.delete(b.as_str());

    let signer_a = store.create(a.as_str()).expect("创建 a");
    let signer_b = store.create(b.as_str()).expect("创建 b");
    assert_ne!(
        signer_a.public_key().device_id(),
        signer_b.public_key().device_id(),
        "两个标签给出了同一份身份"
    );

    store.delete(a.as_str()).expect("清理 a");
    store.delete(b.as_str()).expect("清理 b");
}

/// TPM 后端必须如实报告自己是 TPM。
#[test]
fn tpm_backend_reports_tpm() {
    let Some(store) = hardware_store() else {
        return;
    };
    assert_eq!(
        qualia_dik::DeviceKeyStore::backend(&store),
        qualia_dik::Backend::Tpm
    );
    assert!(
        qualia_dik::DeviceKeyStore::backend(&store).is_hardware_backed(),
        "TPM 后端必须被判定为硬件保护"
    );
}

/// 软件 KSP 走**完全相同**的代码路径，只是提供程序名不同。
///
/// 这条在**没有 TPM 的机器上也能跑**（软件 KSP 一直存在），因此它保证了那条
/// 降级路径不是死代码。
#[test]
fn software_provider_also_signs_and_verifies() {
    let Some(store) = software_store() else {
        return;
    };
    let label = TestLabel::new("software-provider");
    let _ = store.delete(label.as_str());

    let signer = store.create(label.as_str()).expect("创建软件密钥");
    assert_eq!(
        qualia_dik::DeviceKeyStore::backend(&store),
        qualia_dik::Backend::Software
    );
    assert!(
        !qualia_dik::DeviceKeyStore::backend(&store).is_hardware_backed(),
        "软件后端不得被判定为硬件保护"
    );

    let message = b"software path";
    let signature = signer.sign(message).expect("签名");
    qualia_dik::device::verify(signer.public_key(), message, &signature)
        .expect("软件后端的签名同样必须被 Core 接受");

    store.delete(label.as_str()).expect("清理");
}

/// 非法标签必须在**碰硬件之前**就被拒绝。
#[test]
fn invalid_labels_are_rejected_before_touching_hardware() {
    let Some(store) = hardware_store() else {
        return;
    };
    for bad in ["", "a/b", "a\0b", "has space", "设备", &"x".repeat(200)] {
        let error = store.open(bad).expect_err("应拒绝");
        assert!(
            matches!(error, qualia_dik::KeyStoreError::InvalidKeyLabel { .. }),
            "标签 {bad:?} 的错误类型不对: {error:?}"
        );
    }
}
