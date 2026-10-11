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

//! 确认 `README.md` 里的示例是**能编译**的。
//!
//! # 为什么值得单独写一个测试
//!
//! README 里的示例是使用者看到的第一段代码，而它**不会被 rustdoc 检查**
//! （rustdoc 只测文档注释里的代码块）。一段编译不过的入门示例比没有示例更糟：
//! 它会让人以为是自己环境有问题。
//!
//! 这里用 `cfg(test)` 而不是 rustdoc 的 `no_run`，是为了让它跟着 `cargo test`
//! 一起跑，而不需要额外的 `cargo test --doc` 步骤。

#![cfg(target_os = "windows")]

/// README「用法」一节里的示例，逐行照抄。
///
/// 唯一的差别是把 `?` 换成 `expect`，因为测试函数没有返回 `Result`。这样至少
/// 能保证**类型与调用顺序**都是对的。
#[test]
fn readme_usage_example_compiles_and_runs() {
    use qualia_dik::DeviceKeyStore;
    use qualia_dik::keystore::platform::{WindowsKeyStore, WindowsProvider};

    // README: `let store = WindowsKeyStore::open_best_available()?;`
    // 用显式的 TPM 打开，避免在 CI 上悄悄测到软件后端。
    let Ok(store) = WindowsKeyStore::open(WindowsProvider::Tpm) else {
        println!("跳过：本机没有可用的 TPM");
        return;
    };

    // README: 如实告诉用户私钥在哪里。
    // `is_hardware_backed` 必须存在且可用——这是 README 承诺的接口。
    assert!(
        store.backend().is_hardware_backed(),
        "用 TPM 提供程序打开的密钥库必须报告硬件保护"
    );

    // README: `println!("设备 ID: {}", signer.public_key().device_id());`
    // 用一个不会与真实身份冲突的标签。
    let label = format!("ReadmeExample-{}", std::process::id());
    let _ = store.delete(&label);

    // README: `let signer = store.open_or_create("account-1")?;`
    let signer = store.open_or_create(&label).expect("打开或创建");

    // README: 公钥不是秘密，可以随意传播。
    let device_id = signer.public_key().device_id().to_string();
    assert!(!device_id.is_empty(), "设备 ID 的字符串形式不应为空");

    // README: `let signature = signer.sign(b"待签名的消息")?;`
    let message = b"\x07README example message";
    let signature = signer.sign(message).expect("签名");

    // README: `qualia_dik::device::verify(...)?;`
    qualia_dik::device::verify(signer.public_key(), message, &signature)
        .expect("README 示例里的验签必须通过");

    // README: `sign_digest` 与 `sign` 的分工。
    let digest = qualia_dik::keystore::sha256(message);
    let signature2 = signer.sign_digest(&digest).expect("摘要签名");
    qualia_dik::device::verify(signer.public_key(), message, &signature2)
        .expect("按摘要签名后，对消息的验签同样必须通过");

    // README 承诺：非法标签会被拒绝。
    assert!(
        store.open_or_create("坏 标签").is_err(),
        "README 说 label 只允许 ASCII 字母数字与 - _ .，含空格的必须被拒绝"
    );

    // README 承诺：`create` 不覆盖已有密钥。
    assert!(
        store.create(&label).is_err(),
        "README 说 create 不覆盖已有密钥"
    );

    store.delete(&label).expect("清理");
}

/// README 里 `mock` feature 的示例。
///
/// 它由 `--features mock` 启用，因此这里用 `cfg` 收窄，避免默认测试找不到类型。
#[cfg(feature = "mock")]
#[test]
fn readme_mock_example_compiles_and_runs() {
    use qualia_dik::{DeviceKeyStore, MockKeyStore};

    // README: `let store = MockKeyStore::new();`
    let store = MockKeyStore::new();
    // README: `let signer = store.create("test-device")?;`
    let signer = store.create("test-device").expect("创建");

    let message = b"mock example";
    let signature = signer.sign(message).expect("签名");
    qualia_dik::device::verify(signer.public_key(), message, &signature).expect("验签");
}
