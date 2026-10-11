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

//! 集成测试的共用工具。
//!
//! # 为什么测试标签必须唯一
//!
//! `cargo test` 默认**并行**运行测试，而真实密钥库是全局共享状态。若两个测试用
//! 同一个标签，它们会互相删除对方的密钥，表现为「随机失败」——那是最难查的一类
//! 测试失败，而且会让人开始不信任测试结果。
//!
//! [`TestLabel`] 因此把「测试名 + 进程号 + 原子序号」拼进标签里，保证全局唯一。

#![cfg(target_os = "windows")]
// 每个集成测试二进制都会各自包含本模块，未用到其中全部工具时不该报警告。
#![allow(dead_code)]

use qualia_dik::DeviceKeyStore;
use qualia_dik::keystore::platform::{WindowsKeyStore, WindowsProvider};
use std::sync::atomic::{AtomicU64, Ordering};

/// 所有测试标签的公共前缀。
///
/// **不要**改掉它，也不要让测试用不带前缀的标签：真实用户身份与测试身份混在
/// 同一个命名空间里时，一次误删就是用户永久丢失设备身份。
const TEST_PREFIX: &str = "Q2faTest-";

/// 进程内单调递增的序号，保证同一进程里的标签互不相同。
static COUNTER: AtomicU64 = AtomicU64::new(0);

/// 一个全局唯一的测试标签，drop 时**不做**任何事。
///
/// 刻意不在 `Drop` 里自动清理：清理本身也要碰硬件，而它在 `panic` 展开期间执行
/// 会掩盖真正的失败原因。测试自己显式调用 `delete`。
#[derive(Debug)]
pub struct TestLabel {
    /// 完整的标签文本。
    text: String,
}

impl TestLabel {
    /// 用 `name` 造一个全局唯一的标签。
    #[must_use]
    pub fn new(name: &str) -> Self {
        let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        Self {
            // 只保留 `key_name` 允许的字符：ASCII 字母、数字、`-`、`_`、`.`。
            // `name` 由测试作者给出，含 `-` 是安全的。
            text: format!("{TEST_PREFIX}{name}-{pid}-{sequence}"),
        }
    }

    /// 标签文本。
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

/// 打开 TPM 后端；本机没有可用 TPM 时返回 `None` 并打印原因。
///
/// # 为什么是「返回 None」而不是「panic」
///
/// CI 跑在没有 TPM 的虚拟机上。若这些测试在那里失败，CI 会永远红着，于是没人
/// 再看它——那比不测更糟。真正与硬件无关的性质由 `mock` 后端的单元测试覆盖。
///
/// 但**在开发机上**（有 TPM），这些测试必须真的跑起来。所以这里打印一行明确的
/// 提示，让「跳过」与「通过」在输出里区分得开。
#[must_use]
pub fn hardware_store() -> Option<WindowsKeyStore> {
    match WindowsKeyStore::open(WindowsProvider::Tpm) {
        Ok(store) => Some(store),
        Err(error) => {
            println!("跳过：本机 TPM 不可用（{error}）");
            None
        }
    }
}

/// 打开软件 KSP 后端；连它都不可用时返回 `None`。
///
/// 软件 KSP 在 Windows 上始终存在，因此这个函数实际上总会成功——它让降级路径
/// 也能被测试覆盖到。
#[must_use]
pub fn software_store() -> Option<WindowsKeyStore> {
    match WindowsKeyStore::open(WindowsProvider::Software) {
        Ok(store) => Some(store),
        Err(error) => {
            println!("跳过：本机软件密钥库不可用（{error}）");
            None
        }
    }
}

/// 断言两个密钥库报告的后端不同（用于区分 TPM 与软件路径）。
#[must_use]
pub fn backend_of(store: &WindowsKeyStore) -> qualia_dik::Backend {
    store.backend()
}
