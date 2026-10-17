<div align="center" style="align-items: center">

# QualiaDeviceIdentityKit

简体中文 | [English](README.en.md)

设备身份工具箱：**P-256 设备身份原语**，加上**平台原生的硬件密钥库**。

[![License](https://img.shields.io/github/license/Qualia2FA/QualiaDeviceIdentityKit?label=License)][License]
[![Releases](https://img.shields.io/github/downloads/Qualia2FA/QualiaDeviceIdentityKit/total?logo=github&label=Downloads)][Releases]
[![crates.io](https://img.shields.io/crates/d/qualia-dik?logo=crates.io&label=crates.io+Downloads)][crates.io]

[License]: LICENSE

[Releases]: https://github.com/Qualia2FA/QualiaDeviceIdentityKit/releases

[crates.io]: https://crates.io/crates/qualia-dik

</div>

---

该库把「在设备硬件里生成一个 ECDSA P-256 密钥、取回公钥、让硬件对消息签名」封装成
安全的 Rust 接口，同时提供**公钥侧**的表示、指纹与验签——让上层不必接触任何平台
原生 API，也不必自己实现一遍曲线运算。

私钥**永不离开硬件**，也永不进入本进程的地址空间。

## 两半，一个概念

| 模块       | 做什么                                       | 持私钥吗       |
|------------|----------------------------------------------|----------------|
| `device`   | 公钥表示、设备指纹（`DeviceId`）、验签       | 否             |
| `keystore` | 生成密钥、取公钥、对消息签名、存放应用主密钥 | 是（在硬件里） |

两者共用同一个错误类型。分开的原因很实际：**一台设备必须能验证别人的签名，而它
自己可能根本不持有任何硬件密钥**（没有 TPM 的桌面机就是这样）。

```rust
use qualia_dik::{DeviceKeyStore, device};

let signer = store.open_or_create("account-1")?;

// 公钥不是秘密，可以随意传播。
println!("device id: {}", signer.public_key().device_id());

let message = b"a message to sign";
let signature = signer.sign(message)?;

// 验签不需要密钥库，也不需要私钥。
device::verify(signer.public_key(), message, &signature)?;
```

## 状态

已实现如下部分：

- 抽象层：`DeviceKeyStore` / `DeviceSigner`，以及后端能力查询
  （`platform_backend_is_implemented()` 在 Windows 与 Android 上返回 `true`）
- 抽象层：`DirectMasterKeyStore` / `WrappedMasterKeyStore`（应用主密钥的两种存法）
- **Windows**：CNG `NCrypt*` + TPM 2.0（`MS_PLATFORM_CRYPTO_PROVIDER`）
- **Windows（无 TPM 时）**：CNG 软件密钥库降级路径
- **Windows 主密钥**：包裹形式优先走 TPM，直接形式走软件密钥库（原因见下文）
- **Android 主密钥**：两种形式都架在 Android Keystore 上（已在 Android 17 的真机上用过）
- **Android**：Keystore / StrongBox
- 测试用的内存后端（`mock` feature，**默认关闭**）

尚未实现：macOS（Secure Enclave）、Linux（TPM 2.0）、iOS（Secure Enclave）。

> 调用 `DeviceKeyStore::backend` 可以查到某份密钥库**运行时**实际使用的后端。
> 在没有 TPM 的 Windows 机器上它会返回 `Backend::Software`——即私钥以软件形式
> 保存，只受操作系统用户账户保护。**本层不会静默降级**：未实现的平台返回
> `UnsupportedPlatform`，是否接受软件密钥由调用方（也就是用户）决定。

> **`PlatformKeyStore` 在两个平台上的构造函数签名不同**：Windows 的
> `open_best_available()` 返回 `Result`（真的会失败：没有 TPM、被组策略禁用、
> 密钥库被独占），其它平台的返回 `Self`（占位后端什么都不做，不可能失败）。
> 这是刻意的——给它一个 `Result` 只会让调用方写一个永远走不到的错误分支。

## 主密钥的两种存法

平台密钥库除了设备身份密钥，还持有**应用的主密钥**——保险库文件就是用它加密的。主密
钥是 `MasterKey` 里 32 字节的不透明材料：本 crate 只把它在调用方与平台之间搬运，不从
中派生任何东西。有两种存法，**由调用方选哪个类型决定**，不是运行期开关：

| 形式 | 契约                    | 平台库里放什么         | 调用方要持久化什么 |
|------|-------------------------|------------------------|--------------------|
| 直接 | `DirectMasterKeyStore`  | 主密钥材料本身         | 什么都不用         |
| 包裹 | `WrappedMasterKeyStore` | 一把**不可导出**的 KEK | 返回的包裹字节     |

```rust
use qualia_dik::{
    DirectMasterKeyStore, MasterKey, MockDirectMasterKeyStore, MockWrappedMasterKeyStore,
    WrappedMasterKeyStore,
};

let key = MasterKey::from_bytes([0x2A; qualia_dik::MASTER_KEY_LEN]);

// 直接：库持有材料，调用方不持久化任何东西。
let direct = MockDirectMasterKeyStore::new();
direct.store("account-1", &key)?;
let loaded = direct.load("account-1")?;

// 包裹：库持有 KEK，调用方把返回的字节与保险库存在一起。
let wrapped_store = MockWrappedMasterKeyStore::new();
let blob = wrapped_store.store("account-1", &key)?;
let loaded_again = wrapped_store.load("account-1", &blob)?;

assert_eq!(loaded.as_bytes(), loaded_again.as_bytes());
```

真实平台上把两个 `Mock*` 换成 `PlatformDirectMasterKeyStore` /
`PlatformWrappedMasterKeyStore` 即可（Windows 上的 `open_best_available()` 返回
`Result`，Android 同样）。

KEK 的加解密**不出现在任何接口里**：没有 wrap / unwrap / encrypt / decrypt，也没有
任何方法能拿到那把钥匙——包裹是这一形式的内部设计。两种形式都通过 `backend()` 如实报
告实际生效的后端，绝不用软件后端冒充硬件。

| 平台    | 直接                                                 | 包裹                            |
|---------|------------------------------------------------------|---------------------------------|
| Windows | 软件密钥库（TPM 提供程序会导入密钥却拒绝导出，见下） | 有 TPM 时用 TPM，否则软件密钥库 |
| Android | 已实现，报告 keystore 对该条目的说法                 | 已实现，优先 StrongBox          |
| 其它    | `UnsupportedPlatform`                                | `UnsupportedPlatform`           |

> Windows 上值得先知道的一点：**直接**形式只能落在软件密钥库上，因为 Microsoft
> Platform Crypto Provider 会接受我们的密钥、然后拒绝把材料导出（`NTE_PERM`）。一个
> 拿不回材料的库不满足「直接」的契约，所以它如实报告 `Backend::Software`；想要 TPM
> 保护请选**包裹**形式。`Backend::Software` 意味着私钥只是操作系统保护下的一份软件
> 密钥，界面必须在关键操作前告知用户。

## 接入你自己的项目

```toml
[dependencies]
qualia-dik = "0.1.3"
```

要在自己的测试里使用内存后端（例如在没有 TPM 的 CI 上测试协议逻辑）：

```toml
[dev-dependencies]
qualia-dik = { version = "0.1.3", features = ["mock"] }
```

```rust
use qualia_dik::{DeviceKeyStore, MockKeyStore};

let store = MockKeyStore::new();
let signer = store.create("test-device")?;
```

`mock` 后端的「硬件」是一个 `HashMap`，且**不做持久化**。它只用于测试：任何
在生产路径上使用它的代码，都会在重启后立刻暴露（密钥不见了），而不是带着一份
没有硬件保护的密钥一直跑下去。

## 接口约定

- **`label` 是身份的持久名字**，只允许 ASCII 字母、数字、`-`、`_`、`.`。它会被
  放进系统密钥库的命名空间，因此不允许空字符之类的字符——`"a\0b"` 与 `"a"` 在 C
  字符串看来是同一个名字，那会让两个不同的身份撞在一起。
- **`create` 不覆盖已有密钥**，已存在时返回 `KeyAlreadyExists`。想表达「有则打开、
  无则创建」请用 `open_or_create`。
- **`delete` 是不可逆的**：那台设备将永久无法再证明自己是原来的那台设备，对方设备
  上记录的它会变成无法验证的孤儿。调用前请取得用户确认。
- **`sign` 收消息，`sign_digest` 收摘要**。签名与验签必须对「谁负责哈希」有唯一
  答案，所以消息模式固定使用 SHA-256；`device::verify` 遵循同一约定。

## 参与贡献

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo test --doc --features mock   # 文档示例只在 mock 下有后端可用
cargo doc --no-deps                # 不得有警告（配 RUSTDOCFLAGS="-D warnings"）
cargo check --features mock        # feature 组合也要能编译
cargo +1.89 check --all-targets --features mock
cargo deny check
```

设计与安全的约定：

- **本 crate 是整个项目里唯一允许出现 `unsafe` 的地方**，也是唯一接触平台原生
  API 的地方。它存在的原因就是让上层能保住 `#![forbid(unsafe_code)]`。因此
  **不要**把协议逻辑、密码学原语或任何能用纯 Rust 表达的东西放进来。
- **每个 `unsafe` 块都要有 `// SAFETY:` 说明**，写清为什么这里的不变式成立。
- **签名算法固定 ECDSA P-256**，这不是偏好而是硬约束：Android KeyMint 没有
  EdDSA，Apple 的 Secure Enclave 只支持 NIST P-256。
- **任何输入都不得导致 panic。**
- **错误里不得出现秘密材料。** 本层只处理公钥、消息与密钥名，因此本来就没有秘密
  可泄露——新增后端时不要破坏这个性质。
- **不得静默降级到软件密钥。** 那会让用户以为自己受硬件保护，而实际不是。
- 新增平台后端时，请同时把它加进 `platform_backend_is_implemented`，并在
  `src/keystore/platform.rs` 的表格里登记。

### MSRV 策略

最低支持 Rust **1.89**。MSRV 会随依赖的实际需要提升，但每次提升都要在 CI 里
用真实工具链验证过（`cargo +1.89 check --all-targets`）。

## 发布

打一个 `v*` 标签会触发发布流程。它先用 `cargo publish --dry-run` 在**所有**
目标平台上验证打包结果，确认无误后才真正发布，并在结束后打上对应的 git 标签。

发布前需要在本仓库的 Actions secrets 里配置 `CRATES_IO_PUBLISH_KEY`（crates.io
的 API token，需要 `publish-new` 与 `publish-update` 权限）。

## 许可

LGPL-3.0-or-later，见 [LICENSE](LICENSE) 与 [COPYING.LESSER](COPYING.LESSER)。

选择 LGPL 而非 MIT/Apache 是刻意的：本 crate 处理的是设备身份的私钥，任何修改
都应当以源码形式回馈，以便被审计。
