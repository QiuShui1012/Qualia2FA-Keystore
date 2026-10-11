# Qualia2FA-Keystore

Qualia2FA 的**平台硬件密钥库层**。它把「在设备硬件里生成一个 ECDSA P-256 密钥、
取回公钥、让硬件对消息签名」这件事封装成安全的 Rust 接口，让上层不必接触任何平台
原生 API。

私钥**永不离开硬件**，也永不进入本进程的地址空间。

## 状态

已实现：

- 抽象层：`DeviceKeyStore` / `DeviceSigner`，以及后端能力查询
- **Windows**：CNG `NCrypt*` + TPM 2.0（`MS_PLATFORM_CRYPTO_PROVIDER`）
- **Windows（无 TPM 时）**：CNG 软件密钥库降级路径
- 测试用的内存后端（`mock` feature，**默认关闭**）

尚未实现：macOS（Secure Enclave）、Linux（TPM 2.0）、Android（Keystore /
StrongBox）、iOS（Secure Enclave）。

> 调用 `DeviceKeyStore::backend` 可以查到某份密钥库**运行时**实际使用的后端。
> 在没有 TPM 的 Windows 机器上它会返回 `Backend::Software`——即私钥以软件形式
> 保存，只受操作系统用户账户保护。**本层不会静默降级**：未实现的平台返回
> `UnsupportedPlatform`，是否接受软件密钥由调用方（也就是用户）决定。

## 用法

```rust
use qualia2fa_keystore::{Backend, DeviceKeyStore, DeviceSigner};
use qualia2fa_keystore::platform::{WindowsKeyStore, WindowsProvider};

// 优先用 TPM；本机没有 TPM 时退回软件密钥库。
let store = WindowsKeyStore::open_best_available()?;

// 如实告诉用户私钥在哪里。
if !store.backend().is_hardware_backed() {
    eprintln!("警告：本机没有可用的 TPM，设备身份密钥将以软件形式保存。");
}

// 打开已有身份；不存在则创建。
let signer = store.open_or_create("account-1")?;

// 公钥不是秘密，可以随意传播。
println!("设备 ID: {}", signer.public_key().device_id());

// 签名。硬件签名的是摘要，本层负责先做 SHA-256。
let signature = signer.sign(b"待签名的消息")?;

// 用核心库验签（Core 拥有验签逻辑，本层不重复实现）。
qualia2fa_core::device::verify(signer.public_key(), b"待签名的消息", &signature)?;
```

几个值得注意的接口约定：

- **`label` 是身份的持久名字**，只允许 ASCII 字母、数字、`-`、`_`、`.`。它会被
  放进系统密钥库的命名空间，因此不允许空字符之类的字符——`"a\0b"` 与 `"a"` 在 C
  字符串看来是同一个名字，那会让两个不同的身份撞在一起。
- **`create` 不覆盖已有密钥**，已存在时返回 `KeyAlreadyExists`。想表达「有则打开、
  无则创建」请用 `open_or_create`。
- **`delete` 是不可逆的**：那台设备将永久无法再证明自己是原来的那台设备，对方设备
  上记录的它会变成无法验证的孤儿。调用前请取得用户确认。
- **`sign` 收消息，`sign_digest` 收摘要**。签名与验签必须对「谁负责哈希」有唯一
  答案，所以消息模式固定使用 SHA-256。

## 接入你自己的项目

```toml
[dependencies]
qualia2fa-core = { git = "https://github.com/QiuShui1012/Qualia2FA-Core" }
qualia2fa-keystore = { git = "https://github.com/QiuShui1012/Qualia2FA-Keystore" }
```

本 crate 以 `path = "Core"` 依赖核心库。本地开发时在仓库根放一个指向核心库的目录
联接即可；CI 中由 workflow 显式检出。**目录联接不入库。**

若要在自己的测试里使用内存后端（例如在没有 TPM 的 CI 上测试协议逻辑）：

```toml
[dev-dependencies]
qualia2fa-keystore = { git = "...", features = ["mock"] }
```

```rust
use qualia2fa_keystore::{DeviceKeyStore, MockKeyStore};

let store = MockKeyStore::new();
let signer = store.create("test-device")?;
```

`mock` 后端的「硬件」是一个 `HashMap`，且**不做持久化**。它只用于测试：任何
在生产路径上使用它的代码，都会在重启后立刻暴露（密钥不见了），而不是带着一份
没有硬件保护的密钥一直跑下去。

## 参与贡献

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo doc --no-deps            # 不得有警告
cargo check --features mock    # feature 组合也要能编译
```

设计与安全的约定：

- **本 crate 是整个项目里唯一允许出现 `unsafe` 的地方**，也是唯一接触平台原生
  API 的地方。它存在的原因就是让核心库能保住 `#![forbid(unsafe_code)]`。因此
  **不要**把协议逻辑、密码学原语或任何能用纯 Rust 表达的东西放进来——那些属于
  核心库。
- **每个 `unsafe` 块都要有 `// SAFETY:` 说明**，写清为什么这里的不变式成立。
- **签名算法固定 ECDSA P-256**，这不是偏好而是硬约束：Android KeyMint 没有
  EdDSA，Apple 的 Secure Enclave 只支持 NIST P-256。
- **任何输入都不得导致 panic。**
- **错误里不得出现秘密材料。** 本层只处理公钥、消息与密钥名，因此本来就没有秘密
  可泄露——新增后端时不要破坏这个性质。
- **不得静默降级到软件密钥。** 那会让用户以为自己受硬件保护，而实际不是。
- 新增平台后端时，请同时把它加进 `platform_backend_is_implemented`，并在
  `src/platform.rs` 的表格里登记。

### MSRV 策略

最低支持 Rust **1.89**。MSRV 会随依赖的实际需要提升，但每次提升都要在 CI 里
用真实工具链验证过（`cargo +1.89 check --all-targets`）。

## 许可

LGPL-3.0-or-later，见 [LICENSE](LICENSE) 与 [COPYING.LESSER](COPYING.LESSER)。

选择 LGPL 而非 MIT/Apache 是刻意的：本 crate 处理的是设备身份的私钥，任何修改
都应当以源码形式回馈，以便被审计。
