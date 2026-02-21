# DEVELOPMENT.md — 開発環境セットアップガイド

mosh-wasm プロジェクトの開発環境構築と開発ワークフローの解説。

---

## 目次

1. [必要なツール](#1-必要なツール)
2. [環境セットアップ](#2-環境セットアップ)
3. [プロジェクト構造](#3-プロジェクト構造)
4. [開発ワークフロー](#4-開発ワークフロー)
5. [テスト方法](#5-テスト方法)
6. [デバッグ方法](#6-デバッグ方法)
7. [クレート別の開発ガイド](#7-クレート別の開発ガイド)
8. [トラブルシューティング](#8-トラブルシューティング)

---

## 1. 必要なツール

| ツール | バージョン | 用途 |
|-------|-----------|------|
| Rust | 1.75+ (stable) | コンパイラ |
| Cargo | Rust に同梱 | パッケージマネージャー |
| wasm-pack | 0.12+ | WASM ビルドツール |
| rustup | 最新版 | Rust ツールチェーン管理 |
| Node.js | 18+ | テスト・統合確認用 |
| Wireshark | オプション | パケット解析 |

---

## 2. 環境セットアップ

### 2.1 Rust のインストール

```bash
# rustup でインストール（未インストールの場合）
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# ターミナルを再起動、またはパスを通す
source "$HOME/.cargo/env"

# インストール確認
rustc --version  # rustc 1.75.0 (stable) 以上
cargo --version
```

### 2.2 wasm32 ターゲットの追加

```bash
# wasm32-unknown-unknown ターゲットを追加（WASM ビルドに必須）
rustup target add wasm32-unknown-unknown

# 確認
rustup target list --installed | grep wasm32
# → wasm32-unknown-unknown (installed)
```

### 2.3 wasm-pack のインストール

```bash
# cargo でインストール
cargo install wasm-pack

# または curl でインストール（より高速）
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

# 確認
wasm-pack --version  # wasm-pack 0.12.0 以上
```

### 2.4 開発用ツール（オプション）

```bash
# cargo-watch: ファイル変更時に自動でコマンドを実行
cargo install cargo-watch

# cargo-expand: マクロ展開の確認
cargo install cargo-expand

# sccache: ビルドキャッシュ（ビルド高速化）
cargo install sccache

# twiggy: WASM バイナリサイズ分析
cargo install twiggy

# wasm-opt: WASM バイナリ最適化（wasm-pack が自動使用）
# Homebrew (macOS): brew install binaryen
```

---

## 3. プロジェクト構造

```
mosh-wasm/
├── Cargo.toml              # ワークスペース定義（全クレートの依存バージョンを一元管理）
├── build.sh                # WASM ビルドスクリプト
├── README.md               # プロジェクト概要
├── DEVELOPMENT.md          # このファイル
│
├── .cargo/
│   └── config.toml         # wasm32 向けコンパイルフラグ
│
└── crates/
    ├── mosh-crypto/        # 暗号プリミティブ（no_std）
    │   ├── Cargo.toml
    │   └── src/
    │       ├── lib.rs       # パブリック API
    │       ├── session.rs   # CryptoSession
    │       ├── nonce.rs     # MoshNonce
    │       └── error.rs
    │
    ├── mosh-proto/         # Protobuf 定義
    │   ├── Cargo.toml
    │   ├── build.rs         # prost-build
    │   ├── proto/
    │   │   └── transportinstruction.proto
    │   └── src/
    │       ├── lib.rs
    │       └── error.rs
    │
    ├── mosh-transport/     # Fragment/Reassembly
    │   ├── Cargo.toml
    │   └── src/
    │       ├── lib.rs
    │       ├── fragment.rs  # Fragment, Fragmenter, FragmentAssembly
    │       ├── packet.rs    # UdpPacket
    │       └── timestamp.rs # Timestamp16
    │
    ├── mosh-ssp/           # SSP 状態機械
    │   ├── Cargo.toml
    │   └── src/
    │       ├── lib.rs
    │       └── session.rs   # SspSession
    │
    ├── mosh-stream/        # バイトストリームバッファ
    │   ├── Cargo.toml
    │   └── src/
    │       ├── lib.rs
    │       └── channel.rs   # StreamChannel
    │
    └── mosh-wasm/          # WASM エントリポイント
        ├── Cargo.toml
        ├── mosh_wasm.d.ts   # TypeScript 型定義ひな形
        └── src/
            ├── lib.rs       # wasm-bindgen エクスポート
            └── client.rs    # MoshClient 実装
```

---

## 4. 開発ワークフロー

### 4.1 日常的な開発サイクル

```bash
# コードを変更したら:
# 1. cargo check で文法エラーを確認（高速）
cargo check --workspace

# 2. テストを実行（native）
cargo test --workspace

# 3. WASM ビルドで動作確認
wasm-pack build crates/mosh-wasm --target nodejs --out-dir ../../mosh-wasm-pkg --dev
```

### 4.2 自動ビルド（cargo-watch）

```bash
# ファイル変更時に cargo check を自動実行
cargo watch -x check

# ファイル変更時にテストを自動実行
cargo watch -x test

# mosh-crypto のみウォッチ
cargo watch -p mosh-crypto -x check
```

### 4.3 個別クレートのビルド

```bash
# 特定のクレートのみビルド
cargo build --package mosh-crypto

# 特定のクレートのみテスト
cargo test --package mosh-crypto -- --nocapture
```

---

## 5. テスト方法

### 5.1 ユニットテスト（native）

各クレートには `#[cfg(test)]` ブロックでユニットテストが含まれている。

```bash
# 全クレートのテスト（詳細出力）
cargo test --workspace -- --nocapture

# 特定クレートのテスト
cargo test --package mosh-crypto
cargo test --package mosh-transport
cargo test --package mosh-ssp

# 特定のテスト関数のみ実行
cargo test --package mosh-crypto -- test_encrypt_decrypt_roundtrip

# テスト一覧を表示（実行しない）
cargo test --workspace -- --list
```

### 5.2 WASM テスト（wasm-pack test）

```bash
# Node.js でテスト実行
wasm-pack test crates/mosh-wasm --node

# ブラウザでテスト（ヘッドレス Chrome）
wasm-pack test crates/mosh-wasm --headless --chrome
```

### 5.3 暗号相互運用性テスト

実際の mosh-server との相互運用性を確認するテスト（フェーズ 1 で実装予定）:

```bash
# ローカルの mosh-server（localhost）との疎通テスト
# 要: mosh-server がインストール済みの環境
cargo test --package mosh-crypto -- test_interop -- --nocapture
```

---

## 6. デバッグ方法

### 6.1 WASM のパニックトレース

開発ビルドでは `console_error_panic_hook` が有効になっており、
パニック時にブラウザコンソールにスタックトレースが出力される。

```typescript
// Node.js スクリプトの先頭に追加
import { init_panic_hook } from './mosh-wasm-pkg/mosh_wasm';
init_panic_hook(); // パニック時のデバッグ情報を有効化
```

### 6.2 ログ出力

```rust
// WASM 環境でのコンソール出力
use web_sys::console;
console::log_1(&"デバッグメッセージ".into());
console::error_1(&format!("エラー: {}", e).into());
```

### 6.3 WASM バイナリサイズ分析

```bash
# twiggy で何がバイナリを大きくしているか分析
twiggy top mosh-wasm-pkg/mosh_wasm_bg.wasm

# 関数ごとのサイズ
twiggy dominators mosh-wasm-pkg/mosh_wasm_bg.wasm
```

### 6.4 Wireshark でのパケット解析

実際の mosh セッションをキャプチャして暗号化/復号の動作確認:

```bash
# mosh-server のデバッグログから鍵を取得
mosh-server new -p 60001 -- bash 2>&1 | grep "MOSH CONNECT"
# → MOSH CONNECT 60001 4NeCCgvZFe2RnPgrcU1PQw

# Wireshark で UDP/60001 をキャプチャ
# 既知の鍵で復号テスト
cargo test --package mosh-crypto -- test_interop_with_wireshark_capture
```

---

## 7. クレート別の開発ガイド

### 7.1 mosh-crypto の開発

`no_std` + `alloc` 環境。OCB3 の RFC7253 テストベクタを使って検証する。

```bash
# テスト実行
cargo test --package mosh-crypto -- --nocapture

# WASM ターゲットでビルドが通ることを確認
cargo check --package mosh-crypto --target wasm32-unknown-unknown
```

**注意事項**:
- `std` には依存しない（`no_std` 設定）
- `alloc::vec::Vec` を使う（`std::vec::Vec` ではなく）
- タイミング攻撃への注意: 復号エラーは詳細を外部に漏らさない

### 7.2 mosh-proto の開発

`build.rs` で `prost-build` が自動的に `.proto` → Rust コードを生成する。

```bash
# proto ファイルを変更したら:
touch crates/mosh-proto/build.rs  # 再ビルドをトリガー
cargo build --package mosh-proto

# 生成コードの確認
cat target/debug/build/mosh-proto-*/out/transport_buffers.rs
```

### 7.3 mosh-ssp の開発

SSP は mosh のコアプロトコル。実装は C++ ソース（`src/network/`）を参照:
- `transportinstruction.cc`: Instruction の管理
- `transport.cc`: Transport/Connection クラス

RTT 推定は RFC 6298 (TCP RTO) のアルゴリズムを使用。

### 7.4 mosh-wasm の開発

wasm-bindgen のエクスポートクラス。`#[wasm_bindgen]` マクロの制約に注意:
- `Clone` が不要なため、`&self` / `&mut self` メソッドを使う
- JS との境界では `Uint8Array`（`Vec<u8>` ではなく）を使う
- エラーは `JsError` でラップして返す

---

## 8. トラブルシューティング

### `cargo check` が通らない場合

```bash
# エラーの詳細を確認
cargo check --workspace 2>&1 | head -50

# 依存クレートの再フェッチ
cargo update
```

### WASM ビルドが失敗する場合

```bash
# wasm32 ターゲットで確認
cargo check --workspace --target wasm32-unknown-unknown

# よくあるエラー:
# 1. std に依存しているコード → no_std + alloc に変更
# 2. getrandom の js feature が足りない → Cargo.toml を確認
# 3. prost の版数不一致 → workspace.dependencies を確認
```

### `ocb3` クレートがビルドできない場合

```bash
# RustCrypto の ocb3 は nightly を使わず stable Rust で動作するはず
rustup default stable

# もし問題があれば
cargo update ocb3
```

### `prost-build` が .proto を見つけられない場合

```bash
# build.rs のパスを確認
cat crates/mosh-proto/build.rs
# proto/ ディレクトリが存在するか確認
ls crates/mosh-proto/proto/
```

---

## 参考リンク

- [Rust Documentation](https://doc.rust-lang.org/book/)
- [wasm-bindgen Guide](https://rustwasm.github.io/wasm-bindgen/)
- [wasm-pack Docs](https://rustwasm.github.io/wasm-pack/)
- [RustCrypto AEADs](https://github.com/RustCrypto/AEADs)
- [prost（Protocol Buffers）](https://github.com/tokio-rs/prost)
- [mosh ソースコード](https://github.com/mobile-shell/mosh)
- [RFC 7253 (OCB3)](https://www.rfc-editor.org/rfc/rfc7253)
- [RFC 6298 (TCP RTO)](https://www.rfc-editor.org/rfc/rfc6298)
