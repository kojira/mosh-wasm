# mosh-wasm

**mosh プロトコルの Rust/WASM 実装** — VS Code Remote-Mosh 拡張機能向け

[![Rust](https://img.shields.io/badge/Rust-2021-orange)](https://www.rust-lang.org/)
[![WASM](https://img.shields.io/badge/Target-wasm32--unknown--unknown-blue)](https://webassembly.org/)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-green)](LICENSE)

---

## 概要

[mosh](https://mosh.org/)（mobile shell）プロトコルを Rust で実装し、WebAssembly（WASM）にビルドするプロジェクト。

VS Code の `RemoteAuthorityResolver` API と組み合わせることで、**mosh の UDP/SSP/AES-OCB3 プロトコルを使ったフルリモート開発環境**を実現する。

### なぜ mosh をバイトストリームトンネルとして使うのか

通常の mosh は VT100 端末エミュレーターとして動作するが、このプロジェクトでは端末エミュレーション機能を完全にバイパスし、**VS Code の Extension Host プロトコル（バイトストリーム）を mosh の暗号化 UDP チャンネルで転送する**。

これにより:
- 🛡️ **耐障害性**: 接続が一時的に切れても自動復旧（TCP のような接続断なし）
- 📡 **ネットワーク移行**: Wi-Fi → LTE の切り替えでもセッション維持
- 🔒 **AES-128-OCB3 暗号化**: all traffic は暗号化済み
- ⚡ **UDP の低レイテンシ**: パケットロスがあっても最新状態を優先

---

## アーキテクチャ

```
VS Code Extension Host (Node.js)
│
├── RemoteAuthorityResolver
│     └── ManagedResolvedAuthority
│           └── ManagedMessagePassing
│                 ├── send(data)    → mosh-wasm → UDP → mosh-server
│                 └── onMessage(data) ← mosh-wasm ← UDP ← mosh-server
│
└── mosh-wasm (Rust → WASM)
      ├── mosh-crypto    : AES-128-OCB3 暗号化/復号
      ├── mosh-proto     : Protobuf（Instruction のエンコード/デコード）
      ├── mosh-transport : Fragment 分割・再組み立て
      ├── mosh-ssp       : SSP 状態機械（ACK、RTT、再送）
      └── mosh-stream    : バイトストリームバッファ
```

### WASM と Node.js の責任分担

| 責任 | 担当 |
|------|------|
| AES-128-OCB3 暗号化/復号 | WASM (Rust) |
| SSP プロトコル状態機械 | WASM (Rust) |
| Protobuf エンコード/デコード | WASM (Rust) |
| Fragment 組み立て/分解 | WASM (Rust) |
| UDP ソケット送受信 | Node.js |
| SSH 接続（初期ハンドシェイク）| Node.js |
| タイマー・ハートビートトリガー | Node.js |

---

## クレート構成

```
mosh-wasm/
├── Cargo.toml              # ワークスペース定義
├── build.sh                # ビルドスクリプト
│
└── crates/
    ├── mosh-crypto/        # AES-128-OCB3 暗号プリミティブ
    ├── mosh-proto/         # Protobuf スキーマ + prost コード生成
    ├── mosh-transport/     # Fragment/Reassembly、UDP パケット構造
    ├── mosh-ssp/           # SSP State Synchronization Protocol コア
    ├── mosh-stream/        # バイトストリーム ↔ SSP 変換レイヤー
    └── mosh-wasm/          # wasm-bindgen エクスポート（公開 API）
```

---

## ビルド方法

### 前提条件

```bash
# Rust のインストール（未インストールの場合）
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# wasm32 ターゲットの追加
rustup target add wasm32-unknown-unknown

# wasm-pack のインストール
cargo install wasm-pack
```

### ビルドコマンド

```bash
# リリースビルド（WASM、最適化済み）
./build.sh

# デバッグビルド（WASM、ソースマップあり）
./build.sh --dev

# cargo check のみ（エラー確認）
./build.sh --check

# ユニットテストのみ（native）
./build.sh --test
```

### 手動ビルド

```bash
# native テスト（cargo test）
cargo test --workspace

# WASM リリースビルド
wasm-pack build crates/mosh-wasm \
    --target nodejs \
    --out-dir ../../mosh-wasm-pkg \
    --release

# 生成物
ls mosh-wasm-pkg/
# mosh_wasm_bg.wasm       : WASM バイナリ
# mosh_wasm.js            : CommonJS ラッパー
# mosh_wasm.d.ts          : TypeScript 型定義
# package.json            : npm パッケージ情報
```

---

## Node.js からの使用例

```typescript
import { MoshClient, init_panic_hook } from './mosh-wasm-pkg/mosh_wasm';
import * as dgram from 'dgram';

// パニック時のデバッグ情報を有効化（開発時）
init_panic_hook();

// mosh クライアント初期化
const client = new MoshClient("4NeCCgvZFe2RnPgrcU1PQw", 500);

// UDP ソケット
const socket = dgram.createSocket('udp4');

// UDP 受信 → WASM で処理
socket.on('message', (msg: Buffer) => {
    const bytes = new Uint8Array(msg.buffer, msg.byteOffset, msg.byteLength);
    const data = client.recvUdpPacket(bytes, Date.now());
    if (data.length > 0) {
        // VS Code RPC に渡す
        managedMessagePassing.emit(data);
    }
});

// UDP 接続
socket.connect(60001, 'remote-server.example.com');

// 定期タイマー（50ms ごと）
setInterval(() => {
    const packets = client.tick(Date.now());
    for (const pkt of packets) {
        socket.send(Buffer.from(pkt));
    }
}, 50);

// VS Code からのデータを mosh で送信
function sendToRemote(data: Uint8Array) {
    const packets = client.sendData(data, Date.now());
    for (const pkt of packets) {
        socket.send(Buffer.from(pkt));
    }
}
```

---

## 依存クレート

| クレート | バージョン | 用途 |
|---------|-----------|------|
| `ocb3` | 0.2.x | AES-128-OCB3 AEAD（RustCrypto） |
| `aes` | 0.8.x | AES ブロック暗号 |
| `prost` | 0.13.x | Protocol Buffers（no_std 対応） |
| `wasm-bindgen` | 0.2.x | Rust ↔ JavaScript FFI |
| `js-sys` | 0.3.x | JavaScript 型（Uint8Array 等） |
| `base64` | 0.22.x | mosh 鍵のデコード |
| `getrandom` | 0.2.x | WASM 環境での乱数生成 |
| `serde_json` | 1.x | 統計情報の JSON シリアライズ |

---

## ライセンス

GPL-3.0 — mosh 本家と同じライセンス

---

## 参考資料

- [mosh プロジェクト](https://mosh.org/)
- [mosh ソースコード](https://github.com/mobile-shell/mosh)
- [RFC 7253 (OCB3)](https://www.rfc-editor.org/rfc/rfc7253)
- [VS Code Remote API](https://code.visualstudio.com/api/references/vscode-api#RemoteAuthorityResolver)
- [wasm-bindgen](https://rustwasm.github.io/wasm-bindgen/)
