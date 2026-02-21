//! # mosh-wasm
//!
//! wasm-bindgen エクスポート：VS Code Extension（Node.js）から呼び出す公開 API。
//!
//! ## 使用方法（TypeScript）
//!
//! ```typescript
//! import { MoshClient, init_panic_hook } from '../mosh-wasm-pkg/mosh_wasm';
//!
//! // パニック時のスタックトレースを有効化（開発時）
//! init_panic_hook();
//!
//! // クライアント初期化
//! const client = new MoshClient("4NeCCgvZFe2RnPgrcU1PQw", 500);
//!
//! // 受信 UDP パケットを処理
//! const data = client.recvUdpPacket(udpBuffer, Date.now());
//! if (data.length > 0) {
//!     managedMessagePassing.emit(data);
//! }
//!
//! // VS Code からのデータを送信
//! const packets = client.sendData(rpcData, Date.now());
//! for (const pkt of packets) {
//!     socket.send(Buffer.from(pkt));
//! }
//!
//! // 定期タイマー（50ms ごと）
//! const packets = client.tick(Date.now());
//! ```

use wasm_bindgen::prelude::*;

pub mod client;

pub use client::MoshClient;

/// パニック時にブラウザコンソールにスタックトレースを出力する
///
/// 開発時に必ず呼び出すこと。本番ビルドでは feature flag で無効化可能。
#[wasm_bindgen]
pub fn init_panic_hook() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

/// Base64 鍵（22文字）を 16 バイトの Uint8Array に変換するユーティリティ
///
/// テスト・デバッグ用。実際の使用では `MoshClient` のコンストラクタに渡す。
///
/// # 引数
/// - `key_b64`: mosh-server が出力した Base64 鍵（例: "4NeCCgvZFe2RnPgrcU1PQw"）
///
/// # エラー
/// - Base64 デコード失敗
/// - 鍵長が 16 バイト以外
#[wasm_bindgen(js_name = "decodeBase64Key")]
pub fn decode_base64_key(key_b64: &str) -> Result<js_sys::Uint8Array, JsError> {
    let key = mosh_crypto::decode_base64_key(key_b64)
        .map_err(|e| JsError::new(&alloc::format!("{}", e)))?;
    let arr = js_sys::Uint8Array::new_with_length(16);
    arr.copy_from(&key);
    Ok(arr)
}

extern crate alloc;
