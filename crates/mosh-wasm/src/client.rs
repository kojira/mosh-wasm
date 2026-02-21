//! MoshClient wasm-bindgen エクスポート
//!
//! VS Code Extension（Node.js）から呼び出す mosh クライアントの主エントリポイント。
//! 暗号化・SSP プロトコル・Fragment 管理を統合する。

extern crate alloc;

use alloc::format;
use alloc::vec::Vec;

use wasm_bindgen::prelude::*;
use js_sys::Uint8Array;

use mosh_crypto::{CryptoSession, Direction};
use mosh_proto::Instruction;
use mosh_ssp::SspSession;
use mosh_stream::StreamChannel;
use mosh_transport::{Fragment, FragmentAssembly, Fragmenter, Timestamp16};

/// mosh プロトコルのデフォルト MTU（バイト）
/// モバイル環境向けの保守的な設定
const DEFAULT_MTU: u32 = 500;

/// Fragment ヘッダーのオーバーヘッド（バイト）
/// - nonce_tail: 8
/// - auth_tag: 16
/// - direction_seq: 8
/// - timestamp: 2
/// - timestamp_reply: 2
/// - fragment_header: 10
const CRYPTO_OVERHEAD: usize = 46;

/// mosh クライアントセッション
///
/// AES-128-OCB3 暗号化 + SSP プロトコル + Fragment 管理を統合した
/// wasm-bindgen エクスポートクラス。
///
/// ## 内部アーキテクチャ
///
/// ```text
/// MoshClient
///   ├── CryptoSession  (mosh-crypto) - AES-128-OCB3 暗号化/復号
///   ├── Fragmenter     (mosh-transport) - Instruction を Fragment に分割
///   ├── FragmentAssembly (mosh-transport) - Fragment を再組み立て
///   ├── SspSession     (mosh-ssp) - SSP 状態機械
///   └── StreamChannel  (mosh-stream) - バイトストリームバッファ
/// ```
///
/// ## スレッド安全性
///
/// WASM は シングルスレッドのため、`!Send + !Sync` を満たす。
/// JS からは単一スレッドで呼び出される前提。
#[wasm_bindgen]
pub struct MoshClient {
    /// 暗号セッション（AES-128-OCB3）
    crypto: CryptoSession,
    /// Fragment 分割器
    fragmenter: Fragmenter,
    /// Fragment 再組み立て器
    assembly: FragmentAssembly,
    /// SSP 状態機械
    ssp: SspSession,
    /// バイトストリームチャンネル
    stream: StreamChannel,
    /// 最後に受信したタイムスタンプ（RTT 計算用にエコーバック）
    last_remote_timestamp: u16,
}

#[wasm_bindgen]
impl MoshClient {
    /// mosh クライアントを初期化する
    ///
    /// # 引数
    /// - `key_base64`: mosh-server が出力した Base64 鍵（22文字）
    ///   例: `"4NeCCgvZFe2RnPgrcU1PQw"`
    /// - `mtu`: UDP の実効 MTU（バイト）。省略時は 500（モバイル推奨値）。
    ///
    /// # エラー
    /// - Base64 鍵のデコード失敗
    /// - 鍵長が不正
    ///
    /// # 例（TypeScript）
    /// ```typescript
    /// const client = new MoshClient("4NeCCgvZFe2RnPgrcU1PQw");
    /// const client2 = new MoshClient("4NeCCgvZFe2RnPgrcU1PQw", 1400); // 大きい MTU
    /// ```
    #[wasm_bindgen(constructor)]
    pub fn new(key_base64: &str, mtu: Option<u32>) -> Result<MoshClient, JsError> {
        let crypto = CryptoSession::from_base64_key(key_base64)
            .map_err(|e| JsError::new(&format!("Invalid mosh key: {}", e)))?;

        let effective_mtu = mtu.unwrap_or(DEFAULT_MTU) as usize;
        // Fragment のペイロード MTU = UDP MTU - 暗号オーバーヘッド
        let app_payload_mtu = effective_mtu.saturating_sub(CRYPTO_OVERHEAD).max(64);

        Ok(MoshClient {
            crypto,
            fragmenter: Fragmenter::new(app_payload_mtu),
            assembly: FragmentAssembly::new(),
            ssp: SspSession::new(),
            stream: StreamChannel::new(),
            last_remote_timestamp: Timestamp16::INIT.raw(),
        })
    }

    /// 受信した UDP ペイロード（生バイト）を処理する
    ///
    /// 処理フロー:
    /// 1. AES-128-OCB3 復号
    /// 2. Fragment ヘッダーを解析
    /// 3. Fragment が揃ったら Instruction に再組み立て
    /// 4. SSP プロトコル処理（ACK、状態更新）
    /// 5. ペイロードをストリームバッファに積む
    ///
    /// # 引数
    /// - `udp_bytes`: Node.js `socket.on('message', msg)` の `msg` を Uint8Array に変換したもの
    /// - `now_ms`: 現在時刻（`Date.now()` の値）
    ///
    /// # 戻り値
    /// 上位レイヤー（VS Code RPC）に渡すバイト列。空の場合は長さ 0 の Uint8Array。
    ///
    /// # エラー
    /// - 復号失敗（タグ不一致、パケット破損）
    ///   注: パケットロスは mosh では正常なので、エラーは軽微として扱う
    #[wasm_bindgen(js_name = "recvUdpPacket")]
    pub fn recv_udp_packet(
        &mut self,
        udp_bytes: &[u8],
        now_ms: f64,
    ) -> Result<Uint8Array, JsError> {
        let now_ms = now_ms as u64;

        // 復号
        let decrypted = self
            .crypto
            .decrypt_packet(udp_bytes)
            .map_err(|e| JsError::new(&format!("Decryption failed: {}", e)))?;

        // タイムスタンプを記録（エコーバック用）
        self.last_remote_timestamp = decrypted.timestamp;

        // Fragment の再組み立て
        let frag = Fragment::from_bytes(&decrypted.payload)
            .map_err(|e| JsError::new(&format!("Fragment parse failed: {}", e)))?;

        let instruction_bytes = match self.assembly.add_fragment(frag) {
            Some(bytes) => bytes,
            None => {
                // まだ Fragment が揃っていない
                return Ok(Uint8Array::new_with_length(0));
            }
        };

        // Instruction のデコード
        let instr = Instruction::decode_from_bytes(&instruction_bytes)
            .map_err(|e| JsError::new(&format!("Instruction decode failed: {}", e)))?;

        // SSP 処理
        let payload = self.ssp.recv_instruction(&instr, now_ms);

        // ストリームバッファに積む
        if let Some(data) = payload {
            self.stream.apply_diff(&data);
        }

        // 読み取り可能なデータを返す
        if self.stream.has_pending_read() {
            let data = self.stream.read_available();
            let arr = Uint8Array::new_with_length(data.len() as u32);
            arr.copy_from(&data);
            Ok(arr)
        } else {
            Ok(Uint8Array::new_with_length(0))
        }
    }

    /// 上位レイヤー（VS Code RPC）からのデータを mosh で送信する
    ///
    /// 処理フロー:
    /// 1. ストリームバッファに積む
    /// 2. SSP Instruction を生成
    /// 3. Fragment に分割
    /// 4. AES-128-OCB3 で暗号化
    /// 5. UDP ペイロードのリストを返す
    ///
    /// # 引数
    /// - `data`: `ManagedMessagePassing.send()` で来た Uint8Array
    /// - `now_ms`: 現在時刻（`Date.now()`）
    ///
    /// # 戻り値
    /// 送信すべき UDP ペイロードの配列。各要素を `socket.send()` で送信する。
    ///
    /// # エラー
    /// - 暗号化失敗（通常は起こらない）
    #[wasm_bindgen(js_name = "sendData")]
    pub fn send_data(
        &mut self,
        data: &[u8],
        now_ms: f64,
    ) -> Result<js_sys::Array, JsError> {
        let now_ms = now_ms as u64;

        // ストリームバッファにデータを積む
        self.stream.write(data);

        // 送信 Instruction を生成して UDP ペイロードに変換
        self.flush_to_udp(now_ms)
    }

    /// 定期タイマー tick（ハートビート・再送管理）
    ///
    /// Node.js の `setInterval(50)` から定期的に呼び出す。
    /// - ペイロードがあれば送信
    /// - 再送が必要な Instruction を再送
    /// - ハートビートが必要なら ACK のみのパケットを送信
    ///
    /// # 引数
    /// - `now_ms`: 現在時刻（`Date.now()`）
    ///
    /// # 戻り値
    /// 送信すべき UDP ペイロードの配列
    #[wasm_bindgen]
    pub fn tick(&mut self, now_ms: f64) -> Result<js_sys::Array, JsError> {
        let now_ms = now_ms as u64;

        // ストリームバッファに溜まっているデータを SSP に渡す
        let pending_diff = self.stream.take_pending_diff();
        if !pending_diff.is_empty() {
            self.ssp.push_payload(pending_diff);
        }

        // SSP の tick で送信すべき Instruction 列を取得
        let instructions = self.ssp.tick(now_ms);
        let result = js_sys::Array::new();

        for instr_bytes in instructions {
            let packets = self.encrypt_and_fragment(&instr_bytes, now_ms)?;
            for pkt in packets {
                result.push(&pkt);
            }
        }

        Ok(result)
    }

    /// 上位レイヤーが読み取れるデータがあるか
    #[wasm_bindgen(js_name = "hasPendingRead")]
    pub fn has_pending_read(&self) -> bool {
        self.stream.has_pending_read()
    }

    /// バッファのデータをすべて読み出す
    ///
    /// `recv_udp_packet` の戻り値を使わずに、後から呼び出すこともできる。
    #[wasm_bindgen(js_name = "readPending")]
    pub fn read_pending(&mut self) -> Uint8Array {
        let data = self.stream.read_available();
        let arr = Uint8Array::new_with_length(data.len() as u32);
        arr.copy_from(&data);
        arr
    }

    /// セッション統計を JSON 文字列で返す
    ///
    /// # 戻り値
    /// JSON 文字列:
    /// ```json
    /// {
    ///   "srtt_ms": 45.2,
    ///   "rto_ms": 230,
    ///   "send_num": 42,
    ///   "recv_num": 38,
    ///   "pending_count": 2,
    ///   "total_sent_bytes": 102400,
    ///   "total_recv_bytes": 98304
    /// }
    /// ```
    #[wasm_bindgen(js_name = "getStats")]
    pub fn get_stats(&self) -> String {
        let stats = self.ssp.stats();
        format!(
            r#"{{"srtt_ms":{:.1},"rto_ms":{},"send_num":{},"recv_num":{},"pending_count":{},"total_sent_bytes":{},"total_recv_bytes":{}}}"#,
            stats.srtt_ms,
            stats.rto_ms,
            stats.send_num,
            stats.recv_num,
            stats.pending_count,
            self.stream.total_sent_bytes(),
            self.stream.total_received_bytes(),
        )
    }
}

impl MoshClient {
    /// Instruction バイト列を Fragment 分割 → 暗号化 → UDP ペイロード変換する
    fn encrypt_and_fragment(
        &mut self,
        instruction_bytes: &[u8],
        now_ms: u64,
    ) -> Result<Vec<Uint8Array>, JsError> {
        let fragments = self.fragmenter.make_fragments(instruction_bytes);
        let timestamp = Timestamp16::now_from_ms(now_ms).raw();
        let timestamp_reply = self.last_remote_timestamp;

        let mut result = Vec::new();
        for frag in fragments {
            let frag_bytes = frag.to_bytes();
            let packet = self
                .crypto
                .encrypt_packet(Direction::ToServer, timestamp, timestamp_reply, &frag_bytes)
                .map_err(|e| JsError::new(&format!("Encryption failed: {}", e)))?;

            let arr = Uint8Array::new_with_length(packet.len() as u32);
            arr.copy_from(&packet);
            result.push(arr);
        }

        Ok(result)
    }

    /// ストリームバッファのデータを SSP → Fragment → 暗号化 → UDP ペイロードに変換する
    fn flush_to_udp(&mut self, now_ms: u64) -> Result<js_sys::Array, JsError> {
        // ストリームバッファから送信待ちデータを取得
        let pending = self.stream.take_pending_diff();
        if !pending.is_empty() {
            self.ssp.push_payload(pending);
        }

        let instructions = self.ssp.tick(now_ms);
        let result = js_sys::Array::new();

        for instr_bytes in instructions {
            let packets = self.encrypt_and_fragment(&instr_bytes, now_ms)?;
            for pkt in packets {
                result.push(&pkt);
            }
        }

        Ok(result)
    }
}
