//! # mosh-proto
//!
//! mosh SSP (State Synchronization Protocol) の Protobuf 定義と
//! エンコード/デコードユーティリティ。
//!
//! ## Instruction の役割
//!
//! SSP の Instruction は、以下の情報を一つのメッセージに格納する：
//! - `old_num` / `new_num`: 送信側の状態番号（差分の起点と終点）
//! - `ack_num`: 受信確認済みの状態番号
//! - `throwaway_num`: これより古い状態は破棄可能
//! - `diff`: 状態差分データ（バイトストリームモードでは raw bytes）
//!
//! ## プロトコルバージョン
//!
//! mosh のプロトコルバージョンは 2 (MOSH_PROTOCOL_VERSION)。

#![no_std]
extern crate alloc;

use alloc::vec::Vec;

pub mod error;

pub use error::ProtoError;

/// mosh SSP プロトコルバージョン
pub const MOSH_PROTOCOL_VERSION: u32 = 2;

// prost-build で自動生成されたコードをインクルード
pub mod transport_buffers {
    include!(concat!(env!("OUT_DIR"), "/transport_buffers.rs"));
}

pub use transport_buffers::Instruction;

/// Instruction の構築・エンコード・デコードユーティリティ
impl Instruction {
    /// 送信用 Instruction を組み立てる
    ///
    /// # 引数
    /// - `old_num`: 前の状態番号（差分の起点。0 = 初回）
    /// - `new_num`: 新しい状態番号
    /// - `ack_num`: ACK する受信済み状態番号
    /// - `throwaway_num`: これより古い状態は破棄可能
    /// - `diff`: ペイロードデータ（バイトストリームでは送信したい raw bytes）
    pub fn new_send(
        old_num: u64,
        new_num: u64,
        ack_num: u64,
        throwaway_num: u64,
        diff: Vec<u8>,
    ) -> Self {
        Instruction {
            protocol_version: Some(MOSH_PROTOCOL_VERSION),
            old_num: Some(old_num),
            new_num: Some(new_num),
            ack_num: Some(ack_num),
            throwaway_num: Some(throwaway_num),
            diff: if diff.is_empty() { None } else { Some(diff) },
            chaff: None,
        }
    }

    /// ACK のみの Instruction（ペイロードなし・ハートビート用）
    pub fn new_ack(ack_num: u64, throwaway_num: u64) -> Self {
        Instruction {
            protocol_version: Some(MOSH_PROTOCOL_VERSION),
            old_num: Some(0),
            new_num: Some(0),
            ack_num: Some(ack_num),
            throwaway_num: Some(throwaway_num),
            diff: None,
            chaff: None,
        }
    }

    /// バイト列から Instruction をデコードする
    ///
    /// # エラー
    /// - `ProtoError::DecodeFailed`: protobuf デコード失敗
    /// - `ProtoError::InvalidProtocolVersion`: バージョン不一致
    pub fn decode_from_bytes(bytes: &[u8]) -> Result<Self, ProtoError> {
        use prost::Message;
        let instr = Instruction::decode(bytes)
            .map_err(ProtoError::DecodeFailed)?;

        // プロトコルバージョンチェック（設定されている場合のみ）
        if let Some(ver) = instr.protocol_version {
            if ver != MOSH_PROTOCOL_VERSION {
                return Err(ProtoError::InvalidProtocolVersion(ver));
            }
        }

        Ok(instr)
    }

    /// Instruction をバイト列にエンコードする
    pub fn encode_to_bytes(&self) -> Vec<u8> {
        use prost::Message;
        let mut buf = Vec::new();
        self.encode(&mut buf).expect("Instruction encode should not fail");
        buf
    }

    /// diff フィールドの参照を返す（None の場合は空スライス）
    pub fn diff_bytes(&self) -> &[u8] {
        self.diff.as_deref().unwrap_or(&[])
    }

    /// old_num の値（デフォルト 0）
    pub fn old_num_or_zero(&self) -> u64 {
        self.old_num.unwrap_or(0)
    }

    /// new_num の値（デフォルト 0）
    pub fn new_num_or_zero(&self) -> u64 {
        self.new_num.unwrap_or(0)
    }

    /// ack_num の値（デフォルト 0）
    pub fn ack_num_or_zero(&self) -> u64 {
        self.ack_num.unwrap_or(0)
    }

    /// throwaway_num の値（デフォルト 0）
    pub fn throwaway_num_or_zero(&self) -> u64 {
        self.throwaway_num.unwrap_or(0)
    }

    /// ペイロードデータを持つか（diff フィールドが Some かつ非空）
    pub fn has_diff(&self) -> bool {
        self.diff.as_ref().is_some_and(|d| !d.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_send_encode_decode_roundtrip() {
        let diff = alloc::vec![1u8, 2, 3, 4, 5];
        let instr = Instruction::new_send(0, 1, 0, 0, diff.clone());

        let encoded = instr.encode_to_bytes();
        let decoded = Instruction::decode_from_bytes(&encoded).unwrap();

        assert_eq!(decoded.old_num_or_zero(), 0);
        assert_eq!(decoded.new_num_or_zero(), 1);
        assert_eq!(decoded.ack_num_or_zero(), 0);
        assert_eq!(decoded.throwaway_num_or_zero(), 0);
        assert_eq!(decoded.diff_bytes(), diff.as_slice());
        assert_eq!(
            decoded.protocol_version,
            Some(MOSH_PROTOCOL_VERSION)
        );
    }

    #[test]
    fn test_new_ack_no_diff() {
        let instr = Instruction::new_ack(5, 4);
        assert!(!instr.has_diff());
        assert_eq!(instr.ack_num_or_zero(), 5);
        assert_eq!(instr.throwaway_num_or_zero(), 4);

        // エンコード/デコードで情報が保たれることを確認
        let bytes = instr.encode_to_bytes();
        let decoded = Instruction::decode_from_bytes(&bytes).unwrap();
        assert_eq!(decoded.ack_num_or_zero(), 5);
        assert!(!decoded.has_diff());
    }

    #[test]
    fn test_empty_diff_roundtrip() {
        // diff が空の場合、has_diff() は false
        let instr = Instruction::new_send(0, 1, 0, 0, alloc::vec![]);
        assert!(!instr.has_diff());
    }
}
