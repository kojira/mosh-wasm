//! # mosh-crypto
//!
//! AES-128-OCB3 暗号プリミティブ実装
//!
//! mosh プロトコルの暗号化に使われる AES-128-OCB3 を実装するクレート。
//! `no_std` + `alloc` 環境（WASM を含む）で動作する。
//!
//! ## mosh の暗号化仕様
//!
//! ```text
//! UDP ペイロード構造:
//!   [nonce_tail: 8bytes][ciphertext + auth_tag: variable]
//!
//! Nonce（12バイト）:
//!   bytes[0..4]  = 0x00000000 (ゼロパディング、送信時省略)
//!   bytes[4..12] = seq as u64, big-endian
//!
//! 平文（暗号化前）:
//!   [direction_seq: u64 BE][timestamp: u16 BE][timestamp_reply: u16 BE][payload...]
//!
//! direction_seq:
//!   seq の MSB (bit 63) = direction (TO_SERVER=0, TO_CLIENT=1)
//! ```

#![no_std]
extern crate alloc;

mod error;
mod nonce;
mod session;

pub use error::CryptoError;
pub use nonce::MoshNonce;
pub use session::CryptoSession;

/// mosh パケットの方向（TO_SERVER or TO_CLIENT）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// クライアント → サーバー (bit 63 = 0)
    ToServer = 0,
    /// サーバー → クライアント (bit 63 = 1)
    ToClient = 1,
}

impl Direction {
    /// seq の MSB から方向を判定する
    pub fn from_seq(direction_seq: u64) -> Self {
        if direction_seq >> 63 == 0 {
            Direction::ToServer
        } else {
            Direction::ToClient
        }
    }

    /// direction を seq の MSB に適用する
    pub fn apply_to_seq(&self, seq: u64) -> u64 {
        match self {
            Direction::ToServer => seq & !(1u64 << 63),
            Direction::ToClient => seq | (1u64 << 63),
        }
    }
}

/// Base64 文字列（22文字）を 16 バイトのキーにデコードする
///
/// mosh-server が出力するキーフォーマット: `4NeCCgvZFe2RnPgrcU1PQw`（22文字）
pub fn decode_base64_key(key_b64: &str) -> Result<[u8; 16], CryptoError> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(key_b64)
        .map_err(|_| CryptoError::InvalidBase64)?;

    if bytes.len() != 16 {
        return Err(CryptoError::InvalidKeyLength);
    }

    let mut key = [0u8; 16];
    key.copy_from_slice(&bytes);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_direction_to_server() {
        let dir = Direction::from_seq(0x0000000000000001u64);
        assert_eq!(dir, Direction::ToServer);
    }

    #[test]
    fn test_direction_to_client() {
        let dir = Direction::from_seq(0x8000000000000001u64);
        assert_eq!(dir, Direction::ToClient);
    }

    #[test]
    fn test_direction_apply_to_seq() {
        let seq: u64 = 42;
        let ts = Direction::ToServer.apply_to_seq(seq);
        assert_eq!(ts >> 63, 0);
        let tc = Direction::ToClient.apply_to_seq(seq);
        assert_eq!(tc >> 63, 1);
    }

    #[test]
    fn test_decode_base64_key_valid() {
        // 16バイト = 22文字（URL-safe base64 no-pad）
        let key_b64 = "AAAAAAAAAAAAAAAAAAAAAA"; // 16 zero bytes
        let key = decode_base64_key(key_b64).unwrap();
        assert_eq!(key, [0u8; 16]);
    }

    #[test]
    fn test_decode_base64_key_invalid_length() {
        let key_b64 = "AAAAAAAAAAAAAA"; // 短すぎる
        let result = decode_base64_key(key_b64);
        assert!(result.is_err());
    }
}
