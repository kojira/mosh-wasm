//! UDP パケット構造
//!
//! mosh の UDP ペイロード（暗号化済みの Fragment）を表す。
//!
//! ## Wire Format
//! ```text
//! [nonce_tail: 8bytes][ciphertext_with_tag: variable]
//! ↑ nonce の先頭 4 バイトは常にゼロなので省略して送信する
//! ```

use alloc::vec::Vec;
use crate::error::TransportError;

/// mosh UDP パケット（暗号化済みの Fragment を含む）
///
/// 送信前・受信後のパケット構造を表す。
/// 実際の暗号化/復号は `mosh-crypto` クレートが担当する。
#[derive(Debug, Clone, PartialEq)]
pub struct UdpPacket {
    /// Nonce の後半 8 バイト（送信時に先頭 4 バイトのゼロを省略）
    pub nonce_tail: [u8; 8],
    /// AES-128-OCB3 で暗号化された Fragment バイト列 + 16 バイトの認証タグ
    pub ciphertext: Vec<u8>,
}

impl UdpPacket {
    /// nonce の後半 8 バイトと暗号化済みデータから UDP パケットを構築する
    pub fn new(nonce_tail: [u8; 8], ciphertext: Vec<u8>) -> Self {
        UdpPacket { nonce_tail, ciphertext }
    }

    /// 受信した UDP ペイロードをパースする
    ///
    /// # 形式
    /// ```text
    /// [nonce_tail: 8bytes][ciphertext: variable]
    /// ```
    ///
    /// # エラー
    /// - `TransportError::TooShort`: 8 バイト未満
    pub fn from_udp_payload(bytes: &[u8]) -> Result<Self, TransportError> {
        if bytes.len() < 8 {
            return Err(TransportError::TooShort);
        }

        let mut nonce_tail = [0u8; 8];
        nonce_tail.copy_from_slice(&bytes[0..8]);
        let ciphertext = bytes[8..].to_vec();

        Ok(UdpPacket { nonce_tail, ciphertext })
    }

    /// UDP に送信する生バイト列を返す
    ///
    /// ```text
    /// [nonce_tail: 8bytes][ciphertext: variable]
    /// ```
    pub fn to_udp_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(8 + self.ciphertext.len());
        payload.extend_from_slice(&self.nonce_tail);
        payload.extend_from_slice(&self.ciphertext);
        payload
    }

    /// パケットの全バイト数を返す
    pub fn total_len(&self) -> usize {
        8 + self.ciphertext.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_packet_roundtrip() {
        let nonce_tail = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let ciphertext = alloc::vec![0xABu8; 32];
        let packet = UdpPacket::new(nonce_tail, ciphertext.clone());

        let payload = packet.to_udp_payload();
        let restored = UdpPacket::from_udp_payload(&payload).unwrap();

        assert_eq!(restored.nonce_tail, nonce_tail);
        assert_eq!(restored.ciphertext, ciphertext);
    }

    #[test]
    fn test_udp_packet_too_short() {
        let result = UdpPacket::from_udp_payload(&[0u8; 7]);
        assert_eq!(result, Err(TransportError::TooShort));
    }

    #[test]
    fn test_udp_packet_total_len() {
        let nonce_tail = [0u8; 8];
        let ciphertext = alloc::vec![0u8; 50];
        let packet = UdpPacket::new(nonce_tail, ciphertext);
        assert_eq!(packet.total_len(), 58);
    }
}
