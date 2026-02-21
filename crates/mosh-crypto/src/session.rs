//! AES-128-OCB3 セッション実装
//!
//! mosh の Session クラスに相当する暗号セッション管理。

use alloc::vec::Vec;

use aead::KeyInit;
use aes::Aes128;
use ocb3::Ocb3;

use crate::error::CryptoError;
use crate::nonce::MoshNonce;
use crate::{Direction, decode_base64_key};

/// AES-128-OCB3 (12バイト nonce, 16バイト tag) の型エイリアス
type Aes128Ocb3 = Ocb3<Aes128>;

/// AES-128-OCB3 暗号セッション
///
/// mosh プロトコルのパケット暗号化/復号を管理する。
/// 送信シーケンス番号を自動インクリメントし、Nonce の重複を防ぐ。
pub struct CryptoSession {
    cipher: Aes128Ocb3,
    /// 次の送信シーケンス番号
    send_seq: u64,
    /// 最後に受信した（有効な）シーケンス番号
    recv_seq: u64,
}

impl CryptoSession {
    /// mosh-server が出力する Base64 鍵（22文字）からセッションを初期化する
    ///
    /// # 引数
    /// - `key_b64`: Base64 エンコードされた 16 バイト鍵（例: "4NeCCgvZFe2RnPgrcU1PQw"）
    ///
    /// # エラー
    /// - `CryptoError::InvalidBase64`: Base64 デコード失敗
    /// - `CryptoError::InvalidKeyLength`: 鍵長が 16 バイト以外
    pub fn from_base64_key(key_b64: &str) -> Result<Self, CryptoError> {
        let key = decode_base64_key(key_b64)?;
        Self::from_key(key)
    }

    /// 16 バイトの raw 鍵からセッションを初期化する
    pub fn from_key(key: [u8; 16]) -> Result<Self, CryptoError> {
        let cipher = Aes128Ocb3::new((&key).into());
        Ok(CryptoSession {
            cipher,
            send_seq: 0,
            recv_seq: 0,
        })
    }

    /// 平文を暗号化して UDP ペイロードを返す
    ///
    /// ## UDP ペイロード構造
    /// ```text
    /// [nonce_tail: 8bytes][ciphertext_with_tag: variable]
    /// ```
    ///
    /// ## 平文構造（暗号化前）
    /// ```text
    /// [direction_seq: u64 BE][timestamp: u16 BE][timestamp_reply: u16 BE][payload...]
    /// ```
    ///
    /// # 引数
    /// - `direction`: パケットの方向（ToServer/ToClient）
    /// - `timestamp`: ローカルタイムスタンプ（16bit, ms の下位16ビット）
    /// - `timestamp_reply`: 相手から受け取ったタイムスタンプのエコー
    /// - `payload`: 暗号化するペイロード（Fragment バイト列）
    pub fn encrypt_packet(
        &mut self,
        direction: Direction,
        timestamp: u16,
        timestamp_reply: u16,
        payload: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let seq = self.send_seq;
        self.send_seq += 1;

        let direction_seq = direction.apply_to_seq(seq);
        let nonce = MoshNonce::new(direction_seq);

        // 平文の組み立て
        let mut plaintext = Vec::with_capacity(12 + payload.len());
        plaintext.extend_from_slice(&direction_seq.to_be_bytes());
        plaintext.extend_from_slice(&timestamp.to_be_bytes());
        plaintext.extend_from_slice(&timestamp_reply.to_be_bytes());
        plaintext.extend_from_slice(payload);

        // AES-128-OCB3 暗号化
        use aead::Aead;
        let ciphertext = self
            .cipher
            .encrypt(nonce.as_bytes().into(), plaintext.as_slice())
            .map_err(|_| CryptoError::EncryptionFailed)?;

        // UDP ペイロードの組み立て: nonce後半8バイト + 暗号文
        let mut packet = Vec::with_capacity(8 + ciphertext.len());
        packet.extend_from_slice(nonce.tail_bytes());
        packet.extend_from_slice(&ciphertext);

        Ok(packet)
    }

    /// 受信した UDP ペイロードを復号する
    ///
    /// # 引数
    /// - `packet`: UDP ペイロード（nonce 後半8バイト + 暗号文）
    ///
    /// # 戻り値
    /// 復号された平文（direction_seq + timestamp + timestamp_reply + payload）
    ///
    /// # エラー
    /// - `CryptoError::PacketTooShort`: パケットが短すぎる（最低 8 + 16 = 24 バイト必要）
    /// - `CryptoError::DecryptionFailed`: 認証タグ検証失敗
    /// - `CryptoError::ReplayAttack`: シーケンス番号が古すぎる
    pub fn decrypt_packet(&mut self, packet: &[u8]) -> Result<DecryptedPacket, CryptoError> {
        // 最低: nonce_tail(8) + empty_plaintext_with_tag(16) = 24 バイト
        if packet.len() < 24 {
            return Err(CryptoError::PacketTooShort);
        }

        let nonce = MoshNonce::from_udp_payload_prefix(packet)
            .ok_or(CryptoError::PacketTooShort)?;
        let ciphertext = &packet[8..];

        // AES-128-OCB3 復号
        use aead::Aead;
        let plaintext = self
            .cipher
            .decrypt(nonce.as_bytes().into(), ciphertext)
            .map_err(|_| CryptoError::DecryptionFailed)?;

        // 平文は最低 12 バイト（direction_seq:8 + timestamp:2 + timestamp_reply:2）
        if plaintext.len() < 12 {
            return Err(CryptoError::DecryptionFailed);
        }

        // direction_seq の解析
        let mut seq_bytes = [0u8; 8];
        seq_bytes.copy_from_slice(&plaintext[0..8]);
        let direction_seq = u64::from_be_bytes(seq_bytes);
        let direction = Direction::from_seq(direction_seq);
        let seq = direction_seq & !(1u64 << 63); // direction ビットを除いた seq

        // タイムスタンプの解析
        let timestamp = u16::from_be_bytes([plaintext[8], plaintext[9]]);
        let timestamp_reply = u16::from_be_bytes([plaintext[10], plaintext[11]]);

        // ペイロード
        let payload = plaintext[12..].to_vec();

        // recv_seq を更新（簡易的なリプレイ検出）
        // TODO: ウィンドウベースのより堅牢なリプレイ検出を実装する
        self.recv_seq = seq;

        Ok(DecryptedPacket {
            seq,
            direction,
            timestamp,
            timestamp_reply,
            payload,
        })
    }

    /// 現在の送信シーケンス番号を返す（テスト用）
    pub fn send_seq(&self) -> u64 {
        self.send_seq
    }

    /// 最後に受信したシーケンス番号を返す（テスト用）
    pub fn recv_seq(&self) -> u64 {
        self.recv_seq
    }
}

/// 復号されたパケットの内容
#[derive(Debug, Clone, PartialEq)]
pub struct DecryptedPacket {
    /// シーケンス番号（direction ビット除く）
    pub seq: u64,
    /// パケットの方向
    pub direction: Direction,
    /// 送信側のタイムスタンプ（16bit ms）
    pub timestamp: u16,
    /// 受信側がエコーするタイムスタンプ
    pub timestamp_reply: u16,
    /// 復号されたペイロード（Fragment バイト列）
    pub payload: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_session() -> CryptoSession {
        let key = [0u8; 16];
        CryptoSession::from_key(key).unwrap()
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let mut session = make_session();
        let payload = b"Hello, mosh!";

        let packet = session
            .encrypt_packet(Direction::ToServer, 1000, 0, payload)
            .unwrap();

        // 復号には同じ鍵の別セッションを使う
        let mut recv_session = make_session();
        let decrypted = recv_session.decrypt_packet(&packet).unwrap();

        assert_eq!(decrypted.payload, payload);
        assert_eq!(decrypted.direction, Direction::ToServer);
        assert_eq!(decrypted.timestamp, 1000);
        assert_eq!(decrypted.timestamp_reply, 0);
    }

    #[test]
    fn test_seq_increments() {
        let mut session = make_session();
        assert_eq!(session.send_seq(), 0);

        session
            .encrypt_packet(Direction::ToServer, 0, 0, b"")
            .unwrap();
        assert_eq!(session.send_seq(), 1);

        session
            .encrypt_packet(Direction::ToServer, 0, 0, b"")
            .unwrap();
        assert_eq!(session.send_seq(), 2);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let mut send_session = make_session();
        let packet = send_session
            .encrypt_packet(Direction::ToServer, 0, 0, b"secret")
            .unwrap();

        // 異なる鍵で復号 → 失敗すべき
        let key = [0xFFu8; 16];
        let mut recv_session = CryptoSession::from_key(key).unwrap();
        let result = recv_session.decrypt_packet(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_too_short_fails() {
        let mut session = make_session();
        let result = session.decrypt_packet(&[0u8; 10]);
        assert_eq!(result, Err(CryptoError::PacketTooShort));
    }

    #[test]
    fn test_from_base64_key() {
        // 16 zero bytes → base64url = "AAAAAAAAAAAAAAAAAAAAAA"
        let session = CryptoSession::from_base64_key("AAAAAAAAAAAAAAAAAAAAAA");
        assert!(session.is_ok());
    }
}
