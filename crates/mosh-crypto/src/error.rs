//! 暗号エラー型

/// 暗号操作のエラー
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// 鍵の長さが不正（16バイト以外）
    InvalidKeyLength,
    /// Base64 デコードに失敗
    InvalidBase64,
    /// 暗号化に失敗
    EncryptionFailed,
    /// 復号に失敗（認証タグ検証失敗を含む）
    DecryptionFailed,
    /// リプレイアタック検出（seq が期待値より古い）
    ReplayAttack,
    /// パケットが短すぎる
    PacketTooShort,
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CryptoError::InvalidKeyLength => write!(f, "Invalid key length (expected 16 bytes)"),
            CryptoError::InvalidBase64 => write!(f, "Invalid Base64 encoding"),
            CryptoError::EncryptionFailed => write!(f, "Encryption failed"),
            CryptoError::DecryptionFailed => write!(f, "Decryption failed (authentication tag mismatch)"),
            CryptoError::ReplayAttack => write!(f, "Replay attack detected: packet sequence number too old"),
            CryptoError::PacketTooShort => write!(f, "Packet too short"),
        }
    }
}
