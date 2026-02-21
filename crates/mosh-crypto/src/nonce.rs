//! mosh Nonce 実装
//!
//! ## mosh Nonce 構造（12バイト）
//! ```text
//! bytes[0..4]  = 0x00000000  (ゼロパディング)
//! bytes[4..12] = seq as u64, big-endian
//! ```
//!
//! UDP ペイロードには nonce の後半 8 バイト（bytes[4..12]）のみ送信する
//! （先頭 4 バイトは常にゼロなので省略）

/// mosh プロトコルの Nonce（12バイト）
///
/// シーケンス番号から構築され、AES-128-OCB3 の nonce として使用される。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MoshNonce([u8; 12]);

impl MoshNonce {
    /// シーケンス番号から Nonce を構築する
    ///
    /// # 引数
    /// - `seq`: シーケンス番号（direction ビット込みの u64）
    ///
    /// # 例
    /// ```
    /// use mosh_crypto::MoshNonce;
    /// let nonce = MoshNonce::new(42);
    /// assert_eq!(nonce.seq(), 42);
    /// ```
    pub fn new(seq: u64) -> Self {
        let mut bytes = [0u8; 12];
        // bytes[0..4] はゼロのまま（ゼロパディング）
        bytes[4..12].copy_from_slice(&seq.to_be_bytes());
        MoshNonce(bytes)
    }

    /// UDP ペイロードの先頭 8 バイト（nonce の後半部分）から Nonce を復元する
    ///
    /// mosh の UDP ペイロードは nonce の先頭 4 バイト（ゼロ）を省略して送信する。
    /// そのため、受信時は 8 バイトを受け取り、先頭 4 バイトをゼロ埋めして復元する。
    pub fn from_nonce_tail(tail: &[u8; 8]) -> Self {
        let mut bytes = [0u8; 12];
        // bytes[0..4] はゼロのまま
        bytes[4..12].copy_from_slice(tail);
        MoshNonce(bytes)
    }

    /// 受信パケットの先頭 8 バイトから Nonce を復元する（スライス版）
    pub fn from_udp_payload_prefix(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 8 {
            return None;
        }
        let mut tail = [0u8; 8];
        tail.copy_from_slice(&bytes[0..8]);
        Some(Self::from_nonce_tail(&tail))
    }

    /// シーケンス番号を取得する
    pub fn seq(&self) -> u64 {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&self.0[4..12]);
        u64::from_be_bytes(buf)
    }

    /// 12 バイトの nonce データへの参照を返す
    /// AES-OCB3 の nonce 引数として使用する
    pub fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }

    /// UDP ペイロードに埋め込む 8 バイト（nonce の後半）
    pub fn tail_bytes(&self) -> &[u8] {
        &self.0[4..12]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_from_seq() {
        let nonce = MoshNonce::new(1u64);
        assert_eq!(&nonce.0[0..4], &[0u8; 4]); // 先頭4バイトはゼロ
        assert_eq!(nonce.seq(), 1u64);
    }

    #[test]
    fn test_nonce_roundtrip() {
        let seq: u64 = 0xDEADBEEFCAFEBABE;
        let nonce = MoshNonce::new(seq);
        assert_eq!(nonce.seq(), seq);
    }

    #[test]
    fn test_nonce_from_udp_payload() {
        let seq: u64 = 42;
        let original = MoshNonce::new(seq);
        
        // UDP ペイロードには後半8バイトのみ
        let tail: [u8; 8] = original.tail_bytes().try_into().unwrap();
        let restored = MoshNonce::from_nonce_tail(&tail);
        
        assert_eq!(original, restored);
        assert_eq!(restored.seq(), seq);
    }

    #[test]
    fn test_nonce_zero_padding() {
        let nonce = MoshNonce::new(0xFFFFFFFFFFFFFFFF);
        // 先頭4バイトは常にゼロ
        assert_eq!(&nonce.0[0..4], &[0u8; 4]);
        // 後半8バイトはすべて 0xFF
        assert_eq!(&nonce.0[4..12], &[0xFF; 8]);
    }
}
