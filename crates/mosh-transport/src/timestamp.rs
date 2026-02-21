//! mosh タイムスタンプ（16ビット）
//!
//! mosh はミリ秒単位の時刻の下位 16 ビットをタイムスタンプとして使用する。
//! RTT 計算のために送信側のタイムスタンプを受信側がエコーバックする。

/// mosh パケットのタイムスタンプ（16ビット、ミリ秒の下位16ビット）
///
/// オーバーフローは mod 2^16 として扱う（最大表現できるのは約 65 秒）。
/// RTT が 65 秒を超えるようなケースは mosh では想定しない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timestamp16(pub u16);

impl Timestamp16 {
    /// ミリ秒の Unix タイムスタンプから Timestamp16 を生成する
    ///
    /// # 引数
    /// - `now_ms`: 現在時刻（ミリ秒、WASM 環境では JS の Date.now() から注入）
    pub fn now_from_ms(now_ms: u64) -> Self {
        Timestamp16((now_ms & 0xFFFF) as u16)
    }

    /// 2 つのタイムスタンプの差を計算する（newer - older）
    ///
    /// オーバーフローを考慮した差分計算。
    /// 結果は u16 の範囲内（0〜65535 ms）。
    pub fn diff(newer: Self, older: Self) -> u16 {
        newer.0.wrapping_sub(older.0)
    }

    /// 生の u16 値を返す
    pub fn raw(&self) -> u16 {
        self.0
    }

    /// 未初期化/不明なタイムスタンプを表す特殊値
    pub const INIT: Self = Timestamp16(u16::MAX);

    /// タイムスタンプが初期化済みか
    pub fn is_initialized(&self) -> bool {
        self.0 != u16::MAX
    }
}

impl From<u16> for Timestamp16 {
    fn from(val: u16) -> Self {
        Timestamp16(val)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_from_ms() {
        let ts = Timestamp16::now_from_ms(1000);
        assert_eq!(ts.raw(), 1000u16);
    }

    #[test]
    fn test_timestamp_wraps() {
        // 65536 ms → 0（u16 のラップアラウンド）
        let ts = Timestamp16::now_from_ms(65536);
        assert_eq!(ts.raw(), 0u16);

        let ts2 = Timestamp16::now_from_ms(65537);
        assert_eq!(ts2.raw(), 1u16);
    }

    #[test]
    fn test_timestamp_diff_normal() {
        let older = Timestamp16(100);
        let newer = Timestamp16(200);
        assert_eq!(Timestamp16::diff(newer, older), 100);
    }

    #[test]
    fn test_timestamp_diff_wraparound() {
        // タイムスタンプがオーバーフローした場合
        let older = Timestamp16(65000);
        let newer = Timestamp16(100); // 65536 - 65000 + 100 = 636 ms 経過
        assert_eq!(Timestamp16::diff(newer, older), 636);
    }

    #[test]
    fn test_timestamp_init() {
        assert!(!Timestamp16::INIT.is_initialized());
        assert!(Timestamp16(0).is_initialized());
        assert!(Timestamp16(100).is_initialized());
    }
}
