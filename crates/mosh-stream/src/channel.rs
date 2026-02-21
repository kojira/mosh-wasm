//! バイトストリームチャンネル実装

use alloc::collections::VecDeque;
use alloc::vec::Vec;

/// バイトストリームチャンネル
///
/// VS Code RPC プロトコルのバイトストリームを mosh SSP の diff フィールドで転送するための
/// バッファ管理クラス。
///
/// ## 責任
/// - 上位レイヤー（VS Code RPC）からの送信データをバッファリング
/// - SSP から受信した diff データをバッファリングして上位レイヤーに提供
/// - mosh の端末エミュレーション機能は一切使用しない
///
/// ## 注意
/// このクラス自体はステートレスなバッファ管理のみ。
/// 実際の SSP 送受信のタイミング管理は `mosh-ssp` クレートと `mosh-wasm` が担当する。
pub struct StreamChannel {
    /// 受信バッファ（上位レイヤーへ渡すデータ）
    /// SSP の diff を受け取り、上位レイヤーが read_available() で取得する
    recv_buffer: VecDeque<u8>,
    /// 送信バッファ（まだ SSP に渡していないデータ）
    /// 上位レイヤーが write() で積み、tick 時に take_pending_diff() で取得される
    send_buffer: Vec<u8>,
    /// 受信した総バイト数（統計用）
    total_received: u64,
    /// 送信した総バイト数（統計用）
    total_sent: u64,
}

impl StreamChannel {
    /// 新しい StreamChannel を生成する
    pub fn new() -> Self {
        StreamChannel {
            recv_buffer: VecDeque::new(),
            send_buffer: Vec::new(),
            total_received: 0,
            total_sent: 0,
        }
    }

    /// 上位レイヤー（VS Code RPC）から送信データを積む
    ///
    /// このデータは次の `take_pending_diff()` 呼び出し時に SSP に渡される。
    ///
    /// # 引数
    /// - `data`: 送信するバイト列
    pub fn write(&mut self, data: &[u8]) {
        self.send_buffer.extend_from_slice(data);
    }

    /// SSP に渡す送信データを取得し、バッファをクリアする
    ///
    /// SSP の tick 時に呼び出し、返値を Instruction の diff フィールドに設定する。
    /// データがない場合は空の Vec を返す。
    ///
    /// # 戻り値
    /// 送信待ちのバイト列（空の場合は `Vec::new()`）
    pub fn take_pending_diff(&mut self) -> Vec<u8> {
        let diff = core::mem::take(&mut self.send_buffer);
        self.total_sent += diff.len() as u64;
        diff
    }

    /// SSP から受信した diff データをバッファに適用する
    ///
    /// SSP で受信した Instruction の diff フィールドを渡す。
    /// その後 `read_available()` で上位レイヤーが読み取れる。
    ///
    /// # 引数
    /// - `diff`: 受信した Instruction の diff バイト列
    pub fn apply_diff(&mut self, diff: &[u8]) {
        self.recv_buffer.extend(diff.iter().copied());
        self.total_received += diff.len() as u64;
    }

    /// 上位レイヤーが読み取れるデータをすべて返す
    ///
    /// 読み取ったデータは内部バッファから削除される。
    /// データがない場合は空の Vec を返す。
    pub fn read_available(&mut self) -> Vec<u8> {
        self.recv_buffer.drain(..).collect()
    }

    /// バッファに未読データがあるか
    pub fn has_pending_read(&self) -> bool {
        !self.recv_buffer.is_empty()
    }

    /// 送信待ちデータがあるか
    pub fn has_pending_write(&self) -> bool {
        !self.send_buffer.is_empty()
    }

    /// 受信バッファのバイト数
    pub fn recv_buffer_len(&self) -> usize {
        self.recv_buffer.len()
    }

    /// 送信バッファのバイト数
    pub fn send_buffer_len(&self) -> usize {
        self.send_buffer.len()
    }

    /// 受信した総バイト数（統計用）
    pub fn total_received_bytes(&self) -> u64 {
        self.total_received
    }

    /// 送信した総バイト数（統計用）
    pub fn total_sent_bytes(&self) -> u64 {
        self.total_sent
    }
}

impl Default for StreamChannel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_and_take_pending() {
        let mut ch = StreamChannel::new();
        ch.write(b"hello");
        ch.write(b" world");

        let diff = ch.take_pending_diff();
        assert_eq!(diff, b"hello world");

        // 取得後はバッファがクリアされる
        assert!(!ch.has_pending_write());
        let diff2 = ch.take_pending_diff();
        assert!(diff2.is_empty());
    }

    #[test]
    fn test_apply_diff_and_read() {
        let mut ch = StreamChannel::new();
        ch.apply_diff(b"from remote");

        assert!(ch.has_pending_read());
        let data = ch.read_available();
        assert_eq!(data, b"from remote");

        // 読み取り後はバッファがクリアされる
        assert!(!ch.has_pending_read());
    }

    #[test]
    fn test_multiple_diffs_accumulate() {
        let mut ch = StreamChannel::new();
        ch.apply_diff(b"part1");
        ch.apply_diff(b"part2");
        ch.apply_diff(b"part3");

        let data = ch.read_available();
        assert_eq!(data, b"part1part2part3");
    }

    #[test]
    fn test_empty_read_returns_empty() {
        let mut ch = StreamChannel::new();
        let data = ch.read_available();
        assert!(data.is_empty());
    }

    #[test]
    fn test_stats() {
        let mut ch = StreamChannel::new();
        ch.write(b"send data");
        let _ = ch.take_pending_diff();

        ch.apply_diff(b"recv data");
        let _ = ch.read_available();

        assert_eq!(ch.total_sent_bytes(), 9);
        assert_eq!(ch.total_received_bytes(), 9);
    }

    #[test]
    fn test_buffer_independence() {
        // 送信バッファと受信バッファが独立していることを確認
        let mut ch = StreamChannel::new();
        ch.write(b"outgoing");
        ch.apply_diff(b"incoming");

        assert!(ch.has_pending_write());
        assert!(ch.has_pending_read());

        let recv = ch.read_available();
        assert_eq!(recv, b"incoming");
        assert!(ch.has_pending_write()); // 送信バッファは影響を受けない

        let send = ch.take_pending_diff();
        assert_eq!(send, b"outgoing");
    }
}
