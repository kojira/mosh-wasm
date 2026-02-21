//! SSP セッション状態機械
//!
//! mosh の Transport クラス相当の実装。
//! 送受信状態の管理、ACK 処理、ハートビート、RTT 推定、再送を担当する。

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use mosh_proto::Instruction;

use crate::{HEARTBEAT_INTERVAL_MS, RTO_INITIAL_MS, RTO_MAX_MS, RTO_MIN_MS};

/// ACK 前の送信済み Instruction
#[derive(Debug, Clone)]
struct PendingInstruction {
    /// Instruction の new_num（識別用）
    num: u64,
    /// エンコード済み Instruction バイト列
    payload: Vec<u8>,
    /// 送信時刻（ミリ秒）
    sent_at_ms: u64,
    /// 再送回数
    retransmit_count: u32,
}

/// SSP 送信側の状態
struct SendState {
    /// 次に送信する Instruction の番号
    next_send_num: u64,
    /// 最後に ACK された番号
    last_acked: u64,
    /// ACK 待ちの Instruction キュー
    pending: VecDeque<PendingInstruction>,
    /// 送信待ちペイロード（push_payload で積まれたデータ）
    outgoing_diff: Vec<u8>,
    /// 最後に送信した時刻（ミリ秒）
    last_send_ms: u64,
}

/// SSP 受信側の状態
struct RecvState {
    /// 最後に受信した Instruction の番号
    last_recv_num: u64,
    /// throwaway_num（これより古いものは破棄可能）
    throwaway_num: u64,
    /// 最後に受信した時刻（ミリ秒）
    last_recv_ms: u64,
    /// エコーバック用のタイムスタンプ（受信パケットの timestamp をエコー）
    /// 将来の RTT 計算精度向上のために保持
    _last_timestamp: u16,
    /// タイムスタンプを受信した時刻（将来の RTT 計算用）
    _last_timestamp_recv_ms: u64,
}

/// SSP セッション
///
/// 送受信状態を管理し、送信すべき Instruction バイト列を生成する。
/// 実際の暗号化・Fragment 分割は呼び出し側（`mosh-wasm` クレート）が担当する。
pub struct SspSession {
    /// 送信側の状態
    send: SendState,
    /// 受信側の状態
    recv: RecvState,
    /// Smoothed RTT（ミリ秒）
    srtt_ms: f64,
    /// RTTVAR（ミリ秒）
    rttvar_ms: f64,
    /// RTO（Retransmission Timeout）
    rto_ms: u64,
}

impl SspSession {
    /// 新しい SSP セッションを生成する
    pub fn new() -> Self {
        SspSession {
            send: SendState {
                next_send_num: 1, // 1 始まり
                last_acked: 0,
                pending: VecDeque::new(),
                outgoing_diff: Vec::new(),
                last_send_ms: 0,
            },
            recv: RecvState {
                last_recv_num: 0,
                throwaway_num: 0,
                last_recv_ms: 0,
                _last_timestamp: u16::MAX,
                _last_timestamp_recv_ms: 0,
            },
            srtt_ms: 0.0,
            rttvar_ms: 0.0,
            rto_ms: RTO_INITIAL_MS,
        }
    }

    /// 上位レイヤーからの送信データを積む
    ///
    /// # 引数
    /// - `diff`: 送信するバイト列（バイトストリームモードでは VS Code RPC データ）
    pub fn push_payload(&mut self, diff: Vec<u8>) {
        self.send.outgoing_diff.extend_from_slice(&diff);
    }

    /// タイマー tick を処理し、送信すべき Instruction バイト列のリストを返す
    ///
    /// Node.js の setInterval(50ms) から定期的に呼び出す。
    /// - ペイロードがあれば送信 Instruction を生成
    /// - 再送が必要な Instruction があれば再送
    /// - ハートビートが必要なら ACK のみの Instruction を生成
    ///
    /// # 引数
    /// - `now_ms`: 現在時刻（JS Date.now()）
    ///
    /// # 戻り値
    /// エンコード済み Instruction バイト列のリスト。各要素を Fragment 分割→暗号化→UDP 送信する。
    pub fn tick(&mut self, now_ms: u64) -> Vec<Vec<u8>> {
        let mut to_send = Vec::new();

        // 送信待ちペイロードがあれば送信 Instruction を生成
        if !self.send.outgoing_diff.is_empty() {
            let diff = core::mem::take(&mut self.send.outgoing_diff);
            let instr = self.make_send_instruction(diff, now_ms);
            let bytes = instr.encode_to_bytes();
            self.enqueue_pending(instr.new_num_or_zero(), bytes.clone(), now_ms);
            to_send.push(bytes);
        }

        // 再送チェック: RTO 超過した pending Instruction を再送
        let rto = self.rto_ms;
        for pending in &mut self.send.pending {
            if now_ms.saturating_sub(pending.sent_at_ms) >= rto {
                pending.sent_at_ms = now_ms;
                pending.retransmit_count += 1;
                to_send.push(pending.payload.clone());
            }
        }

        // ハートビートが必要なら送信
        if to_send.is_empty() && self.needs_heartbeat(now_ms) {
            let ack_instr = self.make_ack(now_ms);
            to_send.push(ack_instr.encode_to_bytes());
            self.send.last_send_ms = now_ms;
        }

        to_send
    }

    /// 受信した Instruction を処理し、上位レイヤーに渡すペイロードを返す
    ///
    /// # 引数
    /// - `instr`: 受信・復号・再組み立て済みの Instruction
    /// - `now_ms`: 受信時刻（RTT 計算用）
    ///
    /// # 戻り値
    /// - `Some(bytes)`: 有効なペイロード（上位レイヤーに渡す）
    /// - `None`: 重複・古すぎるパケット（破棄）
    pub fn recv_instruction(&mut self, instr: &Instruction, now_ms: u64) -> Option<Vec<u8>> {
        let new_num = instr.new_num_or_zero();
        let ack_num = instr.ack_num_or_zero();
        let throwaway_num = instr.throwaway_num_or_zero();

        // ACK 処理: 相手が ACK した番号までの pending を解放
        self.process_ack(ack_num, now_ms);

        // throwaway_num 更新
        if throwaway_num > self.recv.throwaway_num {
            self.recv.throwaway_num = throwaway_num;
        }

        // 受信時刻を更新
        self.recv.last_recv_ms = now_ms;

        // 重複・古いパケットのチェック
        // new_num == 0 はハートビート（ACK のみ）なのでペイロードなし
        if new_num == 0 {
            return None;
        }

        // 既に受信済みの Instruction は無視（重複）
        if new_num <= self.recv.last_recv_num {
            return None;
        }

        // 受信番号を更新
        self.recv.last_recv_num = new_num;

        // ペイロードを返す
        if instr.has_diff() {
            Some(instr.diff.clone().unwrap_or_default())
        } else {
            None
        }
    }

    /// ACK のみの Instruction を生成する（ハートビート用）
    pub fn make_ack(&self, _now_ms: u64) -> Instruction {
        Instruction::new_ack(
            self.recv.last_recv_num,
            self.recv.throwaway_num,
        )
    }

    /// ハートビートが必要か（前回送信から HEARTBEAT_INTERVAL_MS 経過）
    pub fn needs_heartbeat(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.send.last_send_ms) >= HEARTBEAT_INTERVAL_MS
    }

    /// セッション統計を返す
    pub fn stats(&self) -> SspStats {
        SspStats {
            srtt_ms: self.srtt_ms,
            rto_ms: self.rto_ms,
            send_num: self.send.next_send_num,
            recv_num: self.recv.last_recv_num,
            pending_count: self.send.pending.len(),
        }
    }

    // ===== Private メソッド =====

    /// 送信用 Instruction を組み立てる
    fn make_send_instruction(&mut self, diff: Vec<u8>, _now_ms: u64) -> Instruction {
        let old_num = self.send.last_acked;
        let new_num = self.send.next_send_num;
        self.send.next_send_num += 1;

        let throwaway_num = self.recv.throwaway_num;
        let ack_num = self.recv.last_recv_num;

        Instruction::new_send(old_num, new_num, ack_num, throwaway_num, diff)
    }

    /// Pending キューに Instruction を追加する
    fn enqueue_pending(&mut self, num: u64, payload: Vec<u8>, now_ms: u64) {
        self.send.pending.push_back(PendingInstruction {
            num,
            payload,
            sent_at_ms: now_ms,
            retransmit_count: 0,
        });
        self.send.last_send_ms = now_ms;
    }

    /// ACK を処理する（pending キューから ACK 済みを削除）
    fn process_ack(&mut self, ack_num: u64, now_ms: u64) {
        if ack_num <= self.send.last_acked {
            return; // 古い ACK
        }

        // ACK されたものを pending から削除
        while let Some(front) = self.send.pending.front() {
            if front.num <= ack_num {
                let pending = self.send.pending.pop_front().unwrap();

                // RTT サンプルを更新（初回送信のものだけ使う、再送は使わない）
                if pending.retransmit_count == 0 {
                    let rtt_sample = now_ms.saturating_sub(pending.sent_at_ms);
                    self.update_rtt(rtt_sample);
                }
            } else {
                break;
            }
        }

        self.send.last_acked = ack_num;
    }

    /// Jacobson/Karels アルゴリズムで RTT を更新する
    ///
    /// RFC 6298 に基づく実装。
    fn update_rtt(&mut self, rtt_sample_ms: u64) {
        let rtt = rtt_sample_ms as f64;

        if self.srtt_ms == 0.0 {
            // 初回サンプル
            self.srtt_ms = rtt;
            self.rttvar_ms = rtt / 2.0;
        } else {
            // RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - R'|
            // SRTT   = (1 - alpha) * SRTT + alpha * R'
            // alpha = 1/8, beta = 1/4 (RFC 6298)
            let alpha = 0.125_f64;
            let beta = 0.25_f64;

            self.rttvar_ms = (1.0 - beta) * self.rttvar_ms + beta * (self.srtt_ms - rtt).abs();
            self.srtt_ms = (1.0 - alpha) * self.srtt_ms + alpha * rtt;
        }

        // RTO = SRTT + max(G, K*RTTVAR) where G=50ms (clock granularity), K=4
        let k = 4.0_f64;
        let g = 50.0_f64; // クロック粒度
        let rto = self.srtt_ms + (k * self.rttvar_ms).max(g);

        self.rto_ms = (rto as u64).clamp(RTO_MIN_MS, RTO_MAX_MS);
    }
}

impl Default for SspSession {
    fn default() -> Self {
        Self::new()
    }
}

/// SSP セッション統計情報
#[derive(Debug, Clone)]
pub struct SspStats {
    /// Smoothed RTT（ミリ秒）
    pub srtt_ms: f64,
    /// RTO（ミリ秒）
    pub rto_ms: u64,
    /// 次の送信番号
    pub send_num: u64,
    /// 最後に受信した番号
    pub recv_num: u64,
    /// ACK 待ちの Instruction 数
    pub pending_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssp_session_new() {
        let session = SspSession::new();
        let stats = session.stats();
        assert_eq!(stats.send_num, 1);
        assert_eq!(stats.recv_num, 0);
        assert_eq!(stats.pending_count, 0);
    }

    #[test]
    fn test_push_payload_and_tick() {
        let mut session = SspSession::new();
        session.push_payload(alloc::vec![1, 2, 3, 4]);

        let packets = session.tick(1000);
        assert_eq!(packets.len(), 1);

        // Instruction がデコードできることを確認
        let instr = Instruction::decode_from_bytes(&packets[0]).unwrap();
        assert_eq!(instr.new_num_or_zero(), 1);
        assert_eq!(instr.diff_bytes(), &[1, 2, 3, 4]);
    }

    #[test]
    fn test_recv_instruction_updates_state() {
        let mut session = SspSession::new();

        let instr = Instruction::new_send(0, 1, 0, 0, alloc::vec![9, 8, 7]);
        let payload = session.recv_instruction(&instr, 1000);

        assert_eq!(payload, Some(alloc::vec![9, 8, 7]));
        assert_eq!(session.stats().recv_num, 1);
    }

    #[test]
    fn test_ack_handling() {
        let mut session = SspSession::new();

        // データを送信
        session.push_payload(alloc::vec![1, 2, 3]);
        let _ = session.tick(1000);
        assert_eq!(session.stats().pending_count, 1);

        // ACK を受信
        let ack = Instruction::new_ack(1, 0);
        session.recv_instruction(&ack, 1100);

        assert_eq!(session.stats().pending_count, 0);
        assert_eq!(session.stats().send_num, 2); // 次の番号
    }

    #[test]
    fn test_heartbeat_needed() {
        let mut session = SspSession::new();

        // 最初はハートビートが必要（last_send_ms = 0）
        assert!(session.needs_heartbeat(HEARTBEAT_INTERVAL_MS));

        // tick でハートビートを送信
        let packets = session.tick(HEARTBEAT_INTERVAL_MS);
        assert!(!packets.is_empty()); // ハートビートが生成される

        // 送信直後は不要
        assert!(!session.needs_heartbeat(HEARTBEAT_INTERVAL_MS));
    }

    #[test]
    fn test_duplicate_recv_ignored() {
        let mut session = SspSession::new();

        let instr = Instruction::new_send(0, 1, 0, 0, alloc::vec![1]);
        let payload1 = session.recv_instruction(&instr, 1000);
        let payload2 = session.recv_instruction(&instr, 1001); // 同じ番号を再受信

        assert!(payload1.is_some());
        assert!(payload2.is_none()); // 重複は無視
    }

    #[test]
    fn test_rtt_update() {
        let mut session = SspSession::new();

        // データ送信
        session.push_payload(alloc::vec![0]);
        let _ = session.tick(0);

        // ACK で RTT 計算
        let ack = Instruction::new_ack(1, 0);
        session.recv_instruction(&ack, 150); // 150ms 後に ACK

        // SRTT が更新されているはず
        assert!(session.srtt_ms > 0.0);
        assert!(session.rto_ms >= RTO_MIN_MS);
        assert!(session.rto_ms <= RTO_MAX_MS);
    }
}
