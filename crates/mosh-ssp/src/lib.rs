//! # mosh-ssp
//!
//! SSP (State Synchronization Protocol) のコア状態機械。
//!
//! ## SSP の概要
//!
//! SSP は mosh のトランスポートプロトコル。TCP とは異なり、
//! 最新の状態の同期を保証する（中間の状態はスキップ可能）。
//!
//! ### キーコンセプト
//!
//! - **Instruction**: 送信の最小単位。old_num〜new_num の状態差分を含む
//! - **ACK**: ack_num で受信確認を通知する
//! - **throwaway_num**: これより古い Instruction はもう不要（メモリ解放の合図）
//! - **ハートビート**: 3000ms ごとに ACK を送って接続を維持する
//! - **RTT 推定**: Jacobson アルゴリズムで Smoothed RTT を推定
//! - **再送**: RTO 経過後に未 ACK の Instruction を再送
//!
//! ## セッションの状態遷移
//!
//! ```text
//! Initial → Connected (初回 Instruction 送受信後)
//!         → Connected (ハートビート継続)
//!         → Timeout (長時間 ACK なし、アプリ層が判断)
//! ```

#![no_std]
extern crate alloc;

pub mod session;

pub use session::SspSession;

pub use mosh_proto::MOSH_PROTOCOL_VERSION;

/// ハートビート間隔（ミリ秒）
/// mosh C++ 実装では 3000ms
pub const HEARTBEAT_INTERVAL_MS: u64 = 3000;

/// 再送タイムアウト最小値（ミリ秒）
pub const RTO_MIN_MS: u64 = 50;

/// 再送タイムアウト最大値（ミリ秒）
pub const RTO_MAX_MS: u64 = 1000;

/// 初期 RTO（ミリ秒）
pub const RTO_INITIAL_MS: u64 = 1000;
