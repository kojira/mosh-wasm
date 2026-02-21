//! # mosh-stream
//!
//! バイトストリーム抽象化レイヤー
//!
//! VS Code RPC プロトコル（バイトストリーム）を mosh SSP チャンネルで流すための抽象化。
//!
//! ## 設計の背景
//!
//! mosh 本来の用途は VT100 端末エミュレーションで、状態差分は「画面の変化」。
//! この実装では端末エミュレーションを完全にバイパスし、
//! `diff` フィールドを raw バイトストリームとして使用する。
//!
//! ## バイトストリームモードの仕組み
//!
//! ```text
//! 送信:
//!   1. VS Code Extension → stream.write(data)
//!   2. stream.take_pending_diff() → SSP の Instruction.diff に設定
//!   3. SSP → Fragment 分割 → 暗号化 → UDP
//!
//! 受信:
//!   1. UDP → 復号 → Fragment 再組み立て → SSP
//!   2. SSP の Instruction.diff → stream.apply_diff(diff)
//!   3. stream.read_available() → VS Code Extension
//! ```

#![no_std]
extern crate alloc;

pub mod channel;

pub use channel::StreamChannel;
