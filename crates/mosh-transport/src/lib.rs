//! # mosh-transport
//!
//! UDP トランスポート層の実装。
//!
//! mosh の UDP パケット構造と Fragment 分割/再組み立てを担当する。
//!
//! ## Fragment の Wire Format
//!
//! ```text
//! [instruction_id: u64 BE][fragment_num_with_final: u16 BE][payload...]
//!
//! fragment_num_with_final:
//!   bit 15 (MSB) = is_final フラグ（最後の Fragment なら 1）
//!   bit 0..14    = fragment_num（0 始まり）
//! ```
//!
//! ## UDP ペイロードの全体構造
//!
//! ```text
//! [nonce_tail: 8bytes][encrypted_fragment + auth_tag: variable]
//!                      ↑ AES-128-OCB3 で暗号化された Fragment バイト列 + 16バイトタグ
//! ```

#![no_std]
extern crate alloc;

pub mod error;
pub mod fragment;
pub mod packet;
pub mod timestamp;

pub use error::TransportError;
pub use fragment::{Fragment, FragmentAssembly, Fragmenter};
pub use packet::UdpPacket;
pub use timestamp::Timestamp16;
