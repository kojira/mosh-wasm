//! Fragment 分割と再組み立て
//!
//! ## Fragment Wire Format
//! ```text
//! [instruction_id: u64 BE (8 bytes)]
//! [fragment_num_with_final: u16 BE (2 bytes)]
//!   - bit 15: is_final (最後の Fragment の場合 1)
//!   - bit 0..14: fragment 番号 (0 始まり)
//! [payload: variable]
//! ```

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::error::TransportError;

/// mosh Fragment（ネットワーク上の最小送受信単位）
///
/// 一つの SSP Instruction が MTU を超える場合、複数の Fragment に分割される。
/// すべての Fragment が揃うと元の Instruction バイト列に再組み立てされる。
#[derive(Debug, Clone)]
pub struct Fragment {
    /// この Fragment が属する Instruction の ID
    pub instruction_id: u64,
    /// Fragment 番号（0 始まり）
    pub fragment_num: u16,
    /// 最後の Fragment かどうか
    pub is_final: bool,
    /// Fragment ペイロード（Instruction バイト列の一部）
    pub payload: Vec<u8>,
}

impl Fragment {
    /// Fragment ヘッダー長（instruction_id: 8 + fragment_num_with_final: 2）
    pub const HEADER_LEN: usize = 10;

    /// バイト列から Fragment を復元する（復号後のバイト列を渡す）
    ///
    /// # Wire Format
    /// ```text
    /// [instruction_id: u64 BE (8 bytes)][fragment_num_with_final: u16 BE (2 bytes)][payload...]
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TransportError> {
        if bytes.len() < Self::HEADER_LEN {
            return Err(TransportError::TooShort);
        }

        // instruction_id (8 bytes, big-endian)
        let mut id_bytes = [0u8; 8];
        id_bytes.copy_from_slice(&bytes[0..8]);
        let instruction_id = u64::from_be_bytes(id_bytes);

        // fragment_num_with_final (2 bytes, big-endian)
        let frag_word = u16::from_be_bytes([bytes[8], bytes[9]]);
        let is_final = (frag_word >> 15) == 1;
        let fragment_num = frag_word & 0x7FFF; // 下位 15 ビット

        let payload = bytes[Self::HEADER_LEN..].to_vec();

        Ok(Fragment {
            instruction_id,
            fragment_num,
            is_final,
            payload,
        })
    }

    /// Fragment を Wire Format に変換する
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::HEADER_LEN + self.payload.len());

        // instruction_id (8 bytes, big-endian)
        bytes.extend_from_slice(&self.instruction_id.to_be_bytes());

        // fragment_num_with_final (2 bytes, big-endian)
        let frag_word: u16 = self.fragment_num | if self.is_final { 0x8000 } else { 0 };
        bytes.extend_from_slice(&frag_word.to_be_bytes());

        // payload
        bytes.extend_from_slice(&self.payload);

        bytes
    }
}

/// Instruction バイト列を Fragment 列に分割するクラス
///
/// MTU を超える Instruction を複数の Fragment に分割する。
/// mosh のデフォルト MTU は 500 バイト（モバイル向け保守的設定）。
pub struct Fragmenter {
    /// 次に使う instruction_id
    next_instruction_id: u64,
    /// アプリケーション MTU（Fragment ペイロードの最大バイト数）
    /// = ネットワーク MTU - 暗号オーバーヘッド(24) - Fragment ヘッダー(10)
    app_payload_mtu: usize,
}

impl Fragmenter {
    /// 新しい Fragmenter を生成する
    ///
    /// # 引数
    /// - `app_mtu`: Fragment ペイロードの最大バイト数
    ///   - mosh デフォルト: 500 - 24(crypto overhead) - 10(fragment header) = 466
    ///   - 保守的推奨値: 450（PMTUD なし環境向け）
    pub fn new(app_mtu: usize) -> Self {
        Fragmenter {
            next_instruction_id: 1, // 1 始まり（0 は未初期化扱い）
            app_payload_mtu: app_mtu,
        }
    }

    /// Instruction バイト列を Fragment 列に分割する
    ///
    /// # 引数
    /// - `instruction_bytes`: Instruction の Protocol Buffer エンコード済みバイト列
    ///
    /// # 戻り値
    /// Fragment のベクタ。1 つに収まる場合でも常に Vec で返す。
    pub fn make_fragments(&mut self, instruction_bytes: &[u8]) -> Vec<Fragment> {
        let id = self.next_instruction_id;
        self.next_instruction_id = self.next_instruction_id.wrapping_add(1);

        if instruction_bytes.is_empty() {
            // 空 Instruction → Fragment 1 つ（ハートビート用）
            return alloc::vec![Fragment {
                instruction_id: id,
                fragment_num: 0,
                is_final: true,
                payload: alloc::vec![],
            }];
        }

        let chunks: Vec<&[u8]> = instruction_bytes.chunks(self.app_payload_mtu).collect();
        let num_chunks = chunks.len();

        chunks
            .into_iter()
            .enumerate()
            .map(|(i, chunk)| Fragment {
                instruction_id: id,
                fragment_num: i as u16,
                is_final: i == num_chunks - 1,
                payload: chunk.to_vec(),
            })
            .collect()
    }

    /// 現在の instruction_id カウンタを返す（テスト用）
    pub fn current_id(&self) -> u64 {
        self.next_instruction_id
    }
}

/// Fragment を受け取り、Instruction に再組み立てするクラス
///
/// 複数の Fragment を順番通りではなく受け取り、すべて揃った時点で
/// 元の Instruction バイト列を返す。
///
/// mosh では、より新しい instruction_id の Fragment が来たら
/// 古い instruction_id の Fragment は破棄する。
pub struct FragmentAssembly {
    /// 現在組み立て中の instruction_id
    current_id: Option<u64>,
    /// 受信済み Fragment（fragment_num → Fragment）
    arrived: BTreeMap<u16, Fragment>,
    /// 最後の Fragment（is_final=true）の fragment_num
    final_fragment_num: Option<u16>,
}

impl FragmentAssembly {
    /// 新しい FragmentAssembly を生成する
    pub fn new() -> Self {
        FragmentAssembly {
            current_id: None,
            arrived: BTreeMap::new(),
            final_fragment_num: None,
        }
    }

    /// Fragment を追加する
    ///
    /// # 戻り値
    /// - `Some(Vec<u8>)`: すべての Fragment が揃い、再組み立てした Instruction バイト列
    /// - `None`: まだ Fragment が足りない
    pub fn add_fragment(&mut self, frag: Fragment) -> Option<Vec<u8>> {
        // 新しい instruction_id が来たら古いものを破棄
        self.reset_if_new_id(frag.instruction_id);

        if self.current_id.is_none() {
            self.current_id = Some(frag.instruction_id);
        }

        if frag.is_final {
            self.final_fragment_num = Some(frag.fragment_num);
        }

        let frag_num = frag.fragment_num;
        self.arrived.insert(frag_num, frag);

        // すべての Fragment が揃ったか確認
        self.try_assemble()
    }

    /// 新しい instruction_id が来たら古い状態をリセットする
    ///
    /// # 戻り値
    /// - `true`: リセットが行われた（新しい ID だった）
    /// - `false`: 同じ ID（リセットなし）
    pub fn reset_if_new_id(&mut self, id: u64) -> bool {
        match self.current_id {
            Some(current) if current == id => false,
            _ => {
                self.arrived.clear();
                self.final_fragment_num = None;
                self.current_id = Some(id);
                true
            }
        }
    }

    /// すべての Fragment が揃っていれば Instruction バイト列を返す
    fn try_assemble(&self) -> Option<Vec<u8>> {
        let final_num = self.final_fragment_num?;

        // fragment_num が 0..=final_num のすべてが揃っているか
        for num in 0..=final_num {
            if !self.arrived.contains_key(&num) {
                return None;
            }
        }

        // 揃ったので順番に結合する
        let mut assembled = Vec::new();
        for num in 0..=final_num {
            assembled.extend_from_slice(&self.arrived[&num].payload);
        }

        Some(assembled)
    }

    /// 現在組み立て中の instruction_id を返す
    pub fn current_id(&self) -> Option<u64> {
        self.current_id
    }
}

impl Default for FragmentAssembly {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fragment_roundtrip() {
        let frag = Fragment {
            instruction_id: 42,
            fragment_num: 0,
            is_final: true,
            payload: alloc::vec![1, 2, 3, 4, 5],
        };

        let bytes = frag.to_bytes();
        let restored = Fragment::from_bytes(&bytes).unwrap();

        assert_eq!(restored.instruction_id, 42);
        assert_eq!(restored.fragment_num, 0);
        assert!(restored.is_final);
        assert_eq!(restored.payload, alloc::vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_fragmenter_single_fragment() {
        let mut fragmenter = Fragmenter::new(500);
        let data = alloc::vec![0u8; 100];
        let frags = fragmenter.make_fragments(&data);

        assert_eq!(frags.len(), 1);
        assert!(frags[0].is_final);
        assert_eq!(frags[0].fragment_num, 0);
        assert_eq!(frags[0].payload, data);
    }

    #[test]
    fn test_fragmenter_multiple_fragments() {
        let mut fragmenter = Fragmenter::new(10); // 小さい MTU でテスト
        let data = alloc::vec![0u8; 25];          // 3 つに分割される
        let frags = fragmenter.make_fragments(&data);

        assert_eq!(frags.len(), 3);
        assert!(!frags[0].is_final);
        assert!(!frags[1].is_final);
        assert!(frags[2].is_final);
        assert_eq!(frags[0].fragment_num, 0);
        assert_eq!(frags[1].fragment_num, 1);
        assert_eq!(frags[2].fragment_num, 2);
    }

    #[test]
    fn test_assembly_single_fragment() {
        let mut assembly = FragmentAssembly::new();
        let payload = alloc::vec![1, 2, 3, 4, 5];

        let frag = Fragment {
            instruction_id: 1,
            fragment_num: 0,
            is_final: true,
            payload: payload.clone(),
        };

        let result = assembly.add_fragment(frag);
        assert_eq!(result, Some(payload));
    }

    #[test]
    fn test_assembly_multiple_fragments() {
        let mut assembly = FragmentAssembly::new();

        let frag0 = Fragment {
            instruction_id: 1,
            fragment_num: 0,
            is_final: false,
            payload: alloc::vec![1, 2, 3],
        };
        let frag1 = Fragment {
            instruction_id: 1,
            fragment_num: 1,
            is_final: true,
            payload: alloc::vec![4, 5, 6],
        };

        // 順不同で追加
        assert_eq!(assembly.add_fragment(frag1), None);
        let result = assembly.add_fragment(frag0);
        assert_eq!(result, Some(alloc::vec![1, 2, 3, 4, 5, 6]));
    }

    #[test]
    fn test_assembly_new_id_resets() {
        let mut assembly = FragmentAssembly::new();

        // 古い ID の Fragment を追加
        let old_frag = Fragment {
            instruction_id: 1,
            fragment_num: 0,
            is_final: false,
            payload: alloc::vec![1, 2, 3],
        };
        assembly.add_fragment(old_frag);

        // 新しい ID の Fragment が来たら古いのはリセットされ、
        // is_final の Fragment のみなので即座に完成する
        let new_frag = Fragment {
            instruction_id: 2,
            fragment_num: 0,
            is_final: true,
            payload: alloc::vec![9, 8, 7],
        };
        let result = assembly.add_fragment(new_frag);
        assert_eq!(result, Some(alloc::vec![9, 8, 7]));
    }

    #[test]
    fn test_fragmenter_assembly_roundtrip() {
        let mut fragmenter = Fragmenter::new(10);
        let original: Vec<u8> = (0u8..100).collect();

        let frags = fragmenter.make_fragments(&original);
        assert!(frags.len() > 1);

        let mut assembly = FragmentAssembly::new();
        let mut result = None;
        for frag in frags {
            result = assembly.add_fragment(frag);
        }

        assert_eq!(result.unwrap(), original);
    }

    #[test]
    fn test_is_final_bit_encoding() {
        // is_final = true のとき fragment_num の MSB が立つことを確認
        let frag_final = Fragment {
            instruction_id: 1,
            fragment_num: 0,
            is_final: true,
            payload: alloc::vec![],
        };
        let bytes = frag_final.to_bytes();
        // bytes[8] と bytes[9] が fragment_num_with_final
        let frag_word = u16::from_be_bytes([bytes[8], bytes[9]]);
        assert_eq!(frag_word >> 15, 1); // MSB が 1

        let frag_not_final = Fragment {
            instruction_id: 1,
            fragment_num: 3,
            is_final: false,
            payload: alloc::vec![],
        };
        let bytes2 = frag_not_final.to_bytes();
        let frag_word2 = u16::from_be_bytes([bytes2[8], bytes2[9]]);
        assert_eq!(frag_word2 >> 15, 0); // MSB が 0
        assert_eq!(frag_word2 & 0x7FFF, 3); // fragment_num = 3
    }
}
