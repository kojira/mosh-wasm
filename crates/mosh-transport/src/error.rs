//! mosh-transport エラー型

/// トランスポート層のエラー
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// パケット/フラグメントが短すぎる
    TooShort,
    /// Fragment のフォーマットが不正
    InvalidFragmentFormat,
    /// 再組み立てエラー
    AssemblyError,
}

impl core::fmt::Display for TransportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TransportError::TooShort => write!(f, "Packet or fragment too short"),
            TransportError::InvalidFragmentFormat => write!(f, "Invalid fragment format"),
            TransportError::AssemblyError => write!(f, "Fragment reassembly error"),
        }
    }
}
