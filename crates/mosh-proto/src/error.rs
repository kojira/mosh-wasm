//! mosh-proto エラー型

/// Protobuf エンコード/デコードのエラー
#[derive(Debug)]
pub enum ProtoError {
    /// Protobuf デコード失敗
    DecodeFailed(prost::DecodeError),
    /// プロトコルバージョン不一致（現在サポートするのはバージョン 2 のみ）
    InvalidProtocolVersion(u32),
}

impl core::fmt::Display for ProtoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ProtoError::DecodeFailed(e) => write!(f, "Proto decode failed: {}", e),
            ProtoError::InvalidProtocolVersion(v) => {
                write!(f, "Invalid protocol version: {} (expected {})", v, super::MOSH_PROTOCOL_VERSION)
            }
        }
    }
}
