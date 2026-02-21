/// mosh-proto build script
///
/// prost-build を使って .proto ファイルから Rust コードを自動生成する。
/// 生成されたコードは OUT_DIR に配置される。

fn main() {
    prost_build::Config::new()
        .compile_protos(
            &["proto/transportinstruction.proto"],
            &["proto/"],
        )
        .expect("Failed to compile proto files");
}
