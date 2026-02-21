#!/usr/bin/env bash
# build.sh - mosh-wasm ビルドスクリプト
#
# 使い方:
#   ./build.sh           # リリースビルド (WASM)
#   ./build.sh --dev     # デバッグビルド (WASM, ソースマップあり)
#   ./build.sh --check   # cargo check のみ
#   ./build.sh --test    # ユニットテスト (native)
#
# 前提条件:
#   - Rust + Cargo (rustup)
#   - wasm-pack: cargo install wasm-pack
#   - wasm32 ターゲット: rustup target add wasm32-unknown-unknown

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 色付き出力
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# ==============================================================
# 前提条件チェック
# ==============================================================
check_prerequisites() {
    log_info "前提条件を確認中..."

    # Rust / Cargo
    if ! command -v cargo &> /dev/null; then
        log_error "Cargo が見つかりません。rustup でインストールしてください:"
        echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
        exit 1
    fi
    log_ok "Cargo: $(cargo --version)"

    # wasm32 ターゲット
    if ! rustup target list --installed | grep -q "wasm32-unknown-unknown"; then
        log_warn "wasm32-unknown-unknown ターゲットが未インストール。追加します..."
        rustup target add wasm32-unknown-unknown
        log_ok "wasm32-unknown-unknown ターゲットを追加しました"
    else
        log_ok "wasm32-unknown-unknown ターゲット: インストール済み"
    fi

    # wasm-pack
    if ! command -v wasm-pack &> /dev/null; then
        log_warn "wasm-pack が見つかりません。インストールします..."
        cargo install wasm-pack
        log_ok "wasm-pack をインストールしました"
    else
        log_ok "wasm-pack: $(wasm-pack --version)"
    fi
}

# ==============================================================
# cargo check
# ==============================================================
run_check() {
    log_info "cargo check を実行中 (native)..."
    cargo check --workspace
    log_ok "cargo check 完了"

    log_info "cargo check を実行中 (wasm32)..."
    cargo check --workspace --target wasm32-unknown-unknown
    log_ok "cargo check (wasm32) 完了"
}

# ==============================================================
# テスト実行
# ==============================================================
run_tests() {
    log_info "ユニットテストを実行中 (native)..."
    cargo test --workspace
    log_ok "全テスト通過"
}

# ==============================================================
# WASM ビルド（リリース）
# ==============================================================
build_release() {
    log_info "WASM リリースビルドを開始..."

    local OUT_DIR="$SCRIPT_DIR/mosh-wasm-pkg"
    mkdir -p "$OUT_DIR"

    wasm-pack build \
        crates/mosh-wasm \
        --target nodejs \
        --out-dir "../../mosh-wasm-pkg" \
        --release

    log_ok "リリースビルド完了 → $OUT_DIR"
    log_info "生成ファイル:"
    ls -lh "$OUT_DIR"
}

# ==============================================================
# WASM ビルド（デバッグ）
# ==============================================================
build_dev() {
    log_info "WASM デバッグビルドを開始..."

    local OUT_DIR="$SCRIPT_DIR/mosh-wasm-pkg"
    mkdir -p "$OUT_DIR"

    wasm-pack build \
        crates/mosh-wasm \
        --target nodejs \
        --out-dir "../../mosh-wasm-pkg" \
        --dev

    log_ok "デバッグビルド完了 → $OUT_DIR"
}

# ==============================================================
# エントリポイント
# ==============================================================
main() {
    local MODE="${1:-release}"

    case "$MODE" in
        --check)
            check_prerequisites
            run_check
            ;;
        --test)
            check_prerequisites
            run_tests
            ;;
        --dev)
            check_prerequisites
            run_check
            run_tests
            build_dev
            ;;
        release | --release)
            check_prerequisites
            run_check
            run_tests
            build_release
            ;;
        --help | -h)
            echo "使い方: $0 [オプション]"
            echo ""
            echo "オプション:"
            echo "  (なし)     リリースビルド (WASM)"
            echo "  --dev      デバッグビルド (WASM, ソースマップあり)"
            echo "  --check    cargo check のみ"
            echo "  --test     ユニットテストのみ"
            echo "  --help     このヘルプを表示"
            ;;
        *)
            log_error "不明なオプション: $MODE"
            echo "使い方: $0 [--dev|--check|--test|--help]"
            exit 1
            ;;
    esac
}

main "$@"
