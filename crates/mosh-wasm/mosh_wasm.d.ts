/**
 * mosh_wasm.d.ts
 *
 * wasm-bindgen が自動生成する型定義のひな形。
 * 実際の型定義は `wasm-pack build` によって `mosh-wasm-pkg/mosh_wasm.d.ts` に生成される。
 *
 * このファイルは:
 * 1. wasm-pack が未実行の段階での開発支援（型チェック・IDE 補完）
 * 2. 公開 API の仕様ドキュメントとして機能
 *
 * 注意: 実際に使用するのは `mosh-wasm-pkg/mosh_wasm.d.ts`（自動生成）
 *
 * @module mosh-wasm
 */

/* tslint:disable */
/* eslint-disable */

/**
 * mosh クライアントセッション
 *
 * AES-128-OCB3 暗号化 + SSP プロトコル + Fragment 管理を統合した
 * wasm-bindgen エクスポートクラス。
 *
 * ## 使用例
 *
 * ```typescript
 * import { MoshClient, init_panic_hook } from './mosh-wasm-pkg/mosh_wasm';
 *
 * // 初期化（開発時のみ）
 * init_panic_hook();
 *
 * // クライアント作成
 * const client = new MoshClient("4NeCCgvZFe2RnPgrcU1PQw");
 *
 * // UDP 受信処理
 * socket.on('message', (msg: Buffer) => {
 *     const data = client.recvUdpPacket(new Uint8Array(msg.buffer), Date.now());
 *     if (data.length > 0) {
 *         onDataReceived(data); // VS Code RPC に渡す
 *     }
 * });
 *
 * // 定期タイマー（ハートビート・再送）
 * setInterval(() => {
 *     const packets = client.tick(Date.now());
 *     for (const pkt of packets) {
 *         socket.send(Buffer.from(pkt));
 *     }
 * }, 50);
 *
 * // VS Code からのデータ送信
 * function sendToMosh(data: Uint8Array) {
 *     const packets = client.sendData(data, Date.now());
 *     for (const pkt of packets) {
 *         socket.send(Buffer.from(pkt));
 *     }
 * }
 * ```
 */
export class MoshClient {
    /**
     * mosh クライアントを初期化する
     *
     * @param key_base64 - mosh-server が出力した Base64 鍵（22文字）
     *   例: `"4NeCCgvZFe2RnPgrcU1PQw"`
     *   SSH 接続後に `mosh-server new` の標準出力 `"MOSH CONNECT <PORT> <KEY>"` から取得
     * @param mtu - UDP の実効 MTU（バイト）。省略時は 500（モバイル向け推奨値）。
     *   - 有線 LAN や高品質な接続: 1400 を推奨
     *   - モバイル・混雑した Wi-Fi: 500（デフォルト）を推奨
     *
     * @throws {Error} - Base64 鍵のデコード失敗または鍵長不正
     */
    constructor(key_base64: string, mtu?: number);

    /**
     * 受信した UDP ペイロード（生バイト）を処理する
     *
     * 処理フロー:
     * 1. AES-128-OCB3 復号
     * 2. Fragment ヘッダーを解析
     * 3. Fragment が揃ったら Instruction に再組み立て
     * 4. SSP プロトコル処理（ACK、状態更新）
     * 5. ペイロードをバッファに積む
     *
     * @param udp_bytes - Node.js `socket.on('message', msg)` の `msg` を Uint8Array に変換したもの
     *   ```typescript
     *   socket.on('message', (msg: Buffer) => {
     *       const bytes = new Uint8Array(msg.buffer, msg.byteOffset, msg.byteLength);
     *       const data = client.recvUdpPacket(bytes, Date.now());
     *   });
     *   ```
     * @param now_ms - 現在時刻（`Date.now()` の値）
     *
     * @returns 上位レイヤー（VS Code RPC）に渡すバイト列。
     *   データがない場合は長さ 0 の Uint8Array。
     *   空かどうかは `data.length > 0` で確認する。
     *
     * @throws {Error} - 復号失敗（パケット破損）
     *   注: mosh ではパケットロスが起こりうるため、エラーは catch して警告ログに留める。
     *   接続が切れたわけではない。
     */
    recvUdpPacket(udp_bytes: Uint8Array, now_ms: number): Uint8Array;

    /**
     * 上位レイヤー（VS Code RPC）からのデータを mosh で送信する
     *
     * 処理フロー:
     * 1. SSP Instruction を生成
     * 2. Fragment に分割（MTU に合わせて）
     * 3. AES-128-OCB3 で暗号化
     * 4. UDP ペイロードのリストを返す
     *
     * @param data - `ManagedMessagePassing.send()` で来た Uint8Array
     * @param now_ms - 現在時刻（`Date.now()`）
     *
     * @returns 送信すべき UDP ペイロードの配列。
     *   各要素を `socket.send()` で送信する。
     *   ```typescript
     *   const packets = client.sendData(data, Date.now());
     *   for (const pkt of packets) {
     *       socket.send(Buffer.from(pkt));
     *   }
     *   ```
     *
     * @throws {Error} - 暗号化失敗（通常は起こらない）
     */
    sendData(data: Uint8Array, now_ms: number): Uint8Array[];

    /**
     * 定期タイマー tick（ハートビート・再送管理）
     *
     * Node.js の `setInterval` から **50ms ごと** に呼び出す。
     * - 送信待ちデータがあれば送信 Instruction を生成
     * - 再送タイムアウト（RTO）を超えた未 ACK パケットを再送
     * - 3000ms 以上何も送っていなければハートビートを送信
     *
     * @param now_ms - 現在時刻（`Date.now()`）
     *
     * @returns 送信すべき UDP ペイロードの配列（空の場合もある）
     *
     * @throws {Error} - 暗号化失敗（通常は起こらない）
     *
     * @example
     * ```typescript
     * setInterval(() => {
     *     const packets = client.tick(Date.now());
     *     for (const pkt of packets) {
     *         socket.send(Buffer.from(pkt));
     *     }
     * }, 50);
     * ```
     */
    tick(now_ms: number): Uint8Array[];

    /**
     * 上位レイヤーが読み取れるデータがあるかチェック
     *
     * `recvUdpPacket` の戻り値を使わずに、`readPending` で後から読み取る場合に使う。
     * 通常は `recvUdpPacket` の戻り値を直接使う方がシンプル。
     */
    hasPendingRead(): boolean;

    /**
     * バッファのデータをすべて読み出す
     *
     * `recvUdpPacket` の戻り値とは別に、後から呼び出すこともできる。
     * データがない場合は長さ 0 の Uint8Array を返す。
     */
    readPending(): Uint8Array;

    /**
     * セッション統計を JSON 文字列で返す
     *
     * @returns JSON 文字列:
     * ```json
     * {
     *   "srtt_ms": 45.2,
     *   "rto_ms": 230,
     *   "send_num": 42,
     *   "recv_num": 38,
     *   "pending_count": 2,
     *   "total_sent_bytes": 102400,
     *   "total_recv_bytes": 98304
     * }
     * ```
     *
     * @example
     * ```typescript
     * const stats = JSON.parse(client.getStats());
     * console.log(`RTT: ${stats.srtt_ms.toFixed(1)}ms`);
     * ```
     */
    getStats(): string;

    /**
     * GC 対象になる前に呼ぶ（内部バッファ解放）
     *
     * JavaScript の GC が解放するが、明示的に呼ぶことで WASM メモリを
     * 早期解放できる。接続終了時に呼ぶことを推奨。
     *
     * @example
     * ```typescript
     * try {
     *     // 接続処理
     * } finally {
     *     client.free();
     * }
     * ```
     */
    free(): void;
}

/**
 * デバッグ用: コンソールにパニックスタックトレースを出力するよう設定する
 *
 * 開発時に一度だけ呼び出す。本番環境では不要（呼んでも害はない）。
 *
 * @example
 * ```typescript
 * import { init_panic_hook } from './mosh-wasm-pkg/mosh_wasm';
 * init_panic_hook(); // アプリ起動時に一度だけ
 * ```
 */
export function init_panic_hook(): void;

/**
 * Base64 鍵（22文字）を 16 バイトの Uint8Array に変換する
 *
 * テスト・デバッグ用ユーティリティ。
 * 実際の接続には `MoshClient` コンストラクタに直接渡す。
 *
 * @param key_b64 - mosh-server が出力した Base64 鍵（例: "4NeCCgvZFe2RnPgrcU1PQw"）
 * @returns 16 バイトの Uint8Array（AES-128 鍵）
 *
 * @throws {Error} - Base64 デコード失敗または鍵長不正
 *
 * @example
 * ```typescript
 * const keyBytes = decodeBase64Key("4NeCCgvZFe2RnPgrcU1PQw");
 * console.log(keyBytes); // Uint8Array(16) [...]
 * ```
 */
export function decodeBase64Key(key_b64: string): Uint8Array;

/**
 * セッション統計の型定義
 * `JSON.parse(client.getStats())` の結果に使う
 */
export interface MoshStats {
    /** Smoothed RTT（ミリ秒）。-1 は未計測。 */
    srtt_ms: number;
    /** Retransmission Timeout（ミリ秒）。50〜1000 の範囲。 */
    rto_ms: number;
    /** 次の送信 Instruction 番号 */
    send_num: number;
    /** 最後に受信した Instruction 番号 */
    recv_num: number;
    /** ACK 待ちの Instruction 数 */
    pending_count: number;
    /** セッション開始からの送信総バイト数 */
    total_sent_bytes: number;
    /** セッション開始からの受信総バイト数 */
    total_recv_bytes: number;
}
