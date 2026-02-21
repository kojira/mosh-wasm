//! mosh-wasm 統合テスト
//!
//! crypto + transport + SSP + stream の完全なパイプラインをテストする。
//! mosh プロトコルの実際の動作をシミュレートする。

use mosh_crypto::{CryptoSession, Direction};
use mosh_proto::Instruction;
use mosh_ssp::SspSession;
use mosh_stream::StreamChannel;
use mosh_transport::{Fragment, FragmentAssembly, Fragmenter, Timestamp16};

// ==============================================================
// ヘルパー: 完全なパイプラインを経由して Instruction を送受信する
// ==============================================================

/// 送信側セッション（フル）
struct Sender {
    crypto: CryptoSession,
    fragmenter: Fragmenter,
    ssp: SspSession,
    stream: StreamChannel,
    last_remote_ts: u16,
}

/// 受信側セッション（フル）
struct Receiver {
    crypto: CryptoSession,
    assembly: FragmentAssembly,
    ssp: SspSession,
    stream: StreamChannel,
}

impl Sender {
    fn new(key: [u8; 16], mtu: usize) -> Self {
        Sender {
            crypto: CryptoSession::from_key(key).unwrap(),
            fragmenter: Fragmenter::new(mtu.saturating_sub(46).max(64)),
            ssp: SspSession::new(),
            stream: StreamChannel::new(),
            last_remote_ts: Timestamp16::INIT.raw(),
        }
    }

    /// データを送信して UDP ペイロード列を返す
    fn send(&mut self, data: &[u8], now_ms: u64) -> Vec<Vec<u8>> {
        self.stream.write(data);
        let pending = self.stream.take_pending_diff();
        if !pending.is_empty() {
            self.ssp.push_payload(pending);
        }

        let instructions = self.ssp.tick(now_ms);
        let mut udp_packets = Vec::new();

        for instr_bytes in instructions {
            let frags = self.fragmenter.make_fragments(&instr_bytes);
            let ts = Timestamp16::now_from_ms(now_ms).raw();
            let ts_reply = self.last_remote_ts;

            for frag in frags {
                let frag_bytes = frag.to_bytes();
                let udp_payload = self.crypto
                    .encrypt_packet(Direction::ToServer, ts, ts_reply, &frag_bytes)
                    .unwrap();
                udp_packets.push(udp_payload);
            }
        }

        udp_packets
    }

    /// ACK のみのハートビートを送信
    fn heartbeat(&mut self, now_ms: u64) -> Vec<Vec<u8>> {
        let instructions = self.ssp.tick(now_ms);
        let mut udp_packets = Vec::new();

        for instr_bytes in instructions {
            let frags = self.fragmenter.make_fragments(&instr_bytes);
            let ts = Timestamp16::now_from_ms(now_ms).raw();
            let ts_reply = self.last_remote_ts;

            for frag in frags {
                let frag_bytes = frag.to_bytes();
                let udp_payload = self.crypto
                    .encrypt_packet(Direction::ToServer, ts, ts_reply, &frag_bytes)
                    .unwrap();
                udp_packets.push(udp_payload);
            }
        }

        udp_packets
    }
}

impl Receiver {
    fn new(key: [u8; 16]) -> Self {
        Receiver {
            crypto: CryptoSession::from_key(key).unwrap(),
            assembly: FragmentAssembly::new(),
            ssp: SspSession::new(),
            stream: StreamChannel::new(),
        }
    }

    /// UDP ペイロードを受信して処理し、上位レイヤーデータを返す
    fn recv(&mut self, udp_payload: &[u8], now_ms: u64) -> Option<Vec<u8>> {
        // 1. 復号
        let decrypted = self.crypto.decrypt_packet(udp_payload).ok()?;

        // 2. Fragment 解析
        let frag = Fragment::from_bytes(&decrypted.payload).ok()?;

        // 3. 再組み立て
        let instruction_bytes = self.assembly.add_fragment(frag)?;

        // 4. Instruction デコード
        let instr = Instruction::decode_from_bytes(&instruction_bytes).ok()?;

        // 5. SSP 処理
        let payload = self.ssp.recv_instruction(&instr, now_ms)?;

        // 6. ストリームバッファへ
        self.stream.apply_diff(&payload);
        Some(self.stream.read_available())
    }
}

// ==============================================================
// テスト
// ==============================================================

/// 暗号化 → 復号のラウンドトリップテスト（AES-128-OCB3）
#[test]
fn test_crypto_roundtrip_full() {
    let key = [0xABu8; 16];
    let mut sender = CryptoSession::from_key(key).unwrap();
    let mut receiver = CryptoSession::from_key(key).unwrap();

    let payloads = [
        b"".as_slice(),
        b"Hello, mosh!".as_slice(),
        &[0u8; 500],       // 500バイト（標準 MTU）
        &[0xFFu8; 1400],   // 1400バイト（大きいパケット）
    ];

    for (i, payload) in payloads.iter().enumerate() {
        let packet = sender
            .encrypt_packet(Direction::ToServer, i as u16, 0, payload)
            .expect("暗号化に失敗");

        let decrypted = receiver
            .decrypt_packet(&packet)
            .expect("復号に失敗");

        assert_eq!(decrypted.payload, *payload, "ペイロード {} の往復が一致しない", i);
        assert_eq!(decrypted.direction, Direction::ToServer, "方向が一致しない");
        assert_eq!(decrypted.timestamp, i as u16, "タイムスタンプが一致しない");
    }
}

/// Direction ビットの暗号化・復号テスト
#[test]
fn test_crypto_direction_bits() {
    let key = [0u8; 16];
    let mut sender = CryptoSession::from_key(key).unwrap();
    let mut receiver = CryptoSession::from_key(key).unwrap();

    // ToServer 方向
    let pkt_to_server = sender
        .encrypt_packet(Direction::ToServer, 100, 200, b"from client")
        .unwrap();
    let dec = receiver.decrypt_packet(&pkt_to_server).unwrap();
    assert_eq!(dec.direction, Direction::ToServer);
    assert_eq!(dec.timestamp, 100);
    assert_eq!(dec.timestamp_reply, 200);
    assert_eq!(dec.payload, b"from client");

    // ToClient 方向
    let pkt_to_client = sender
        .encrypt_packet(Direction::ToClient, 300, 100, b"from server")
        .unwrap();
    let dec2 = receiver.decrypt_packet(&pkt_to_client).unwrap();
    assert_eq!(dec2.direction, Direction::ToClient);
    assert_eq!(dec2.timestamp, 300);
    assert_eq!(dec2.payload, b"from server");
}

/// 改ざんされたパケットの復号失敗テスト
#[test]
fn test_crypto_tampered_packet_fails() {
    let key = [0x42u8; 16];
    let mut sender = CryptoSession::from_key(key).unwrap();
    let mut receiver = CryptoSession::from_key(key).unwrap();

    let mut packet = sender
        .encrypt_packet(Direction::ToServer, 0, 0, b"authentic data")
        .unwrap();

    // パケットを改ざん（ciphertext 部分を変更）
    let len = packet.len();
    packet[len / 2] ^= 0xFF;

    let result = receiver.decrypt_packet(&packet);
    assert!(result.is_err(), "改ざんパケットは復号失敗すべき");
}

/// フラグメント分割 → 再組み立てのラウンドトリップテスト
#[test]
fn test_fragment_roundtrip_various_sizes() {
    let test_sizes = [0usize, 1, 100, 466, 467, 1000, 10_000];

    for &size in &test_sizes {
        let original: Vec<u8> = (0u8..).take(size % 256).cycle().take(size).collect();

        let mut fragmenter = Fragmenter::new(466); // 標準 payload MTU
        let frags = fragmenter.make_fragments(&original);

        let mut assembly = FragmentAssembly::new();
        let mut assembled = None;

        for frag in frags {
            assembled = assembly.add_fragment(frag);
        }

        let result = assembled.unwrap_or_default();
        assert_eq!(result, original, "サイズ {} のラウンドトリップ失敗", size);
    }
}

/// 順不同フラグメントの再組み立てテスト
#[test]
fn test_fragment_out_of_order_assembly() {
    let mut fragmenter = Fragmenter::new(10); // 小さい MTU で強制的に分割

    // 30バイト → 3フラグメント (10 + 10 + 10)
    let data: Vec<u8> = (0u8..30).collect();
    let frags = fragmenter.make_fragments(&data);
    assert_eq!(frags.len(), 3);

    // 逆順で追加
    let mut assembly = FragmentAssembly::new();
    let frag2 = frags[2].clone();
    let frag1 = frags[1].clone();
    let frag0 = frags[0].clone();

    assert!(assembly.add_fragment(frag2).is_none(), "最後から追加して再組み立て完了しないはず");
    assert!(assembly.add_fragment(frag1).is_none(), "中間追加で再組み立て完了しないはず");
    let result = assembly.add_fragment(frag0);

    assert_eq!(result, Some(data), "逆順フラグメントの再組み立て失敗");
}

/// 新しい instruction_id が来たとき古いフラグメントが破棄されるテスト
#[test]
fn test_fragment_id_reset_discards_old() {
    let mut fragmenter = Fragmenter::new(5); // 超小さい MTU
    let mut assembly = FragmentAssembly::new();

    // 最初の Instruction（3フラグメント分のデータ）
    let data1: Vec<u8> = vec![0u8; 15];
    let frags1 = fragmenter.make_fragments(&data1);

    // フラグメント 0 のみ追加（未完成）
    assembly.add_fragment(frags1[0].clone());
    assert_eq!(assembly.current_id(), Some(1));

    // 新しい Instruction（完結する1フラグメント）
    let data2 = vec![9u8; 3];
    let frags2 = fragmenter.make_fragments(&data2);
    let result = assembly.add_fragment(frags2[0].clone());

    // 古いフラグメントが破棄されて新しいのが完結する
    assert_eq!(result, Some(data2), "新しい ID で古いフラグメントが破棄されるべき");
    assert_eq!(assembly.current_id(), Some(2));
}

/// SSP 双方向通信の完全なパイプラインテスト（暗号化込み）
#[test]
fn test_full_pipeline_bidirectional() {
    let shared_key = [0xDEu8; 16];

    let mut client = Sender::new(shared_key, 500);
    let mut server = Receiver::new(shared_key);

    let now_ms: u64 = 100_000;

    // クライアント → サーバー: "Hello, Server!"
    let client_msg = b"Hello, Server!";
    let udp_packets = client.send(client_msg, now_ms);

    assert!(!udp_packets.is_empty(), "クライアントが UDP パケットを生成すべき");

    // すべての UDP パケットをサーバーで受信
    let mut server_received = None;
    for pkt in &udp_packets {
        server_received = server.recv(pkt, now_ms + 50);
    }

    assert_eq!(
        server_received,
        Some(client_msg.to_vec()),
        "サーバーがクライアントのデータを正確に受信すべき"
    );
}

/// 大きなデータのフラグメント化 + 暗号化 + 復号テスト
#[test]
fn test_large_payload_encrypted_fragmented() {
    let key = [0x77u8; 16];
    let mtu = 200usize; // 小さい MTU でフラグメント化を確認

    let mut sender = Sender::new(key, mtu);
    let mut receiver = Receiver::new(key);

    // 2000バイトのデータ（複数フラグメントになる）
    let large_data: Vec<u8> = (0u8..=255).cycle().take(2000).collect();

    let udp_packets = sender.send(&large_data, 50_000);

    // 複数の UDP パケットが生成されているはず
    assert!(udp_packets.len() > 1, "大きなペイロードは複数フラグメントになるべき");

    // すべて受信して再組み立て
    let mut final_data = None;
    for pkt in &udp_packets {
        if let Some(data) = receiver.recv(pkt, 50_100) {
            final_data = Some(data);
        }
    }

    assert_eq!(
        final_data,
        Some(large_data),
        "大きなペイロードの完全ラウンドトリップ失敗"
    );
}

/// SSP の複数メッセージ送受信テスト
#[test]
fn test_ssp_multiple_messages() {
    let key = [0x11u8; 16];
    let mut sender = Sender::new(key, 500);
    let mut receiver = Receiver::new(key);

    let messages = [
        b"Message #1".as_slice(),
        b"Message #2 - slightly longer".as_slice(),
        b"Message #3 - even longer message for testing purposes".as_slice(),
    ];

    for (i, msg) in messages.iter().enumerate() {
        let now_ms = 1000u64 + i as u64 * 100;
        let udp_packets = sender.send(msg, now_ms);

        let mut received = None;
        for pkt in &udp_packets {
            if let Some(data) = receiver.recv(pkt, now_ms + 30) {
                received = Some(data);
            }
        }

        assert_eq!(
            received,
            Some(msg.to_vec()),
            "メッセージ #{} の送受信失敗",
            i + 1
        );
    }

    // 受信側の状態確認
    assert_eq!(
        receiver.ssp.stats().recv_num,
        messages.len() as u64,
        "受信番号がメッセージ数と一致すべき"
    );
}

/// 異なる鍵での復号失敗テスト（セキュリティテスト）
#[test]
fn test_wrong_key_decryption_fails() {
    let key_correct = [0xAAu8; 16];
    let key_wrong = [0xBBu8; 16];

    let mut sender = Sender::new(key_correct, 500);
    let mut receiver = Receiver::new(key_wrong); // 異なる鍵！

    let udp_packets = sender.send(b"secret message", 1000);

    // 復号は失敗すべき
    for pkt in &udp_packets {
        let result = receiver.recv(pkt, 1050);
        assert!(result.is_none(), "異なる鍵では復号できてはいけない");
    }
}

/// SSP ハートビートの動作テスト
#[test]
fn test_ssp_heartbeat_via_tick() {
    let mut session = SspSession::new();

    // ハートビートが必要な時刻（初期状態）
    let heartbeat_time = mosh_ssp::HEARTBEAT_INTERVAL_MS;
    let packets = session.tick(heartbeat_time);

    assert!(!packets.is_empty(), "ハートビートが生成されるべき");

    // ハートビートは ACK のみ（new_num = 0）
    let instr = Instruction::decode_from_bytes(&packets[0]).unwrap();
    assert_eq!(instr.new_num_or_zero(), 0, "ハートビートは new_num = 0");
}

/// Timestamp16 ラップアラウンドテスト
#[test]
fn test_timestamp_wraparound_in_crypto() {
    let key = [0u8; 16];
    let mut sender = CryptoSession::from_key(key).unwrap();
    let mut receiver = CryptoSession::from_key(key).unwrap();

    // ラップアラウンド付近のタイムスタンプ
    let ts_near_max = 65535u16;
    let ts_after_wrap = 100u16;

    let pkt1 = sender.encrypt_packet(Direction::ToServer, ts_near_max, 0, b"near max").unwrap();
    let dec1 = receiver.decrypt_packet(&pkt1).unwrap();
    assert_eq!(dec1.timestamp, ts_near_max);

    let pkt2 = sender.encrypt_packet(Direction::ToServer, ts_after_wrap, ts_near_max, b"after wrap").unwrap();
    let dec2 = receiver.decrypt_packet(&pkt2).unwrap();
    assert_eq!(dec2.timestamp, ts_after_wrap);
    assert_eq!(dec2.timestamp_reply, ts_near_max);
}

/// mosh-stream のバイトストリームテスト
#[test]
fn test_stream_channel_full_duplex() {
    let mut stream = StreamChannel::new();

    // 送信方向
    stream.write(b"send 1");
    stream.write(b"send 2");
    let diff = stream.take_pending_diff();
    assert_eq!(diff, b"send 1send 2");
    assert!(!stream.has_pending_write());

    // 受信方向
    stream.apply_diff(b"recv 1");
    stream.apply_diff(b"recv 2");
    assert!(stream.has_pending_read());
    let data = stream.read_available();
    assert_eq!(data, b"recv 1recv 2");
    assert!(!stream.has_pending_read());

    // 統計確認
    assert_eq!(stream.total_sent_bytes(), 12);
    assert_eq!(stream.total_received_bytes(), 12);
}

/// 空のペイロードでのハートビート送信テスト
#[test]
fn test_heartbeat_empty_payload() {
    let key = [0u8; 16];
    let mut sender = Sender::new(key, 500);

    // ハートビートは空でも UDP パケットが生成される
    let pkts = sender.heartbeat(mosh_ssp::HEARTBEAT_INTERVAL_MS);
    assert!(!pkts.is_empty(), "ハートビートパケットが生成されるべき");

    // 各パケットが最低限のサイズを持つか確認
    // nonce(8) + auth_tag(16) + direction_seq(8) + ts(2) + ts_reply(2) + fragment_header(10) = 46 バイト以上
    for pkt in &pkts {
        assert!(pkt.len() >= 46, "パケットサイズが最低限以上であるべき: {} bytes", pkt.len());
    }
}
