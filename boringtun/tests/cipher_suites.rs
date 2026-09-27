use boringtun::{
    noise::{cipher::CipherSuite, Index, Tunn, TunnResult},
    x25519::{PublicKey, StaticSecret},
};
use std::time::{Duration, Instant};
fn tunnel(secret: u8, peer: u8, cipher: CipherSuite, now: Instant) -> Tunn {
    Tunn::new_with_cipher_at(
        StaticSecret::from([secret; 32]),
        PublicKey::from(&StaticSecret::from([peer; 32])),
        None,
        None,
        Index::new_local(secret as u32),
        None,
        1,
        now,
        now,
        Duration::from_secs(1_700_000_000),
        cipher,
    )
}
fn network(result: TunnResult<'_>) -> Vec<u8> {
    match result {
        TunnResult::WriteToNetwork(p) => p.to_vec(),
        other => panic!("expected network: {other:?}"),
    }
}
#[test]
fn both_suites_handshake_transport_replay_and_tamper() {
    for suite in [CipherSuite::Aes256Gcm, CipherSuite::ChaCha20Poly1305] {
        let now = Instant::now();
        let mut a = tunnel(1, 2, suite, now);
        let mut b = tunnel(2, 1, suite, now);
        let mut buf = [0; 2048];
        // Use a deterministic time origin for the handshake and transport.
        let init = network(a.format_handshake_initiation_at(&mut buf, false, now));
        let later = now + Duration::from_secs(1);
        let response = network(b.decapsulate_at(None, &init, &mut buf, later));
        let confirm = network(a.decapsulate_at(None, &response, &mut buf, later));
        assert!(matches!(
            b.decapsulate_at(None, &confirm, &mut buf, later),
            TunnResult::Done
        ));
        let mut ip = [0u8; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&20u16.to_be_bytes());
        ip[12..16].copy_from_slice(&[10, 0, 0, 1]);
        ip[16..20].copy_from_slice(&[10, 0, 0, 2]);
        let len = a.encapsulate_data_at(&ip, &mut buf, later).unwrap();
        let packet = buf[..len].to_vec();
        let mut damaged = packet.clone();
        *damaged.last_mut().unwrap() ^= 1;
        assert!(matches!(
            b.decapsulate_at(None, &damaged, &mut buf, later),
            TunnResult::Err(_)
        ));
        match b.decapsulate_at(None, &packet, &mut buf, later) {
            TunnResult::WriteToTunnelV4(p, _) => assert_eq!(p, ip),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            b.decapsulate_at(None, &packet, &mut buf, later),
            TunnResult::Err(_)
        ));
    }
}
#[test]
fn mismatched_suite_fails_handshake() {
    let now = Instant::now();
    let mut a = tunnel(1, 2, CipherSuite::Aes256Gcm, now);
    let mut b = tunnel(2, 1, CipherSuite::ChaCha20Poly1305, now);
    let mut buf = [0; 2048];
    let init = network(a.format_handshake_initiation_at(&mut buf, false, now));
    let later = now + Duration::from_secs(1);
    assert!(matches!(
        b.decapsulate_at(None, &init, &mut buf, later),
        TunnResult::Err(_)
    ));
}

#[test]
fn in_place_transport_preserves_tunnel_semantics() {
    use boringtun::noise::errors::WireGuardError;
    for suite in [CipherSuite::Aes256Gcm, CipherSuite::ChaCha20Poly1305] {
        let now = Instant::now();
        let mut a = tunnel(1, 2, suite, now);
        let mut b = tunnel(2, 1, suite, now);
        let mut buf = [0x42; 2048];
        assert!(matches!(
            a.encapsulate_data_in_place_at(20, &mut buf, now),
            Err(WireGuardError::NoCurrentSession)
        ));
        assert_eq!(buf, [0x42; 2048]);
        let init = network(a.format_handshake_initiation_at(&mut buf, false, now));
        let mut wrong_kind = init.clone();
        assert!(matches!(
            b.decapsulate_data_in_place_at(&mut wrong_kind, now),
            TunnResult::Err(WireGuardError::UnexpectedPacket)
        ));
        let response = network(b.decapsulate_at(None, &init, &mut buf, now));
        let mut confirm = network(a.decapsulate_at(None, &response, &mut buf, now));
        assert!(matches!(
            b.decapsulate_data_in_place_at(&mut confirm, now),
            TunnResult::Done
        ));
        for v6 in [false, true] {
            let len: usize = if v6 { 52 } else { 32 };
            let mut ip = vec![0; len];
            ip[0] = if v6 { 0x60 } else { 0x45 };
            if v6 {
                ip[4..6].copy_from_slice(&12u16.to_be_bytes());
            } else {
                ip[2..4].copy_from_slice(&(len as u16).to_be_bytes());
            }
            buf[16..16 + len].copy_from_slice(&ip);
            let n = a.encapsulate_data_in_place_at(len, &mut buf, now).unwrap();
            let mut encrypted = buf[..n].to_vec();
            let mut bad_tag = encrypted.clone();
            *bad_tag.last_mut().unwrap() ^= 1;
            let before = b.stats_at(now);
            assert!(matches!(
                b.decapsulate_data_in_place_at(&mut bad_tag, now),
                TunnResult::Err(_)
            ));
            assert_eq!(b.stats_at(now).2, before.2);
            let ptr = buf[16..].as_ptr();
            match b.decapsulate_data_in_place_at(&mut buf[..n], now) {
                TunnResult::WriteToTunnelV4(p, _) | TunnResult::WriteToTunnelV6(p, _) => {
                    assert_eq!(p, ip);
                    assert_eq!(p.as_ptr(), ptr);
                }
                other => panic!("{other:?}"),
            }
            assert_eq!(b.stats_at(now).2, before.2 + len);
            assert!(matches!(
                b.decapsulate_data_in_place_at(&mut encrypted, now),
                TunnResult::Err(_)
            ));
            // The unchanged API still interoperates in the other direction.
            let n = b.encapsulate_data_at(&ip, &mut buf, now).unwrap();
            assert!(matches!(
                a.decapsulate_data_in_place_at(&mut buf[..n], now),
                TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _)
            ));
        }
        for len in 0..32 {
            assert!(matches!(
                b.decapsulate_data_in_place_at(&mut [0u8; 32][..len], now),
                TunnResult::Err(_)
            ));
        }
    }
}
