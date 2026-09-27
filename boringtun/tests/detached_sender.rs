use boringtun::{
    noise::{cipher::CipherSuite, Index, Tunn, TunnResult},
    x25519::{PublicKey, StaticSecret},
};
use std::time::{Duration, Instant};
fn tunnel(a: u8, b: u8, cipher: CipherSuite, now: Instant) -> Tunn {
    Tunn::new_with_cipher_at(
        StaticSecret::from([a; 32]),
        PublicKey::from(&StaticSecret::from([b; 32])),
        None,
        Some(1),
        Index::new_local(a as u32),
        None,
        1,
        now,
        now,
        Duration::from_secs(1700000000),
        cipher,
    )
}
fn wire(r: TunnResult<'_>) -> Vec<u8> {
    match r {
        TunnResult::WriteToNetwork(p) => p.to_vec(),
        other => panic!("{other:?}"),
    }
}
fn pair(cipher: CipherSuite, now: Instant) -> (Tunn, Tunn) {
    let (mut a, mut b) = (tunnel(1, 2, cipher, now), tunnel(2, 1, cipher, now));
    let mut out = [0; 2048];
    let init = wire(a.format_handshake_initiation_at(&mut out, false, now));
    let response = wire(b.decapsulate_at(None, &init, &mut out, now));
    let mut confirm = wire(a.decapsulate_at(None, &response, &mut out, now));
    assert!(matches!(
        b.decapsulate_data_in_place_at(&mut confirm, now),
        TunnResult::Done
    ));
    (a, b)
}
fn ip() -> [u8; 20] {
    let mut p = [0; 20];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&20u16.to_be_bytes());
    p
}
#[test]
fn exclusive_nonce_handoff_and_revocation() {
    for cipher in [CipherSuite::Aes256Gcm, CipherSuite::ChaCha20Poly1305] {
        let now = Instant::now();
        let (mut a, mut b) = pair(cipher, now);
        let mut tx = a.take_transport_sender().unwrap();
        assert!(a.take_transport_sender().is_none());
        let mut out = [0; 2048];
        out[16..36].copy_from_slice(&ip());
        assert!(a.encapsulate_data_in_place_at(20, &mut out, now).is_err());
        let n = tx.encapsulate_in_place_at(20, &mut out, now).unwrap();
        assert_eq!(u64::from_le_bytes(out[8..16].try_into().unwrap()), 1); // confirmation used zero
        let mut replay = out[..n].to_vec();
        assert!(matches!(
            b.decapsulate_data_in_place_at(&mut out[..n], now),
            TunnResult::WriteToTunnelV4(..)
        ));
        assert!(matches!(
            b.decapsulate_data_in_place_at(&mut replay, now),
            TunnResult::Err(_)
        ));
        drop(a);
        assert!(!tx.is_valid_at(now));
        assert!(tx.encapsulate_in_place_at(0, &mut out, now).is_err());
    }
}
#[test]
fn duplex_transport_and_deferred_keepalives() {
    for cipher in [CipherSuite::Aes256Gcm, CipherSuite::ChaCha20Poly1305] {
        let now = Instant::now();
        let (mut a, mut b) = pair(cipher, now);
        let mut ta = a.take_transport_sender().unwrap();
        let mut tb = b.take_transport_sender().unwrap();
        let (abtx, abrx) = std::sync::mpsc::sync_channel::<Vec<u8>>(32);
        let (batx, barx) = std::sync::mpsc::sync_channel::<Vec<u8>>(32);
        std::thread::scope(|s| {
            s.spawn(move || {
                for _ in 0..512 {
                    let mut p = vec![0; 52];
                    p[16..36].copy_from_slice(&ip());
                    ta.encapsulate_in_place_at(20, &mut p, now).unwrap();
                    abtx.send(p).unwrap();
                }
            });
            s.spawn(move || {
                for _ in 0..512 {
                    let mut p = vec![0; 52];
                    p[16..36].copy_from_slice(&ip());
                    tb.encapsulate_in_place_at(20, &mut p, now).unwrap();
                    batx.send(p).unwrap();
                }
            });
            s.spawn(|| {
                for mut p in abrx {
                    assert!(matches!(
                        b.decapsulate_data_in_place_at(&mut p, now),
                        TunnResult::WriteToTunnelV4(..)
                    ));
                }
            });
            s.spawn(|| {
                for mut p in barx {
                    assert!(matches!(
                        a.decapsulate_data_in_place_at(&mut p, now),
                        TunnResult::WriteToTunnelV4(..)
                    ));
                }
            });
        });
        a.record_external_send(512 * 20, now, Some(now), Some(now));
        assert_eq!(a.stats_at(now).1, 512 * 20);
        assert_eq!(a.stats_at(now).2, 512 * 20);
        let mut out = [0; 2048];
        assert!(matches!(
            a.update_timers_at(&mut out, now + Duration::from_secs(1)),
            TunnResult::Done
        ));
        assert!(a.take_external_keepalive());
        assert!(!a.take_external_keepalive());
    }
}
#[test]
fn expiry_without_timer_driver_and_timer_revocation() {
    for cipher in [CipherSuite::Aes256Gcm, CipherSuite::ChaCha20Poly1305] {
        let now = Instant::now();
        let (mut a, mut b) = pair(cipher, now);
        let mut ta = a.take_transport_sender().unwrap();
        let mut tb = b.take_transport_sender().unwrap();
        let mut out = [0; 2048];
        assert!(ta
            .encapsulate_in_place_at(0, &mut out, now + Duration::from_secs(171))
            .is_err());
        assert!(tb
            .encapsulate_in_place_at(0, &mut out, now + Duration::from_secs(179))
            .is_ok());
        assert!(tb
            .encapsulate_in_place_at(0, &mut out, now + Duration::from_secs(180))
            .is_err());
        let _ = b.update_timers_at(&mut out, now + Duration::from_secs(181));
        assert!(!tb.is_valid_at(now)); // revocation is independent of caller timestamp
    }
}

#[test]
fn rekey_handoff_preserves_nonce_and_retires_old_keys() {
    for cipher in [CipherSuite::Aes256Gcm, CipherSuite::ChaCha20Poly1305] {
        let now = Instant::now();
        let (mut a, mut b) = pair(cipher, now);
        let old = a.take_transport_sender().unwrap();
        let mut out = [0; 2048];
        // More than the receive ring capacity, ensuring replacement revokes
        // the oldest detached key even if its owner has not tried to send.
        for round in 1..=10 {
            let at = now + Duration::from_secs(round * 2);
            let init = wire(a.format_handshake_initiation_at(&mut out, false, at));
            let response = wire(b.decapsulate_at(None, &init, &mut out, at));
            let mut confirm = wire(a.decapsulate_at(None, &response, &mut out, at));
            assert!(matches!(
                b.decapsulate_data_in_place_at(&mut confirm, at),
                TunnResult::Done
            ));
            let mut tx = a.take_transport_sender().unwrap();
            out[16..36].copy_from_slice(&ip());
            let n = tx.encapsulate_in_place_at(20, &mut out, at).unwrap();
            assert_eq!(u64::from_le_bytes(out[8..16].try_into().unwrap()), 1);
            assert!(matches!(
                b.decapsulate_data_in_place_at(&mut out[..n], at),
                TunnResult::WriteToTunnelV4(..)
            ));
        }
        assert!(!old.is_valid_at(now));
    }
}

#[test]
fn timer_keepalive_uses_detached_nonce_owner() {
    for cipher in [CipherSuite::Aes256Gcm, CipherSuite::ChaCha20Poly1305] {
        let now = Instant::now();
        let (mut a, mut b) = pair(cipher, now);
        let mut sender = a.take_transport_sender().unwrap();
        let mut out = [0; 2048];
        let at = now + Duration::from_secs(1);
        assert!(matches!(a.update_timers_at(&mut out, at), TunnResult::Done));
        assert!(a.take_external_keepalive());
        let n = sender.encapsulate_in_place_at(0, &mut out, at).unwrap();
        assert_eq!(u64::from_le_bytes(out[8..16].try_into().unwrap()), 1);
        a.record_external_send(0, at, None, None);
        assert!(matches!(
            b.decapsulate_data_in_place_at(&mut out[..n], at),
            TunnResult::Done
        ));
        assert_eq!(a.stats_at(at).1, 0);
    }
}
