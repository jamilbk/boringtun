# Interestun transport cipher extension

Based on firezone/boringtun d76a1cb23af9f2b0020d5f6a1de7d95c1989fc4f.

`Tunn::new_with_cipher_at` accepts `noise::cipher::CipherSuite`:

- `ChaCha20Poly1305`: unchanged WireGuard transcript and transport; existing
  constructors keep this default for source/protocol compatibility.
- `Aes256Gcm`: AES-256-GCM transport using ring's runtime-dispatched implementation.
  Handshake encryption remains ChaCha20-Poly1305 and cookies remain XChaCha20.
  A distinct versioned initial chaining key binds the AES transport choice into
  the authenticated Noise transcript and key derivation. No negotiation or fallback.
  Both endpoints must use this extension. This is not the WireGuard protocol.

AES uses WireGuard's 96-bit nonce encoding (four zero bytes, then the little-endian
64-bit record counter), direction-specific keys, 16-byte tags, and existing replay
protection. AES stops normal encapsulation at 2^23 records to request rekey and
rejects sealing/opening counters >= 2^24. Records are bounded to 65535 plaintext
bytes. Existing time-based session expiry and rekey rules remain in place.
Applications using the sans-I/O API must initiate a handshake on NoCurrentSession.

The AES protocol extension is experimental, not independently audited. Its GCM
usage bounds and protocol transcript require review before production use.

Run `cargo test -p boringtun`, and also `cargo test -p boringtun
--no-default-features`. New tests cover both suites, replay, tampering, suite
mismatch, and the AES counter boundary; the existing tests cover WireGuard mode.
