//! Explicit transport cipher selection. There is no negotiation or fallback.
//! ChaCha retains the WireGuard transcript; AES has a versioned, distinct transcript.
use ring::aead::{Algorithm, AES_256_GCM, CHACHA20_POLY1305};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CipherSuite {
    #[default]
    ChaCha20Poly1305,
    Aes256Gcm,
}

impl CipherSuite {
    pub(crate) fn algorithm(self) -> &'static Algorithm {
        match self {
            Self::ChaCha20Poly1305 => &CHACHA20_POLY1305,
            Self::Aes256Gcm => &AES_256_GCM,
        }
    }

    // Bound GCM invocations per session, independent of the time-based rekey timer.
    // At most 2^24 records of <= 65535 bytes; rekey begins well before this limit.
    pub(crate) fn message_limit(self) -> u64 {
        match self {
            Self::ChaCha20Poly1305 => u64::MAX - (1 << 13),
            Self::Aes256Gcm => 1 << 24,
        }
    }
}
