//! Argon2id (RFC 9106): master password → key-encryption key (PRD 04, «Почему Argon2id»).

use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, Params, Version};

use crate::error::{Result, VaultError};
use crate::secret::{Key, KEY_LEN};

pub const SALT_LEN: usize = 16;

/// Argon2id cost: memory in KiB, passes, lanes. Written into the vault header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl KdfParams {
    /// What a new vault starts from before calibration (PRD 04): 256 MiB, 3 passes, 4 lanes.
    pub const DEFAULT: Self = Self { m_kib: 256 * 1024, t: 3, p: 4 };
    /// Never below this in a vault the app creates or opens: 64 MiB, 3 passes — above RFC 9106's
    /// second recommended option.
    pub const MINIMUM: Self = Self { m_kib: 64 * 1024, t: 3, p: 1 };
    /// Upper bounds, so a crafted header cannot make opening a file take hours or all memory.
    pub const MAXIMUM: Self = Self { m_kib: 4 * 1024 * 1024, t: 64, p: 16 };
    /// Cheap parameters for test vectors and tests (8 MiB, 1 pass). Accepted only with the
    /// `testing` feature, which the app never builds with.
    #[cfg(feature = "testing")]
    pub const TEST_ONLY: Self = Self { m_kib: 8 * 1024, t: 1, p: 1 };

    #[cfg(not(feature = "testing"))]
    const FLOOR: Self = Self::MINIMUM;
    #[cfg(feature = "testing")]
    const FLOOR: Self = Self::TEST_ONLY;

    pub fn check(&self) -> Result<()> {
        let within = |value: u32, low: u32, high: u32| (low..=high).contains(&value);
        let ok = within(self.m_kib, Self::FLOOR.m_kib, Self::MAXIMUM.m_kib)
            && within(self.t, Self::FLOOR.t, Self::MAXIMUM.t)
            && within(self.p, Self::FLOOR.p, Self::MAXIMUM.p)
            // Argon2 needs at least 8 KiB of memory per lane.
            && self.m_kib >= 8 * self.p;
        if ok {
            Ok(())
        } else {
            Err(VaultError::InvalidKdfParams)
        }
    }
}

/// KEK = Argon2id(password, salt), 32 bytes. `params` must have passed `check`.
pub fn derive_kek(password: &[u8], salt: &[u8; SALT_LEN], params: KdfParams) -> Result<Key> {
    params.check()?;
    let argon_params = Params::new(params.m_kib, params.t, params.p, Some(KEY_LEN))
        .map_err(|_| VaultError::InvalidKdfParams)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut kek = Key::zeroed();
    argon.hash_password_into(password, salt, kek.expose_mut()).map_err(|_| VaultError::InvalidKdfParams)?;
    Ok(kek)
}

/// Parameters that take about `target` on this Mac (PRD 04: 0.5–1.0 s — a hypothesis), never
/// below `MINIMUM`. Starts from `DEFAULT`: adds passes while there is time left, halves the
/// memory (down to the minimum) when even 3 passes are too slow. Takes a few seconds.
pub fn calibrate(target: Duration) -> KdfParams {
    let salt = [0u8; SALT_LEN];
    let time = |params: KdfParams| {
        let started = Instant::now();
        // Valid parameters by construction; the result is thrown away.
        let _ = derive_kek(b"calibration", &salt, params);
        started.elapsed()
    };

    let mut params = KdfParams::DEFAULT;
    let mut elapsed = time(params);
    while elapsed > target * 2 && params.m_kib / 2 >= KdfParams::MINIMUM.m_kib {
        params.m_kib /= 2;
        elapsed = time(params);
    }
    // Time grows linearly with passes.
    let per_pass = elapsed / params.t;
    while params.t < KdfParams::MAXIMUM.t && elapsed + per_pass <= target {
        params.t += 1;
        elapsed += per_pass;
    }
    params
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameters_outside_the_range_are_refused() {
        assert_eq!(KdfParams::DEFAULT.check(), Ok(()));
        assert_eq!(KdfParams::MINIMUM.check(), Ok(()));
        let too_small = KdfParams { m_kib: 1024, t: 1, p: 1 };
        assert_eq!(too_small.check(), Err(VaultError::InvalidKdfParams));
        let too_big = KdfParams { m_kib: KdfParams::MAXIMUM.m_kib + 1, ..KdfParams::DEFAULT };
        assert_eq!(too_big.check(), Err(VaultError::InvalidKdfParams));
        let no_lanes = KdfParams { p: 0, ..KdfParams::DEFAULT };
        assert_eq!(no_lanes.check(), Err(VaultError::InvalidKdfParams));
    }

    #[test]
    fn the_same_input_gives_the_same_key_and_the_salt_matters() {
        let params = KdfParams::TEST_ONLY;
        let a = derive_kek(b"password", &[1; SALT_LEN], params).unwrap();
        let b = derive_kek(b"password", &[1; SALT_LEN], params).unwrap();
        let c = derive_kek(b"password", &[2; SALT_LEN], params).unwrap();
        assert_eq!(a.expose(), b.expose());
        assert_ne!(a.expose(), c.expose());
    }
}
