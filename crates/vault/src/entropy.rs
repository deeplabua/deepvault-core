//! Where randomness and the time come from: the system, or — for test vectors only — a
//! script of fixed values.

use std::time::{SystemTime, UNIX_EPOCH};

pub trait Entropy: Send {
    /// Fills `buf` with cryptographically secure random bytes.
    fn fill(&mut self, buf: &mut [u8]);
    /// Seconds since the Unix epoch.
    fn now(&self) -> u64;
}

/// `getentropy` on macOS, through `getrandom`; the wall clock.
pub struct SystemEntropy;

impl Entropy for SystemEntropy {
    fn fill(&mut self, buf: &mut [u8]) {
        // The system source does not fail on macOS; without it no key can be made.
        getrandom::fill(buf).expect("the system random source is unavailable");
    }

    fn now(&self) -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
    }
}

/// Hands out the given byte strings in order, each to a request of exactly its length, and
/// a fixed time. Panics when the script and the requests disagree: a test vector that no
/// longer describes what the code does must fail loudly.
#[cfg(feature = "testing")]
pub struct ScriptedEntropy {
    chunks: std::collections::VecDeque<Vec<u8>>,
    now: u64,
}

#[cfg(feature = "testing")]
impl ScriptedEntropy {
    pub fn new(chunks: Vec<Vec<u8>>, now: u64) -> Self {
        Self { chunks: chunks.into(), now }
    }

    pub fn is_exhausted(&self) -> bool {
        self.chunks.is_empty()
    }
}

#[cfg(feature = "testing")]
impl Entropy for ScriptedEntropy {
    fn fill(&mut self, buf: &mut [u8]) {
        let chunk = self.chunks.pop_front().expect("the entropy script ran out");
        assert_eq!(chunk.len(), buf.len(), "the entropy script and the request differ in length");
        buf.copy_from_slice(&chunk);
    }

    fn now(&self) -> u64 {
        self.now
    }
}
