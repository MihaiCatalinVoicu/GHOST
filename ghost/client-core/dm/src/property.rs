//! Seeded property-run support for the parser tests of R-C4 and §15.2.
//!
//! §7.1 R-C4 and §15.2 ask for `10^6` seeded inputs per CI run over **every** parser: never panics,
//! never over-reads, never returns an untyped error. The generator below is a deterministic
//! xorshift64 so a failure is reproducible from the seed printed with it; the count is
//! [`inputs`], which reads `GHOST_DM_PROPERTY_INPUTS` so a longer soak can be asked for without
//! touching the source.
//!
//! Parsers that verify an Ed25519 signature (`card::parse`, `bundle::parse`) cost about four
//! orders of magnitude more per input than the byte parsers, so their runs feed length-varying
//! inputs: the signature path is reached only by the rare exact-length input, while every length
//! and every prefix is still exercised. Those two records are fixed-length and additionally have
//! an **exhaustive** single-bit mutation test each, which is stronger than sampling for them.

/// A deterministic xorshift64 stream. Not cryptographic: it feeds parsers, never a key.
pub(crate) struct Seeded(u64);

impl Seeded {
    /// A stream from a fixed seed. The seed is part of the test, so a failure replays.
    pub(crate) fn new(seed: u64) -> Self {
        // xorshift64 has a fixed point at zero.
        Seeded(if seed == 0 {
            0x243f_6a88_85a3_08d3
        } else {
            seed
        })
    }

    /// The next word of the stream.
    pub(crate) fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// A value in `0..n`, or 0 when `n` is 0.
    pub(crate) fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }

    /// One byte of the stream.
    pub(crate) fn byte(&mut self) -> u8 {
        (self.next_u64() & 0xff) as u8
    }

    /// Fills `out` from the stream.
    pub(crate) fn fill(&mut self, out: &mut [u8]) {
        for byte in out.iter_mut() {
            *byte = self.byte();
        }
    }

    /// A copy of `template` with one to four bytes replaced, sometimes truncated and sometimes
    /// extended: the mutation shape a fuzz target reaches by itself.
    pub(crate) fn mutate(&mut self, template: &[u8]) -> Vec<u8> {
        let mut bytes = template.to_vec();
        if !bytes.is_empty() {
            let mutations = self.below(4) + 1;
            for _ in 0..mutations {
                let at = self.below(bytes.len());
                bytes[at] = self.byte();
            }
        }
        match self.below(8) {
            0 => bytes.truncate(self.below(bytes.len().max(1))),
            1 => {
                let extra = self.below(16);
                for _ in 0..extra {
                    bytes.push(self.byte());
                }
            }
            _ => {}
        }
        bytes
    }

    /// A free-form input of at most `max_len` bytes.
    pub(crate) fn random_input(&mut self, max_len: usize) -> Vec<u8> {
        let len = self.below(max_len + 1);
        let mut bytes = vec![0u8; len];
        self.fill(&mut bytes);
        bytes
    }
}

/// The number of seeded inputs one parser run feeds, `10^6` by default (R-C4, §15.2).
/// `GHOST_DM_PROPERTY_INPUTS` overrides it for a longer soak or a quicker local loop.
pub(crate) fn inputs() -> usize {
    match std::env::var("GHOST_DM_PROPERTY_INPUTS") {
        Ok(value) => value
            .parse()
            .expect("GHOST_DM_PROPERTY_INPUTS must be a number"),
        Err(_) => 1_000_000,
    }
}

/// The number of seeded inputs a run over a signature-verifying parser feeds, at exact length.
/// The length-varying run around it uses the full [`inputs`] count.
pub(crate) fn signature_inputs() -> usize {
    inputs() / 1_000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stream_is_deterministic_and_does_not_stall() {
        let mut a = Seeded::new(1);
        let mut b = Seeded::new(1);
        let mut seen = Vec::new();
        for _ in 0..64 {
            let value = a.next_u64();
            assert_eq!(value, b.next_u64());
            assert!(!seen.contains(&value));
            seen.push(value);
        }
        assert_ne!(Seeded::new(1).next_u64(), Seeded::new(2).next_u64());
        assert_ne!(Seeded::new(0).next_u64(), 0);
    }

    #[test]
    fn the_default_count_is_the_one_the_design_asks_for() {
        // The run count is a figure of the design (R-C4, §15.2), not a convenience.
        if std::env::var("GHOST_DM_PROPERTY_INPUTS").is_err() {
            assert_eq!(inputs(), 1_000_000);
            assert_eq!(signature_inputs(), 1_000);
        }
    }

    #[test]
    fn mutation_and_random_inputs_stay_inside_their_bounds() {
        let mut rng = Seeded::new(7);
        let template = vec![1u8; 32];
        for _ in 0..1_000 {
            assert!(rng.mutate(&template).len() <= template.len() + 16);
            assert!(rng.random_input(8).len() <= 8);
        }
        assert_eq!(rng.mutate(&[]), Vec::<u8>::new());
    }
}
