//! `ghost-t2-join`: the analyzer of the T2 unlinkability exit gate (Phase 8 design §1.3, §13.4,
//! §19.16). It consumes the complete issuer view (every request and response with exact times and
//! circuit labels, the wallet history, every database row and journal entry) and the complete view
//! of every relay (every call, capture event and nullifier-store row), and runs:
//!
//! - the deterministic join search J1–J10, T2b and T2c (any hit fails T2);
//! - the statistical tests S1–S3 at α = 0.001 against the declared leak L1–L7, and the absolute
//!   bound S4 (Q21: top-1 accuracy of the declared-leak attacker ≤ 0.25, always reported).
//!
//! Ground truth (which client made a call, which runs were quiet, the seeds of each flow) is used
//! only for scoring and for the checks stated over it (J6, J8, J9, T2c); the searches J1–J5 and
//! T2b see the adversary's views only.

pub mod accumulate;
pub mod checks;
pub mod model;
pub mod numbers;
pub mod public;
pub mod stats;
pub mod transforms;
pub mod values;
