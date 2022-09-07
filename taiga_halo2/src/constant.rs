use ff::PrimeField;
use group::Curve;
use halo2_gadgets::ecc::chip::constants::{find_zs_and_us, H, NUM_WINDOWS};
use halo2_gadgets::sinsemilla::primitives::CommitDomain;
use lazy_static::lazy_static;
use pasta_curves::pallas;

/// SWU hash-to-curve personalization for the note commitment generator
pub const NOTE_COMMITMENT_PERSONALIZATION: &str = "Taiga-NoteCommit";

/// Commitment merkle tree depth
pub const TAIGA_COMMITMENT_TREE_DEPTH: usize = 32;

pub const BASE_BITS_NUM: usize = 255;

// SinsemillaCommit parameters
// TODO: use constants to replace the lazy_static
lazy_static! {
    pub static ref NOTE_COMMIT_DOMAIN: CommitDomain =
        CommitDomain::new(NOTE_COMMITMENT_PERSONALIZATION);
    pub static ref NOTE_COMMITMENT_GENERATOR: pallas::Affine = NOTE_COMMIT_DOMAIN.Q().to_affine();
    pub static ref NOTE_COMMITMENT_R_GENERATOR: pallas::Affine = NOTE_COMMIT_DOMAIN.R().to_affine();
    pub static ref R_ZS_AND_US: Vec<(u64, [pallas::Base; H])> =
        find_zs_and_us(*NOTE_COMMITMENT_R_GENERATOR, NUM_WINDOWS).unwrap();
    pub static ref R_U: Vec<[[u8; 32]; H]> = R_ZS_AND_US
        .iter()
        .map(|(_, us)| {
            [
                us[0].to_repr(),
                us[1].to_repr(),
                us[2].to_repr(),
                us[3].to_repr(),
                us[4].to_repr(),
                us[5].to_repr(),
                us[6].to_repr(),
                us[7].to_repr(),
            ]
        })
        .collect();
    pub static ref R_Z: Vec<u64> = R_ZS_AND_US.iter().map(|(z, _)| *z).collect();
}
