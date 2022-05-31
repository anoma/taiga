use crate::poseidon::lfsr::GrainLFSR;
use ark_ff::PrimeField;
/// From the paper
/// THe parameter describes the initial state of constant generation (80-bits)
/// * `field`: description of field. b0, b1
/// * `sbox`: description of s-box. b2..=b5
/// * `field_size`: binary representation of field size. b6..=b17
/// * `t`: binary representation of t. b18..=b29
/// * `rf`: binary representation of rf. b30..=b39
/// * `rp`: binary representation of rp. b40..=b49
/// * `ones`: set to 1. b50..=b79
/// return round constants, and return the LFSR used to generate MDS matrix
pub fn generate_round_constants<F: PrimeField>(
    prime_num_bits: u64,
    width: usize,
    r_f: usize,
    r_p: usize,
) -> (Vec<F>, GrainLFSR) {
    let num_constants = (r_f + r_p) * width;
    let mut lfsr = GrainLFSR::new(prime_num_bits, width, r_f, r_p);
    (
        lfsr.get_field_elements_rejection_sampling(num_constants),
        lfsr,
    )
}
