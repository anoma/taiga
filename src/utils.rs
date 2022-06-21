use ark_ff::PrimeField;

pub fn bytes_to_fields<F: PrimeField>(bytes: Vec<u8>) -> Vec<F> {
    bytes
        .chunks((F::size_in_bits() - 1) / 8 as usize)
        .map(|elt| F::from_le_bytes_mod_order(elt))
        .collect()
}
