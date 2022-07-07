use ark_ff::{BigInteger, PrimeField};


pub fn bits_to_fields<F: PrimeField>(bits: &[bool]) -> Vec<F> {
    bits.chunks((F::size_in_bits() - 1) as usize)
        .map(|elt| F::from_repr(<F as PrimeField>::BigInt::from_bits_le(elt)).unwrap())
        .collect()
}

