use ark_bls12_377::Fq;
use ark_ec::{
    short_weierstrass_jacobian::GroupAffine as SWGroupAffine,
    twisted_edwards_extended::GroupAffine as TEGroupAffine,
};
use ark_ff::{field_new, BigInteger, One, PrimeField};

pub fn bits_to_fields<F: PrimeField>(bits: &[bool]) -> Vec<F> {
    bits.chunks((F::size_in_bits() - 1) as usize)
        .map(|elt| F::from_repr(<F as PrimeField>::BigInt::from_bits_le(elt)).unwrap())
        .collect()
}

// warning! Works only for bls12_377
pub fn ws_to_te(
    p: SWGroupAffine<ark_bls12_377::g1::Parameters>,
) -> TEGroupAffine<ark_bls12_377::g1::Parameters> {
    // values available in https://github.com/arkworks-rs/curves/blob/master/bls12_377/src/curves/g1.rs
    let x = p.x;
    let y = p.y;
    let alpha = -Fq::one();
    let s = field_new!(Fq, "10189023633222963290707194929886294091415157242906428298294512798502806398782149227503530278436336312243746741931");
    let sqrt_te1a = field_new!(Fq, "23560188534917577818843641916571445935985386319233886518929971599490231428764380923487987729215299304184915158756");
    let x_te = (x - alpha) * sqrt_te1a / y;
    let y_te = (s * (x - alpha) - Fq::one()) / (s * (x - alpha) + Fq::one());
    TEGroupAffine::<ark_bls12_377::g1::Parameters>::new(x_te, y_te)
}
