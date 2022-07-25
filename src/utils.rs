use ark_bls12_381_new::{Fq, g1::self, G1Projective};
use ark_ec::{
    short_weierstrass_jacobian::GroupAffine as SWGroupAffine,
    twisted_edwards_extended::GroupAffine as TEGroupAffine, TEModelParameters, ProjectiveCurve,
};
use ark_ff::{field_new, BigInteger, One, PrimeField, UniformRand};
use ark_std::test_rng;

pub fn bits_to_fields<F: PrimeField>(bits: &[bool]) -> Vec<F> {
    bits.chunks((F::size_in_bits() - 1) as usize)
        .map(|elt| F::from_repr(<F as PrimeField>::BigInt::from_bits_le(elt)).unwrap())
        .collect()
}

// warning! Works only for bls12_381_new
pub fn ws_to_te(
    p: SWGroupAffine<ark_bls12_381_new::g1::Parameters>,
) -> TEGroupAffine<ark_bls12_381_new::g1::Parameters> {
    /*
    Wikipedia provides a WS->M and M->TE conversion.
    Here we provide the WS -> TE conversion with few simpliciations.

    (a and b are coefficients of the curve)
    α = sqrt(x**3+a*x+b)
    s1 = sqrt(3*α**2+a)
    s2 = sqrt(3*α+2*s1)
    coeff = (3*α-2*s1)/(3*α+2*s1)

    u = (x-α) * s2 / y
    v = (x-α-s1) / (x-α+s1)
    (u,v) satisfies u**2 + v**2 == 1 + coeff * u**2 * v**2


    In the case of bls12_381_new:
    α = -1
    s1 = sqrt(3)
    s2 = sqrt(-3+2*sqrt(3))
    coeff = (-3-2*sqrt(3)) / (-3+2*sqrt(3))
    u = (x+1) * s2 / y
    v = (x+1-s1) / (x+1+s1)
    */
    let alpha = -Fq::one();
    let s1 = field_new!(Fq, "611336158540232733028115263714465872671465435137168183916056024884978835858365189946006184892099852878171309395862");
    let s2 = field_new!(Fq, "1064881461568443305175032400733120695040834941031583268014086210056237636385831065297199936964360836443404508126238");
    TEGroupAffine::<ark_bls12_381_new::g1::Parameters>::new((p.x-alpha) * s2 / p.y, (p.x-alpha-s1) / (p.x-alpha+s1))
}

#[test]
fn test_ws_to_te() {
    // todo test here
    let mut rng = test_rng();
    for _ in 0..100 {
        let p_ws: SWGroupAffine<g1::Parameters> = G1Projective::rand(&mut rng).into_affine();
        let p_te = ws_to_te(p_ws);
        let x = p_te.x;
        let y = p_te.y;
        let a = <g1::Parameters as TEModelParameters>::COEFF_A;
        let d = <g1::Parameters as TEModelParameters>::COEFF_D;
        assert_eq!(a*x*x + y*y, Fq::one() + d * x*x*y*y);
    }
}
