use ark_ec::{TEModelParameters, AffineCurve, twisted_edwards_extended::{GroupAffine, GroupProjective}, ModelParameters};
use ark_std::UniformRand;

pub struct SigningKey<P:TEModelParameters>{
    private_key:  P::ScalarField,
    pub public_key: GroupProjective<P>,
}

impl <P: TEModelParameters> SigningKey<P> {
    pub fn new(s: P::ScalarField) -> Self {
        SigningKey::<P>{
            private_key: s,
            public_key: GroupAffine::<P>::prime_subgroup_generator().mul(s),
        }
    }
}



#[test]
fn test_key_generation() {
    use ark_bls12_377::g1::Parameters as P;
    let mut rng = rand::thread_rng();
    let s = <P as ModelParameters>::ScalarField::rand(&mut rng);
    let key = SigningKey::<P>::new(s);
}