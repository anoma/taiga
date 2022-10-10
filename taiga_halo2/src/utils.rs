use bitvec::macros::internal::funty::Numeric;
use ff::{PrimeField, BitViewSized, PrimeFieldBits};
use group::GroupEncoding;
use halo2_gadgets::poseidon::primitives as poseidon;
use halo2_proofs::arithmetic::CurveAffine;
use pasta_curves::pallas;
use ff::Field;

use crate::circuit::circuit_parameters::CircuitParameters;

/// Converts from pallas::Base to pallas::Scalar (aka $x \pmod{r_\mathbb{P}}$).
///
/// This requires no modular reduction because Pallas' base field is smaller than its
/// scalar field.
pub(crate) fn mod_r_p<CP: CircuitParameters>(x: CP::CurveScalarField) -> CP::InnerCurveScalarField {
  
    // let mut res = [0; 32];
    // res[0..8].copy_from_slice(&tmp.0[0].to_le_bytes());
    // res[8..16].copy_from_slice(&tmp.0[1].to_le_bytes());
    // res[16..24].copy_from_slice(&tmp.0[2].to_le_bytes());
    // res[24..32].copy_from_slice(&tmp.0[3].to_le_bytes());

    // res
    let a = x.to_repr();
    let a2: <<CP as CircuitParameters>::InnerCurveScalarField as PrimeField>::Repr = a.try_into().unwrap();
    let b = CP::InnerCurveScalarField::from_repr(a);
    CP::InnerCurveScalarField::from_repr(x.to_repr()).unwrap()
}

/// Coordinate extractor for Pallas.
///
/// Defined in [Zcash Protocol Spec § 5.4.9.7: Coordinate Extractor for Pallas][concreteextractorpallas].
///
/// [concreteextractorpallas]: https://zips.z.cash/protocol/nu5.pdf#concreteextractorpallas
pub(crate) fn extract_p<CP: CircuitParameters>(point: &CP::InnerCurve) -> CP::CurveScalarField {
    point
        .coordinates()
        .map(|c| *c.x())
        .unwrap_or_else(CP::CurveScalarField::zero)
}

/// $PRF^\mathsf{nfOrchard}(nk, \rho) := Poseidon(nk, \rho)$
///
/// Defined in [Zcash Protocol Spec § 5.4.2: Pseudo Random Functions][concreteprfs].
///
/// [concreteprfs]: https://zips.z.cash/protocol/nu5.pdf#concreteprfs
pub(crate) fn prf_nf<CP: CircuitParameters>(nk: CP::CurveScalarField, rho: CP::CurveScalarField) -> CP::CurveScalarField {
    poseidon_hash::<CP>(nk, rho)
}

pub(crate) fn poseidon_hash<CP: CircuitParameters>(left: CP::CurveScalarField, right: CP::CurveScalarField) -> CP::CurveScalarField {
    poseidon::Hash::<_, CP::PoseionParamsCurveScalarField, poseidon::ConstantLength<2>, 3, 2>::init()
        .hash([left, right])
}
