use ff::{Field, PrimeField};
use halo2_gadgets::poseidon::primitives::{self as poseidon, P128Pow5T3, Spec};
use halo2_proofs::arithmetic::CurveAffine;

use crate::circuit::circuit_parameters::CircuitParameters;

/// Converts from CP::CurveScalarField to CP::InnerCurveScalarField (aka $x \pmod{r_\mathbb{P}}$).
///
/// This requires no modular reduction because Pallas' base field is smaller than its
/// scalar field.
pub(crate) fn mod_r_p<CP: CircuitParameters>(x: CP::CurveScalarField) -> CP::CurveScalarField {
    CP::CurveScalarField::from_repr(x.to_repr()).unwrap()
}

/// Coordinate extractor for Pallas.
///
/// Defined in [Zcash Protocol Spec § 5.4.9.7: Coordinate Extractor for Pallas][concreteextractorpallas].
///
/// [concreteextractorpallas]: https://zips.z.cash/protocol/nu5.pdf#concreteextractorpallas
pub(crate) fn extract_p<CP: CircuitParameters>(
    point: &CP::InnerCurve,
) -> <CP::InnerCurve as CurveAffine>::Base {
    point
        .coordinates()
        .map(|c| *c.x())
        .unwrap_or_else(<CP::InnerCurve as CurveAffine>::Base::zero)
}

/// $PRF^\mathsf{nfOrchard}(nk, \rho) := Poseidon(nk, \rho)$
///
/// Defined in [Zcash Protocol Spec § 5.4.2: Pseudo Random Functions][concreteprfs].
///
/// [concreteprfs]: https://zips.z.cash/protocol/nu5.pdf#concreteprfs
pub(crate) fn prf_nf<CP: CircuitParameters>(
    nk: CP::CurveScalarField,
    rho: CP::CurveScalarField,
) -> CP::CurveScalarField
where
    P128Pow5T3: Spec<<CP as CircuitParameters>::CurveScalarField, 3_usize, 2_usize>,
{
    poseidon_hash::<CP>(nk, rho)
}

pub(crate) fn poseidon_hash<CP: CircuitParameters>(
    left: CP::CurveScalarField,
    right: CP::CurveScalarField,
) -> CP::CurveScalarField
where
    P128Pow5T3: Spec<<CP as CircuitParameters>::CurveScalarField, 3_usize, 2_usize>,
{
    poseidon::Hash::<_, poseidon::P128Pow5T3, poseidon::ConstantLength<2>, 3, 2>::init()
        .hash([left, right])
}
