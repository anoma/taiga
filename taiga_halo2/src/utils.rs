use crate::constant::{POSEIDON_TO_FIELD_U_0_POSTFIX, POSEIDON_TO_FIELD_U_1_POSTFIX};
use halo2_gadgets::poseidon::primitives as poseidon;
use halo2_proofs::arithmetic::CurveAffine;
use pasta_curves::{arithmetic::CurveExt, hashtocurve, pallas, group::{Curve, ff::PrimeField}};

/// Converts from pallas::Base to pallas::Scalar (aka $x \pmod{r_\mathbb{P}}$).
///
/// This requires no modular reduction because Pallas' base field is smaller than its
/// scalar field.
pub(crate) fn mod_r_p(x: pallas::Base) -> pallas::Scalar {
    pallas::Scalar::from_repr(x.to_repr()).unwrap()
}

/// Coordinate extractor for Pallas.
///
/// Defined in [Zcash Protocol Spec § 5.4.9.7: Coordinate Extractor for Pallas][concreteextractorpallas].
///
/// [concreteextractorpallas]: https://zips.z.cash/protocol/nu5.pdf#concreteextractorpallas
pub(crate) fn extract_p(point: &pallas::Point) -> pallas::Base {
    point
        .to_affine()
        .coordinates()
        .map(|c| *c.x())
        .unwrap_or_else(pallas::Base::zero)
}

/// $PRF^\mathsf{nfOrchard}(nk, \rho) := Poseidon(nk, \rho)$
///
/// Defined in [Zcash Protocol Spec § 5.4.2: Pseudo Random Functions][concreteprfs].
///
/// [concreteprfs]: https://zips.z.cash/protocol/nu5.pdf#concreteprfs
pub(crate) fn prf_nf(nk: pallas::Base, rho: pallas::Base) -> pallas::Base {
    poseidon_hash(nk, rho)
}

pub fn poseidon_hash(left: pallas::Base, right: pallas::Base) -> pallas::Base {
    poseidon::Hash::<_, poseidon::P128Pow5T3, poseidon::ConstantLength<2>, 3, 2>::init()
        .hash([left, right])
}

pub(crate) fn poseidon_hash_n<const L: usize>(message: [pallas::Base; L]) -> pallas::Base {
    poseidon::Hash::<_, poseidon::P128Pow5T3, poseidon::ConstantLength<L>, 3, 2>::init()
        .hash(message)
}

pub fn poseidon_to_curve<const L: usize>(message: &[pallas::Base]) -> pallas::Point {
    let us = poseidon_to_field::<L>(message);
    let q0 = hashtocurve::map_to_curve_simple_swu::<pallas::Base, pallas::Point, pallas::Iso>(
        &us[0],
        pallas::Point::THETA,
        pallas::Point::Z,
    );
    let q1 = hashtocurve::map_to_curve_simple_swu::<pallas::Base, pallas::Point, pallas::Iso>(
        &us[1],
        pallas::Point::THETA,
        pallas::Point::Z,
    );
    let r = q0 + q1;
    debug_assert!(bool::from(r.is_on_curve()));
    hashtocurve::iso_map::<pallas::Base, pallas::Point, pallas::Iso>(
        &r,
        &pallas::Point::ISOGENY_CONSTANTS,
    )
}

/// Hashes over a message and writes the output to all of `buf`.
fn poseidon_to_field<const L: usize>(message: &[pallas::Base]) -> [pallas::Base; 2] {
    assert!(message.len() + POSEIDON_TO_FIELD_U_0_POSTFIX.len() == L);

    let poseidon =
        poseidon::Hash::<_, poseidon::P128Pow5T3, poseidon::ConstantLength<L>, 3, 2>::init();
    let u_0_inputs = [message, &POSEIDON_TO_FIELD_U_0_POSTFIX].concat();
    let u_0 = poseidon.hash(u_0_inputs.try_into().expect("slice with incorrect length"));

    let poseidon =
        poseidon::Hash::<_, poseidon::P128Pow5T3, poseidon::ConstantLength<L>, 3, 2>::init();
    let u_1_inputs = [message, &POSEIDON_TO_FIELD_U_1_POSTFIX].concat();
    let u_1 = poseidon.hash(u_1_inputs.try_into().expect("slice with incorrect length"));

    [u_0, u_1]
}

pub fn to_field_elements(bytes: &[u8]) -> Vec<pallas::Base> {
    let max_size = ((pallas::Base::NUM_BITS - 1) / 8) as usize;
    bytes
        .chunks(max_size)
        .map(|chunk| {
            let mut field_bytes = [0u8; 32];
            field_bytes.iter_mut().zip(chunk).for_each(|(a, b)| *a = *b);
            pallas::Base::from_repr(field_bytes).unwrap()
        })
        .collect::<Vec<pallas::Base>>()
}
