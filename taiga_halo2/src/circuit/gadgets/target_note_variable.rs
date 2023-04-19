use crate::circuit::vp_circuit::NoteSearchableVariablePair;
use crate::constant::NUM_NOTE;
use halo2_gadgets::utilities::bool_check;
use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Layouter, Region},
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Expression, Selector},
    poly::Rotation,
};
use pasta_curves::pallas;

// Search and get owned note variable
pub fn get_owned_note_variable(
    config: GetOwnedNoteVariableConfig,
    mut layouter: impl Layouter<pallas::Base>,
    // The owned_note_pub_id is the spend_note_nf or the output_note_cm_x
    owned_note_pub_id: &AssignedCell<pallas::Base, pallas::Base>,
    // NUM_NOTE pairs are from spend notes, the other NUM_NOTE are from output notes
    note_variable_pairs: &[NoteSearchableVariablePair; NUM_NOTE * 2],
) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
    layouter.assign_region(
        || "get owned_note_variable",
        |mut region| config.assign_region(owned_note_pub_id, note_variable_pairs, 0, &mut region),
    )
}

// Search and get is_spend_note_flag variable
pub fn get_is_spend_note_flag(
    config: GetIsSpendNoteFlagConfig,
    mut layouter: impl Layouter<pallas::Base>,
    // The owned_note_pub_id is the spend_note_nf or the output_note_cm_x
    owned_note_pub_id: &AssignedCell<pallas::Base, pallas::Base>,
    spend_note_nfs: &[AssignedCell<pallas::Base, pallas::Base>; NUM_NOTE],
    output_note_cms: &[AssignedCell<pallas::Base, pallas::Base>; NUM_NOTE],
) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
    layouter.assign_region(
        || "get is_spend_note_flag",
        |mut region| {
            config.assign_region(
                owned_note_pub_id,
                spend_note_nfs,
                output_note_cms,
                0,
                &mut region,
            )
        },
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GetOwnedNoteVariableConfig {
    q_get_owned_note_variable: Selector,
    owned_note_pub_id: Column<Advice>,
    note_variable_pairs: [Column<Advice>; NUM_NOTE * 2],
}

impl GetOwnedNoteVariableConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        owned_note_pub_id: Column<Advice>,
        note_variable_pairs: [Column<Advice>; NUM_NOTE * 2],
    ) -> Self {
        let config = Self {
            q_get_owned_note_variable: meta.selector(),
            owned_note_pub_id,
            note_variable_pairs,
        };

        config.create_gate(meta);

        config
    }

    fn create_gate(&self, meta: &mut ConstraintSystem<pallas::Base>) {
        meta.create_gate("get owned note variable", |meta| {
            let q_get_owned_note_variable = meta.query_selector(self.q_get_owned_note_variable);
            let owned_note_pub_id = meta.query_advice(self.owned_note_pub_id, Rotation::cur());
            let owned_note_variable = meta.query_advice(self.owned_note_pub_id, Rotation::next());
            let nf_or_cm_vec: Vec<Expression<pasta_curves::Fp>> = self
                .note_variable_pairs
                .into_iter()
                .map(|column| meta.query_advice(column, Rotation::cur()))
                .collect();
            let target_variable_vec: Vec<Expression<pasta_curves::Fp>> = self
                .note_variable_pairs
                .into_iter()
                .map(|column| meta.query_advice(column, Rotation::next()))
                .collect();
            let inv_vec: Vec<Expression<pasta_curves::Fp>> = self
                .note_variable_pairs
                .into_iter()
                .map(|column| meta.query_advice(column, Rotation::prev()))
                .collect();
            let nf_or_cm_minus_owned_note_pub_id_vec: Vec<Expression<pasta_curves::Fp>> =
                nf_or_cm_vec
                    .into_iter()
                    .map(|nf_or_cm| nf_or_cm - owned_note_pub_id.clone())
                    .collect();
            let one = Expression::Constant(pallas::Base::one());
            let nf_or_cm_minus_owned_note_pub_id_is_zero_vec: Vec<Expression<pasta_curves::Fp>> =
                nf_or_cm_minus_owned_note_pub_id_vec
                    .clone()
                    .into_iter()
                    .zip(inv_vec.into_iter())
                    .map(|(nf_or_cm_minus_owned_note_pub_id, inv)| {
                        one.clone() - nf_or_cm_minus_owned_note_pub_id * inv
                    })
                    .collect();
            let poly_vec: Vec<Expression<pasta_curves::Fp>> = nf_or_cm_minus_owned_note_pub_id_vec
                .into_iter()
                .zip(
                    nf_or_cm_minus_owned_note_pub_id_is_zero_vec
                        .clone()
                        .into_iter(),
                )
                .map(|(nf_or_cm_minus_owned_note_pub_id, is_zero)| {
                    nf_or_cm_minus_owned_note_pub_id * is_zero
                })
                .collect();

            Constraints::with_selector(
                q_get_owned_note_variable,
                [
                    (
                        "nf_or_cm_minus_owned_note_pub_id_is_zero check0",
                        poly_vec[0].clone(),
                    ),
                    (
                        "nf_or_cm_minus_owned_note_pub_id_is_zero check1",
                        poly_vec[1].clone(),
                    ),
                    (
                        "nf_or_cm_minus_owned_note_pub_id_is_zero check2",
                        poly_vec[2].clone(),
                    ),
                    (
                        "nf_or_cm_minus_owned_note_pub_id_is_zero check3",
                        poly_vec[3].clone(),
                    ),
                    (
                        "owned_note_variable check0",
                        nf_or_cm_minus_owned_note_pub_id_is_zero_vec[0].clone()
                            * (owned_note_variable.clone() - target_variable_vec[0].clone()),
                    ),
                    (
                        "owned_note_variable check1",
                        nf_or_cm_minus_owned_note_pub_id_is_zero_vec[1].clone()
                            * (owned_note_variable.clone() - target_variable_vec[1].clone()),
                    ),
                    (
                        "owned_note_variable check2",
                        nf_or_cm_minus_owned_note_pub_id_is_zero_vec[2].clone()
                            * (owned_note_variable.clone() - target_variable_vec[2].clone()),
                    ),
                    (
                        "owned_note_variable check3",
                        nf_or_cm_minus_owned_note_pub_id_is_zero_vec[3].clone()
                            * (owned_note_variable - target_variable_vec[3].clone()),
                    ),
                ],
            )
        });
    }

    pub fn assign_region(
        &self,
        owned_note_pub_id: &AssignedCell<pallas::Base, pallas::Base>,
        note_variable_pairs: &[NoteSearchableVariablePair; NUM_NOTE * 2],
        offset: usize,
        region: &mut Region<'_, pallas::Base>,
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
        // Enable `q_get_owned_note_variable` selector
        self.q_get_owned_note_variable.enable(region, offset + 1)?;

        // copy owned_note_pub_id, note_variable_pairs into the advice columns
        let mut ret = owned_note_pub_id.copy_advice(
            || "owned_note_pub_id",
            region,
            self.owned_note_pub_id,
            offset + 1,
        )?;
        for (pair, column) in note_variable_pairs
            .iter()
            .zip(self.note_variable_pairs.into_iter())
        {
            pair.src_variable
                .copy_advice(|| "nf or cm", region, column, offset + 1)?;
            pair.target_variable
                .copy_advice(|| "target_variable", region, column, offset + 2)?;
            let inv = pair
                .src_variable
                .value()
                .zip(owned_note_pub_id.value())
                .map(|(nf_or_cm, owned_note_pub_id)| {
                    let inv = (nf_or_cm - owned_note_pub_id)
                        .invert()
                        .unwrap_or(pallas::Base::zero());
                    if inv == pallas::Base::zero() {
                        ret = region
                            .assign_advice(
                                || "ret",
                                self.owned_note_pub_id,
                                offset + 2,
                                || pair.target_variable.value().copied(),
                            )
                            .unwrap();
                    }
                    inv
                });
            region.assign_advice(|| "inv", column, offset, || inv)?;
        }
        Ok(ret)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GetIsSpendNoteFlagConfig {
    q_get_is_spend_note_flag: Selector,
    owned_note_pub_id: Column<Advice>,
    spend_note_nf: Column<Advice>,
    output_note_cm: Column<Advice>,
}

impl GetIsSpendNoteFlagConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        owned_note_pub_id: Column<Advice>,
        spend_note_nf: Column<Advice>,
        output_note_cm: Column<Advice>,
    ) -> Self {
        meta.enable_equality(owned_note_pub_id);
        meta.enable_equality(spend_note_nf);
        meta.enable_equality(output_note_cm);

        let config = Self {
            q_get_is_spend_note_flag: meta.selector(),
            owned_note_pub_id,
            spend_note_nf,
            output_note_cm,
        };

        config.create_gate(meta);

        config
    }

    fn create_gate(&self, meta: &mut ConstraintSystem<pallas::Base>) {
        meta.create_gate("get is_spend_note_flag", |meta| {
            let q_get_is_spend_note_flag = meta.query_selector(self.q_get_is_spend_note_flag);
            let owned_note_pub_id = meta.query_advice(self.owned_note_pub_id, Rotation::cur());
            let is_spend_note_flag = meta.query_advice(self.owned_note_pub_id, Rotation::next());
            let spend_note_nf_1 = meta.query_advice(self.spend_note_nf, Rotation::cur());
            let spend_note_nf_2 = meta.query_advice(self.spend_note_nf, Rotation::next());
            let output_note_cm_1 =
                meta.query_advice(self.output_note_cm, Rotation::cur());
            let output_note_cm_2 =
                meta.query_advice(self.output_note_cm, Rotation::next());
                let one = Expression::Constant(pallas::Base::one());

            Constraints::with_selector(
                q_get_is_spend_note_flag,
                [
                    ("bool_check is_spend_note_flag", bool_check(is_spend_note_flag.clone())),
                    (
                        "if is_spend_note_flag, then owned_note_pub_id == spend_note_nf_1 or owned_note_pub_id == spend_note_nf_2",
                        is_spend_note_flag.clone() * (owned_note_pub_id.clone() - spend_note_nf_1) * (owned_note_pub_id.clone() - spend_note_nf_2),
                    ),
                    (
                        "if not is_spend_note_flag, then owned_note_pub_id == output_note_cm_1 or owned_note_pub_id == output_note_cm_2",
                        (is_spend_note_flag - one) * (owned_note_pub_id.clone() - output_note_cm_1) * (owned_note_pub_id - output_note_cm_2),
                    ),
                ],
            )
        });
    }

    pub fn assign_region(
        &self,
        owned_note_pub_id: &AssignedCell<pallas::Base, pallas::Base>,
        spend_note_nfs: &[AssignedCell<pallas::Base, pallas::Base>; NUM_NOTE],
        output_note_cms: &[AssignedCell<pallas::Base, pallas::Base>; NUM_NOTE],
        offset: usize,
        region: &mut Region<'_, pallas::Base>,
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
        // Enable `q_get_is_spend_note_flag` selector
        self.q_get_is_spend_note_flag.enable(region, offset)?;

        // copy owned_note_pub_id, spend_note_nfs and output_note_cms into the advice columns
        owned_note_pub_id.copy_advice(
            || "owned_note_pub_id",
            region,
            self.owned_note_pub_id,
            offset,
        )?;
        spend_note_nfs[0].copy_advice(|| "spend_note_nf 1", region, self.spend_note_nf, offset)?;
        spend_note_nfs[1].copy_advice(
            || "spend_note_nf 2",
            region,
            self.spend_note_nf,
            offset + 1,
        )?;
        output_note_cms[0].copy_advice(
            || "output_note_cm 1",
            region,
            self.output_note_cm,
            offset,
        )?;
        output_note_cms[1].copy_advice(
            || "output_note_cm 2",
            region,
            self.output_note_cm,
            offset + 1,
        )?;

        // compute the is_spend_note_flag
        let is_spend_note_flag = owned_note_pub_id
            .value()
            .zip(spend_note_nfs[0].value())
            .zip(spend_note_nfs[0].value())
            .map(
                |((&owned_note_pub_id, &spend_note_nf_1), &spend_note_nf_2)| {
                    if owned_note_pub_id == spend_note_nf_1 || owned_note_pub_id == spend_note_nf_2
                    {
                        pallas::Base::one()
                    } else {
                        pallas::Base::zero()
                    }
                },
            );
        region.assign_advice(
            || "is_spend_note_flag",
            self.owned_note_pub_id,
            offset + 1,
            || is_spend_note_flag,
        )
    }
}
