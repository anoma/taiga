use crate::circuit::vp_circuit::ResourceSearchableVariablePair;
use crate::constant::NUM_RESOURCE;
use halo2_gadgets::utilities::bool_check;
use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Expression, Selector},
    poly::Rotation,
};
use pasta_curves::pallas;

// Search and get owned resource variable
pub fn get_owned_resource_variable(
    config: GetOwnedResourceVariableConfig,
    mut layouter: impl Layouter<pallas::Base>,
    // The owned_resource_id is the input_resource_nf or the output_resource_cm_x
    owned_resource_id: &AssignedCell<pallas::Base, pallas::Base>,
    // NUM_RESOURCE pairs are from input resources, the other NUM_RESOURCE are from output resources
    resource_variable_pairs: &[ResourceSearchableVariablePair; NUM_RESOURCE * 2],
) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
    layouter.assign_region(
        || "get owned_resource_variable",
        |mut region| {
            config.assign_region(owned_resource_id, resource_variable_pairs, 0, &mut region)
        },
    )
}

// Search and get is_input_resource_flag variable
pub fn get_is_input_resource_flag(
    config: GetIsInputResourceFlagConfig,
    mut layouter: impl Layouter<pallas::Base>,
    // The owned_resource_id is the input_resource_nf or the output_resource_cm_x
    owned_resource_id: &AssignedCell<pallas::Base, pallas::Base>,
    input_resource_nfs: &[AssignedCell<pallas::Base, pallas::Base>; NUM_RESOURCE],
    output_resource_cms: &[AssignedCell<pallas::Base, pallas::Base>; NUM_RESOURCE],
) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
    layouter.assign_region(
        || "get is_input_resource_flag",
        |mut region| {
            config.assign_region(
                owned_resource_id,
                input_resource_nfs,
                output_resource_cms,
                0,
                &mut region,
            )
        },
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GetOwnedResourceVariableConfig {
    q_get_owned_resource_variable: Selector,
    owned_resource_id: Column<Advice>,
    resource_variable_pairs: [Column<Advice>; NUM_RESOURCE * 2],
}

impl GetOwnedResourceVariableConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        owned_resource_id: Column<Advice>,
        resource_variable_pairs: [Column<Advice>; NUM_RESOURCE * 2],
    ) -> Self {
        let config = Self {
            q_get_owned_resource_variable: meta.selector(),
            owned_resource_id,
            resource_variable_pairs,
        };

        config.create_gate(meta);

        config
    }

    fn create_gate(&self, meta: &mut ConstraintSystem<pallas::Base>) {
        meta.create_gate("get owned resource variable", |meta| {
            let q_get_owned_resource_variable =
                meta.query_selector(self.q_get_owned_resource_variable);
            let owned_resource_id = meta.query_advice(self.owned_resource_id, Rotation::cur());
            let owned_resource_variable =
                meta.query_advice(self.owned_resource_id, Rotation::next());
            let nf_or_cm_vec: Vec<Expression<pasta_curves::Fp>> = self
                .resource_variable_pairs
                .into_iter()
                .map(|column| meta.query_advice(column, Rotation::cur()))
                .collect();
            let target_variable_vec: Vec<Expression<pasta_curves::Fp>> = self
                .resource_variable_pairs
                .into_iter()
                .map(|column| meta.query_advice(column, Rotation::next()))
                .collect();
            let inv_vec: Vec<Expression<pasta_curves::Fp>> = self
                .resource_variable_pairs
                .into_iter()
                .map(|column| meta.query_advice(column, Rotation::prev()))
                .collect();
            let nf_or_cm_minus_owned_resource_id_vec: Vec<Expression<pasta_curves::Fp>> =
                nf_or_cm_vec
                    .into_iter()
                    .map(|nf_or_cm| nf_or_cm - owned_resource_id.clone())
                    .collect();
            let one = Expression::Constant(pallas::Base::one());
            let nf_or_cm_minus_owned_resource_id_is_zero_vec: Vec<Expression<pasta_curves::Fp>> =
                nf_or_cm_minus_owned_resource_id_vec
                    .clone()
                    .into_iter()
                    .zip(inv_vec)
                    .map(|(nf_or_cm_minus_owned_resource_id, inv)| {
                        one.clone() - nf_or_cm_minus_owned_resource_id * inv
                    })
                    .collect();
            let poly_vec: Vec<Expression<pasta_curves::Fp>> = nf_or_cm_minus_owned_resource_id_vec
                .into_iter()
                .zip(nf_or_cm_minus_owned_resource_id_is_zero_vec.clone())
                .map(|(nf_or_cm_minus_owned_resource_id, is_zero)| {
                    nf_or_cm_minus_owned_resource_id * is_zero
                })
                .collect();

            Constraints::with_selector(
                q_get_owned_resource_variable,
                [
                    (
                        "nf_or_cm_minus_owned_resource_id_is_zero check0",
                        poly_vec[0].clone(),
                    ),
                    (
                        "nf_or_cm_minus_owned_resource_id_is_zero check1",
                        poly_vec[1].clone(),
                    ),
                    (
                        "nf_or_cm_minus_owned_resource_id_is_zero check2",
                        poly_vec[2].clone(),
                    ),
                    (
                        "nf_or_cm_minus_owned_resource_id_is_zero check3",
                        poly_vec[3].clone(),
                    ),
                    (
                        "owned_resource_variable check0",
                        nf_or_cm_minus_owned_resource_id_is_zero_vec[0].clone()
                            * (owned_resource_variable.clone() - target_variable_vec[0].clone()),
                    ),
                    (
                        "owned_resource_variable check1",
                        nf_or_cm_minus_owned_resource_id_is_zero_vec[1].clone()
                            * (owned_resource_variable.clone() - target_variable_vec[1].clone()),
                    ),
                    (
                        "owned_resource_variable check2",
                        nf_or_cm_minus_owned_resource_id_is_zero_vec[2].clone()
                            * (owned_resource_variable.clone() - target_variable_vec[2].clone()),
                    ),
                    (
                        "owned_resource_variable check3",
                        nf_or_cm_minus_owned_resource_id_is_zero_vec[3].clone()
                            * (owned_resource_variable - target_variable_vec[3].clone()),
                    ),
                    (
                        "owned_resource_id exists in the resources",
                        nf_or_cm_minus_owned_resource_id_is_zero_vec[0].clone()
                            * nf_or_cm_minus_owned_resource_id_is_zero_vec[1].clone()
                            * nf_or_cm_minus_owned_resource_id_is_zero_vec[2].clone()
                            * nf_or_cm_minus_owned_resource_id_is_zero_vec[3].clone(),
                    ),
                ],
            )
        });
    }

    pub fn assign_region(
        &self,
        owned_resource_id: &AssignedCell<pallas::Base, pallas::Base>,
        resource_variable_pairs: &[ResourceSearchableVariablePair; NUM_RESOURCE * 2],
        offset: usize,
        region: &mut Region<'_, pallas::Base>,
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
        // Enable `q_get_owned_resource_variable` selector
        self.q_get_owned_resource_variable
            .enable(region, offset + 1)?;

        // copy owned_resource_id, resource_variable_pairs into the advice columns
        owned_resource_id.copy_advice(
            || "owned_resource_id",
            region,
            self.owned_resource_id,
            offset + 1,
        )?;

        let mut ret = Value::known(pallas::Base::zero());
        for (pair, column) in resource_variable_pairs
            .iter()
            .zip(self.resource_variable_pairs)
        {
            pair.src_variable
                .copy_advice(|| "nf or cm", region, column, offset + 1)?;
            pair.target_variable
                .copy_advice(|| "target_variable", region, column, offset + 2)?;
            let inv = pair
                .src_variable
                .value()
                .zip(owned_resource_id.value())
                .map(|(nf_or_cm, owned_resource_id)| {
                    let inv = (nf_or_cm - owned_resource_id)
                        .invert()
                        .unwrap_or(pallas::Base::zero());

                    // Find the target variable
                    if inv == pallas::Base::zero() {
                        ret = pair.target_variable.value().copied();
                    }
                    inv
                });
            region.assign_advice(|| "inv", column, offset, || inv)?;
        }
        region.assign_advice(|| "ret", self.owned_resource_id, offset + 2, || ret)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GetIsInputResourceFlagConfig {
    q_get_is_input_resource_flag: Selector,
    owned_resource_id: Column<Advice>,
    input_resource_nf: Column<Advice>,
    output_resource_cm: Column<Advice>,
}

impl GetIsInputResourceFlagConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        owned_resource_id: Column<Advice>,
        input_resource_nf: Column<Advice>,
        output_resource_cm: Column<Advice>,
    ) -> Self {
        meta.enable_equality(owned_resource_id);
        meta.enable_equality(input_resource_nf);
        meta.enable_equality(output_resource_cm);

        let config = Self {
            q_get_is_input_resource_flag: meta.selector(),
            owned_resource_id,
            input_resource_nf,
            output_resource_cm,
        };

        config.create_gate(meta);

        config
    }

    fn create_gate(&self, meta: &mut ConstraintSystem<pallas::Base>) {
        meta.create_gate("get is_input_resource_flag", |meta| {
            let q_get_is_input_resource_flag = meta.query_selector(self.q_get_is_input_resource_flag);
            let owned_resource_id = meta.query_advice(self.owned_resource_id, Rotation::cur());
            let is_input_resource_flag = meta.query_advice(self.owned_resource_id, Rotation::next());
            let input_resource_nf_1 = meta.query_advice(self.input_resource_nf, Rotation::cur());
            let input_resource_nf_2 = meta.query_advice(self.input_resource_nf, Rotation::next());
            let output_resource_cm_1 =
                meta.query_advice(self.output_resource_cm, Rotation::cur());
            let output_resource_cm_2 =
                meta.query_advice(self.output_resource_cm, Rotation::next());
                let one = Expression::Constant(pallas::Base::one());

            Constraints::with_selector(
                q_get_is_input_resource_flag,
                [
                    ("bool_check is_input_resource_flag", bool_check(is_input_resource_flag.clone())),
                    (
                        "if is_input_resource_flag, then owned_resource_id == input_resource_nf_1 or owned_resource_id == input_resource_nf_2",
                        is_input_resource_flag.clone() * (owned_resource_id.clone() - input_resource_nf_1) * (owned_resource_id.clone() - input_resource_nf_2),
                    ),
                    (
                        "if not is_input_resource_flag, then owned_resource_id == output_resource_cm_1 or owned_resource_id == output_resource_cm_2",
                        (is_input_resource_flag - one) * (owned_resource_id.clone() - output_resource_cm_1) * (owned_resource_id - output_resource_cm_2),
                    ),
                ],
            )
        });
    }

    pub fn assign_region(
        &self,
        owned_resource_id: &AssignedCell<pallas::Base, pallas::Base>,
        input_resource_nfs: &[AssignedCell<pallas::Base, pallas::Base>; NUM_RESOURCE],
        output_resource_cms: &[AssignedCell<pallas::Base, pallas::Base>; NUM_RESOURCE],
        offset: usize,
        region: &mut Region<'_, pallas::Base>,
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
        // Enable `q_get_is_input_resource_flag` selector
        self.q_get_is_input_resource_flag.enable(region, offset)?;

        // copy owned_resource_id, input_resource_nfs and output_resource_cms into the advice columns
        owned_resource_id.copy_advice(
            || "owned_resource_id",
            region,
            self.owned_resource_id,
            offset,
        )?;
        input_resource_nfs[0].copy_advice(
            || "input_resource_nf 1",
            region,
            self.input_resource_nf,
            offset,
        )?;
        input_resource_nfs[1].copy_advice(
            || "input_resource_nf 2",
            region,
            self.input_resource_nf,
            offset + 1,
        )?;
        output_resource_cms[0].copy_advice(
            || "output_resource_cm 1",
            region,
            self.output_resource_cm,
            offset,
        )?;
        output_resource_cms[1].copy_advice(
            || "output_resource_cm 2",
            region,
            self.output_resource_cm,
            offset + 1,
        )?;

        // compute the is_input_resource_flag
        let is_input_resource_flag = owned_resource_id
            .value()
            .zip(input_resource_nfs[0].value())
            .zip(input_resource_nfs[1].value())
            .map(
                |((&owned_resource_id, &input_resource_nf_1), &input_resource_nf_2)| {
                    if owned_resource_id == input_resource_nf_1
                        || owned_resource_id == input_resource_nf_2
                    {
                        pallas::Base::one()
                    } else {
                        pallas::Base::zero()
                    }
                },
            );
        region.assign_advice(
            || "is_input_resource_flag",
            self.owned_resource_id,
            offset + 1,
            || is_input_resource_flag,
        )
    }
}
