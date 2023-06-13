use crate::constant::{
    NoteCommitmentFixedBases, POSEIDON_TO_CURVE_INPUT_LEN, POSEIDON_TO_FIELD_U_0_POSTFIX,
    POSEIDON_TO_FIELD_U_1_POSTFIX,
};
use halo2_gadgets::{
    ecc::{chip::EccChip, Point},
    poseidon::Pow5Config as PoseidonConfig,
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter},
    plonk::{Advice, Column, ConstraintSystem, Error},
};
use pasta_curves::pallas;

use super::curve::{
    iso_map::MapToCurveConfig, map_to_curve::IsoMapConfig, to_affine::ToAffineConfig,
};
use crate::circuit::gadgets::poseidon_hash::poseidon_hash_gadget;

// TODO: make HashToCurve a chip
// pub trait HashToCurveInstructions<F: FieldExt>: Chip<F> {
//     type Var;
//     fn hash_to_curve(
//         &self,
//         layouter: impl Layouter<F>,
//         messages: &[Self::Var],
//     ) -> Result<(), Error>;
// }

// #[derive(Clone, Debug)]
// pub struct HashToCurveChip<F: FieldExt> {
//     config: HashToCurveConfig,
//     _marker: PhantomData<F>,
// }

// impl<F: FieldExt> Chip<F> for HashToCurveChip<F> {
//     type Config = HashToCurveConfig;
//     type Loaded = ();

//     fn config(&self) -> &Self::Config {
//         &self.config
//     }

//     fn loaded(&self) -> &Self::Loaded {
//         &()
//     }
// }

// impl<F: FieldExt> HashToCurveInstructions<F> for HashToCurveChip<F> {
//     type Var = AssignedCell<F, F>;
//     fn hash_to_curve(
//         &self,
//         mut layouter: impl Layouter<F>,
//         messages: &[Self::Var],
//     ) -> Result<(), Error> {
//         Ok(())
//     }
// }

pub fn hash_to_curve_circuit(
    mut layouter: impl Layouter<pallas::Base>,
    config: HashToCurveConfig,
    ecc_chip: EccChip<NoteCommitmentFixedBases>,
    messages: &[AssignedCell<pallas::Base, pallas::Base>],
) -> Result<Point<pallas::Affine, EccChip<NoteCommitmentFixedBases>>, Error> {
    // hash to u_0
    let u_0 = {
        let u_0_postfix: Vec<AssignedCell<pallas::Base, pallas::Base>> =
            POSEIDON_TO_FIELD_U_0_POSTFIX
                .iter()
                .map(|&v| {
                    layouter
                        .assign_region(
                            || "load constant",
                            |mut region| {
                                region.assign_advice_from_constant(
                                    || "constant value",
                                    config.advices[0],
                                    0,
                                    v,
                                )
                            },
                        )
                        .unwrap()
                })
                .collect();
        let poseidon_msg = [messages, &u_0_postfix]
            .concat()
            .try_into()
            .expect("slice with incorrect length");
        poseidon_hash_gadget::<POSEIDON_TO_CURVE_INPUT_LEN>(
            config.poseidon_config.clone(),
            layouter.namespace(|| "compute u_0"),
            poseidon_msg,
        )?
    };

    // hash to u_1
    let u_1 = {
        let u_1_postfix: Vec<AssignedCell<pallas::Base, pallas::Base>> =
            POSEIDON_TO_FIELD_U_1_POSTFIX
                .iter()
                .map(|&v| {
                    layouter
                        .assign_region(
                            || "load constant",
                            |mut region| {
                                region.assign_advice_from_constant(
                                    || "constant value",
                                    config.advices[1],
                                    0,
                                    v,
                                )
                            },
                        )
                        .unwrap()
                })
                .collect();
        let poseidon_msg = [messages, &u_1_postfix]
            .concat()
            .try_into()
            .expect("slice with incorrect length");
        poseidon_hash_gadget::<POSEIDON_TO_CURVE_INPUT_LEN>(
            config.poseidon_config.clone(),
            layouter.namespace(|| "compute u_1"),
            poseidon_msg,
        )?
    };

    // Use messages as u_0 and u_1
    let q_0 = layouter.assign_region(
        || "u_0 map_to_curve",
        |mut region| {
            config
                .map_to_curve_config
                .assign_region(&u_0, 0, &mut region)
        },
    )?;

    let r_0 = layouter.assign_region(
        || "q_0 isogeny map",
        |mut region| {
            config
                .iso_map_config
                .assign_region(&q_0.0, &q_0.1, &q_0.2, 0, &mut region)
        },
    )?;

    let k_0 = layouter.assign_region(
        || "r_0 to affine",
        |mut region| {
            config.to_affine_config.assign_region(
                ecc_chip.clone(),
                &r_0.0,
                &r_0.1,
                &r_0.2,
                0,
                &mut region,
            )
        },
    )?;

    let q_1 = layouter.assign_region(
        || "u_1 map_to_curve",
        |mut region| {
            config
                .map_to_curve_config
                .assign_region(&u_1, 0, &mut region)
        },
    )?;

    let r_1 = layouter.assign_region(
        || "q_1 isogeny map",
        |mut region| {
            config
                .iso_map_config
                .assign_region(&q_1.0, &q_1.1, &q_1.2, 0, &mut region)
        },
    )?;

    let k_1 = layouter.assign_region(
        || "r_1 to affine",
        |mut region| {
            config.to_affine_config.assign_region(
                ecc_chip.clone(),
                &r_1.0,
                &r_1.1,
                &r_1.2,
                0,
                &mut region,
            )
        },
    )?;

    k_0.add(layouter.namespace(|| "k_0 + k_1"), &k_1)
}

#[derive(Clone, Debug)]
pub struct HashToCurveConfig {
    advices: [Column<Advice>; 10],
    poseidon_config: PoseidonConfig<pallas::Base, 3, 2>,
    map_to_curve_config: MapToCurveConfig,
    iso_map_config: IsoMapConfig,
    to_affine_config: ToAffineConfig,
}

impl HashToCurveConfig {
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        advices: [Column<Advice>; 10],
        poseidon_config: PoseidonConfig<pallas::Base, 3, 2>,
    ) -> Self {
        let map_to_curve_config = MapToCurveConfig::configure(
            meta, advices[0], advices[1], advices[2], advices[3], advices[4], advices[5],
            advices[6], advices[7], advices[8], advices[9],
        );
        let iso_map_config = IsoMapConfig::configure(meta, advices[0], advices[1], advices[2]);
        let to_affine_config = ToAffineConfig::configure(meta, advices[3], advices[4], advices[5]);

        Self {
            advices,
            poseidon_config,
            map_to_curve_config,
            iso_map_config,
            to_affine_config,
        }
    }
}

#[test]
fn test_hash_to_curve_circuit() {
    use halo2_gadgets::{
        ecc::chip::EccConfig,
        poseidon::{primitives as poseidon, Pow5Chip as PoseidonChip},
        utilities::lookup_range_check::LookupRangeCheckConfig,
    };
    use pasta_curves::group::Curve;

    use crate::circuit::gadgets::assign_free_advice;
    use crate::utils::poseidon_to_curve;
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error},
    };
    #[derive(Default)]
    struct MyCircuit {}

    impl Circuit<pallas::Base> for MyCircuit {
        type Config = (
            [Column<Advice>; 10],
            HashToCurveConfig,
            EccConfig<NoteCommitmentFixedBases>,
        );
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
            let advices = [
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
            ];
            let lagrange_coeffs = [
                meta.fixed_column(),
                meta.fixed_column(),
                meta.fixed_column(),
                meta.fixed_column(),
                meta.fixed_column(),
                meta.fixed_column(),
                meta.fixed_column(),
                meta.fixed_column(),
            ];
            meta.enable_constant(lagrange_coeffs[0]);

            let poseidon_config = PoseidonChip::configure::<poseidon::P128Pow5T3>(
                meta,
                advices[6..9].try_into().unwrap(),
                advices[5],
                lagrange_coeffs[2..5].try_into().unwrap(),
                lagrange_coeffs[5..8].try_into().unwrap(),
            );

            let hash_to_curve_config = HashToCurveConfig::configure(meta, advices, poseidon_config);

            let table_idx = meta.lookup_table_column();

            let range_check = LookupRangeCheckConfig::configure(meta, advices[9], table_idx);

            let ecc_config = EccChip::<NoteCommitmentFixedBases>::configure(
                meta,
                advices,
                lagrange_coeffs,
                range_check,
            );

            (advices, hash_to_curve_config, ecc_config)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<pallas::Base>,
        ) -> Result<(), Error> {
            let (advices, hash_to_curve_config, ecc_config) = config;
            let ecc_chip = EccChip::construct(ecc_config);

            let messages = [pallas::Base::zero(); POSEIDON_TO_CURVE_INPUT_LEN - 2];
            let messages_vars = messages
                .into_iter()
                .map(|v| {
                    assign_free_advice(layouter.namespace(|| "u_0"), advices[0], Value::known(v))
                        .unwrap()
                })
                .collect::<Vec<_>>();
            let ret = hash_to_curve_circuit(
                layouter.namespace(|| "hash to curve"),
                hash_to_curve_config,
                ecc_chip.clone(),
                &messages_vars,
            )?;
            let expect_ret = {
                let expect_point = poseidon_to_curve::<POSEIDON_TO_CURVE_INPUT_LEN>(&messages);
                Point::new(
                    ecc_chip,
                    layouter.namespace(|| "expect_point"),
                    Value::known(expect_point.to_affine()),
                )
            }?;
            ret.constrain_equal(layouter, &expect_ret)
        }
    }

    let circuit = MyCircuit {};

    let prover = MockProver::run(11, &circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()));

    // TODO: there is still space to improve the performance. keep the test
    // {
    //     use halo2_proofs::{
    //         dev::MockProver,
    //         plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier},
    //         poly::commitment::Params,
    //         transcript::{Blake2bRead, Blake2bWrite},
    //     };
    //     use pasta_curves::vesta;
    //     use rand::rngs::OsRng;

    //     let mut rng = OsRng;
    //     let params = Params::new(11);
    //     let empty_circuit = MyCircuit {};
    //     let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
    //     let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");
    //     let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
    //     use std::time::Instant;
    //     let start = Instant::now();
    //     create_proof(
    //         &params,
    //         &pk,
    //         &[empty_circuit],
    //         &[&[]],
    //         &mut rng,
    //         &mut transcript,
    //     )
    //     .unwrap();
    //     let proof = transcript.finalize();
    //     println!(
    //         "hash to curve time: {:?}",
    //         Instant::now().duration_since(start)
    //     );

    //     let strategy = SingleVerifier::new(&params);
    //     let mut transcript = Blake2bRead::init(&proof[..]);
    //     assert!(verify_proof(&params, pk.get_vk(), strategy, &[&[]], &mut transcript).is_ok());
    // }
}
