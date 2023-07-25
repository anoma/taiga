use crate::circuit::gadgets::poseidon_hash::poseidon_hash_gadget;
use crate::merkle_tree::{is_left, LR};
use halo2_gadgets::{
    poseidon::Pow5Config as PoseidonConfig,
    utilities::cond_swap::{CondSwapChip, CondSwapConfig, CondSwapInstructions},
};
use halo2_proofs::{
    circuit::{AssignedCell, Chip, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error},
};
use pasta_curves::pallas;

/// MerkleTreeChip based on poseidon hash.
#[derive(Clone, Debug)]
pub struct MerklePoseidonConfig {
    advices: [Column<Advice>; 5],
    cond_swap_config: CondSwapConfig,
    poseidon_config: PoseidonConfig<pallas::Base, 3, 2>,
}

#[derive(Clone, Debug)]
pub struct MerklePoseidonChip {
    config: MerklePoseidonConfig,
}

impl Chip<pallas::Base> for MerklePoseidonChip {
    type Config = MerklePoseidonConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl MerklePoseidonChip {
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        advices: [Column<Advice>; 5],
        poseidon_config: PoseidonConfig<pallas::Base, 3, 2>,
    ) -> MerklePoseidonConfig {
        let cond_swap_config = CondSwapChip::configure(meta, advices);

        MerklePoseidonConfig {
            advices,
            cond_swap_config,
            poseidon_config,
        }
    }

    pub fn construct(config: MerklePoseidonConfig) -> Self {
        MerklePoseidonChip { config }
    }
}

#[allow(clippy::type_complexity)]
pub fn merkle_poseidon_gadget(
    mut layouter: impl Layouter<pallas::Base>,
    chip: MerklePoseidonChip,
    note_x: AssignedCell<pallas::Base, pallas::Base>,
    merkle_path: &[(pallas::Base, LR)],
) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
    fn swap(
        merkle_chip: &MerklePoseidonChip,
        layouter: impl Layouter<pallas::Base>,
        pair: (
            AssignedCell<pallas::Base, pallas::Base>,
            Value<pallas::Base>,
        ),
        swap: Value<bool>,
    ) -> Result<
        (
            AssignedCell<pallas::Base, pallas::Base>,
            AssignedCell<pallas::Base, pallas::Base>,
        ),
        Error,
    > {
        let config = merkle_chip.config().cond_swap_config.clone();
        let chip = CondSwapChip::<pallas::Base>::construct(config);
        chip.swap(layouter, pair, swap)
    }

    let mut cur = note_x;
    for e in merkle_path.iter() {
        let pair = {
            let pair = (cur, Value::known(e.0));
            swap(
                &chip,
                layouter.namespace(|| "merkle swap"),
                pair,
                Value::known(is_left(e.1)),
            )?
        };

        cur = poseidon_hash_gadget(
            chip.config().poseidon_config.clone(),
            layouter.namespace(|| "merkle poseidon hash"),
            [pair.0, pair.1],
        )?;
    }

    Ok(cur)
}

#[test]
fn test_halo2_merkle_circuit() {
    use crate::circuit::gadgets::assign_free_advice;
    use crate::merkle_tree::{tests::random_merkle_path, MerklePath, Node};
    use halo2_gadgets::poseidon::{primitives as poseidon, Pow5Chip as PoseidonChip};
    use halo2_proofs::{
        arithmetic::Field,
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        plonk::{Circuit, ConstraintSystem, Error},
    };
    use rand::rngs::OsRng;

    #[derive(Default)]
    struct MyCircuit {
        leaf: pallas::Base,
        merkle_path: MerklePath,
    }

    impl Circuit<pallas::Base> for MyCircuit {
        type Config = MerklePoseidonConfig;
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
            ];
            for advice in advices.iter() {
                meta.enable_equality(*advice);
            }
            let cond_swap_config = CondSwapChip::configure(meta, advices);

            let state = (0..3).map(|_| meta.advice_column()).collect::<Vec<_>>();
            let partial_sbox = meta.advice_column();
            let rc_a = (0..3).map(|_| meta.fixed_column()).collect::<Vec<_>>();
            let rc_b = (0..3).map(|_| meta.fixed_column()).collect::<Vec<_>>();
            meta.enable_constant(rc_b[0]);
            let poseidon_config = PoseidonChip::configure::<poseidon::P128Pow5T3>(
                meta,
                state.try_into().unwrap(),
                partial_sbox,
                rc_a.try_into().unwrap(),
                rc_b.try_into().unwrap(),
            );

            Self::Config {
                advices,
                cond_swap_config,
                poseidon_config,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<pallas::Base>,
        ) -> Result<(), Error> {
            // Witness leaf
            let leaf = assign_free_advice(
                layouter.namespace(|| "witness leaf"),
                config.advices[0],
                Value::known(self.leaf),
            )?;

            let merkle_chip = MerklePoseidonChip::construct(config.clone());

            let root = merkle_poseidon_gadget(
                layouter.namespace(|| "poseidon merkle"),
                merkle_chip,
                leaf,
                &self.merkle_path.get_path(),
            )?;

            let expected_root = {
                let root = self.merkle_path.root(Node::new(self.leaf)).inner();
                assign_free_advice(
                    layouter.namespace(|| "witness leaf"),
                    config.advices[0],
                    Value::known(root),
                )?
            };
            layouter.assign_region(
                || "constrain result",
                |mut region| region.constrain_equal(root.cell(), expected_root.cell()),
            )
        }
    }

    let mut rng = OsRng;

    let leaf = pallas::Base::random(rng);
    let merkle_path = random_merkle_path(&mut rng);

    let circuit = MyCircuit { leaf, merkle_path };

    let prover = MockProver::run(11, &circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()))
}
