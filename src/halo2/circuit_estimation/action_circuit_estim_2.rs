use ff::Field;
use halo2_proofs::{
    circuit::{floor_planner, AssignedCell, Layouter, Value},
    plonk::{self, Advice, Assigned, Column, Instance as InstanceColumn, SingleVerifier},
    transcript::{Blake2bRead, Blake2bWrite},
};
use pasta_curves::{pallas, vesta};
use rand::RngCore;

use halo2_gadgets::poseidon::{
    primitives::{self as poseidon, P128Pow5T3, P128Pow5T5},
    Pow5Chip as PoseidonChip, Pow5Config as PoseidonConfig,
};

// number of hashes to do in the circuit
const NUM_NOTES: usize = 4;
const NB_POSEIDON2: usize = NUM_NOTES * 39;
const NB_POSEIDON4: usize = NUM_NOTES * 1;

// constant for the circuit size (depends on the number of hashes, of course)
pub const K: u32 = 13;

pub(crate) fn assign_free_advice<F: Field, V: Copy>(
    mut layouter: impl Layouter<F>,
    column: Column<Advice>,
    value: Value<V>,
) -> Result<AssignedCell<V, F>, plonk::Error>
where
    for<'v> Assigned<F>: From<&'v V>,
{
    layouter.assign_region(
        || "load private",
        |mut region| region.assign_advice(|| "load private", column, 0, || value),
    )
}

#[derive(Clone, Debug)]
pub struct Config {
    primary: Column<InstanceColumn>,
    advices: [Column<Advice>; 10],
    poseidon2_config: PoseidonConfig<pallas::Base, 3, 2>,
    poseidon4_config: PoseidonConfig<pallas::Base, 5, 4>,
}

impl Config {
    pub(super) fn poseidon2_chip(&self) -> PoseidonChip<pallas::Base, 3, 2> {
        PoseidonChip::construct(self.poseidon2_config.clone())
    }
    pub(super) fn poseidon4_chip(&self) -> PoseidonChip<pallas::Base, 5, 4> {
        PoseidonChip::construct(self.poseidon4_config.clone())
    }
}

#[derive(Clone, Debug, Default)]
pub struct Circuit {
    pub x: pallas::Base,
    pub y: pallas::Base,
    pub z: pallas::Base,
    pub t: pallas::Base,
}

impl plonk::Circuit<pallas::Base> for Circuit {
    type Config = Config;
    type FloorPlanner = floor_planner::V1;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut plonk::ConstraintSystem<pallas::Base>) -> Self::Config {
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

        // Instance column used for public inputs
        let primary = meta.instance_column();
        meta.enable_equality(primary);

        // Permutation over all advice columns.
        for advice in advices.iter() {
            meta.enable_equality(*advice);
        }

        // Poseidon requires four advice columns, while ECC incomplete addition requires
        // six, so we could choose to configure them in parallel. However, we only use a
        // single Poseidon invocation, and we have the rows to accommodate it serially.
        // Instead, we reduce the proof size by sharing fixed columns between the ECC and
        // Poseidon chips.
        let lagrange_coeffs = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];

        // Also use the first Lagrange coefficient column for loading global constants.
        // It's free real estate :)
        meta.enable_constant(lagrange_coeffs[0]);

        let rc_a = lagrange_coeffs[1..4].try_into().unwrap();
        let rc_b = lagrange_coeffs[4..7].try_into().unwrap();

        // Configuration for the Poseidon2 hash.
        let poseidon2_config = PoseidonChip::configure::<poseidon::P128Pow5T3>(
            meta,
            // We place the state columns after the partial_sbox column so that the
            // pad-and-add region can be laid out more efficiently.
            advices[0..3].try_into().unwrap(),
            advices[3],
            rc_a,
            rc_b,
        );

        meta.enable_constant(lagrange_coeffs[7]);

        let rc_c = lagrange_coeffs[8..13].try_into().unwrap();
        let rc_d = lagrange_coeffs[13..18].try_into().unwrap();

        // Configuration for the Poseidon4 hash.
        let poseidon4_config = PoseidonChip::configure::<poseidon::P128Pow5T5>(
            meta,
            // We place the state columns after the partial_sbox column so that the
            // pad-and-add region can be laid out more efficiently.
            advices[4..9].try_into().unwrap(),
            advices[9],
            rc_c,
            rc_d,
        );

        Config {
            primary,
            advices,
            poseidon2_config,
            poseidon4_config,
        }
    }

    #[allow(non_snake_case)]
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), plonk::Error> {
        for i in 0..NB_POSEIDON4 {
            let x_cell = assign_free_advice(
                layouter.namespace(|| "x"),
                config.advices[0],
                Value::known(self.x),
            )?;
            let y_cell = assign_free_advice(
                layouter.namespace(|| "y"),
                config.advices[1],
                Value::known(self.y),
            )?;
            let z_cell = assign_free_advice(
                layouter.namespace(|| "z"),
                config.advices[0],
                Value::known(self.z),
            )?;
            let t_cell = assign_free_advice(
                layouter.namespace(|| "t"),
                config.advices[1],
                Value::known(self.t),
            )?;

            // Poseidon(x, y, z, t)
            let gamma = {
                let poseidon_message: [AssignedCell<pallas::Base, pallas::Base>; 4] =
                    [x_cell, y_cell, z_cell, t_cell];

                let poseidon_hasher =
                    halo2_gadgets::poseidon::Hash::<_, _, P128Pow5T5, _, 5, 4>::init(
                        config.poseidon4_chip(),
                        layouter.namespace(|| "Poseidon4 init"),
                    )?;
                poseidon_hasher.hash(layouter.namespace(|| "Poseidon4 hash"), poseidon_message)?
            };

            layouter
                .constrain_instance(gamma.cell(), config.primary, i)
                .unwrap();
        }

        for i in 0..NB_POSEIDON2 {
            let x_cell = assign_free_advice(
                layouter.namespace(|| "x"),
                config.advices[0],
                Value::known(self.x),
            )?;
            let y_cell = assign_free_advice(
                layouter.namespace(|| "y"),
                config.advices[1],
                Value::known(self.y),
            )?;

            // Poseidon(x, y)
            let gamma = {
                let poseidon_message: [AssignedCell<pallas::Base, pallas::Base>; 2] =
                    [x_cell, y_cell];

                let poseidon_hasher =
                    halo2_gadgets::poseidon::Hash::<_, _, P128Pow5T3, _, 3, 2>::init(
                        config.poseidon2_chip(),
                        layouter.namespace(|| "Poseidon2 init"),
                    )?;
                poseidon_hasher.hash(layouter.namespace(|| "Poseidon2 hash"), poseidon_message)?
            };

            layouter
                .constrain_instance(gamma.cell(), config.primary, i + NB_POSEIDON4)
                .unwrap();
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct VerifyingKey {
    pub(crate) params: halo2_proofs::poly::commitment::Params<vesta::Affine>,
    pub(crate) vk: plonk::VerifyingKey<vesta::Affine>,
}

impl VerifyingKey {
    /// Builds the verifying key.
    pub fn build() -> Self {
        let params = halo2_proofs::poly::commitment::Params::new(K);
        let circuit: Circuit = Default::default();

        let vk = plonk::keygen_vk(&params, &circuit).unwrap();

        VerifyingKey { params, vk }
    }
}

#[derive(Debug)]
pub struct ProvingKey {
    params: halo2_proofs::poly::commitment::Params<vesta::Affine>,
    pk: plonk::ProvingKey<vesta::Affine>,
}

impl ProvingKey {
    /// Builds the proving key.
    pub fn build() -> Self {
        let params = halo2_proofs::poly::commitment::Params::new(K);
        let circuit: Circuit = Default::default();

        let vk = plonk::keygen_vk(&params, &circuit).unwrap();
        let pk = plonk::keygen_pk(&params, vk, &circuit).unwrap();

        ProvingKey { params, pk }
    }
}

#[derive(Clone)]
pub struct Proof(Vec<u8>);

impl Proof {
    /// Creates a proof for the given circuits and instances.
    pub fn create(
        pk: &ProvingKey,
        circuit: Circuit,
        instance: &[&[pallas::Base]],
        mut rng: impl RngCore,
    ) -> Result<Self, plonk::Error> {
        let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
        plonk::create_proof(
            &pk.params,
            &pk.pk,
            &[circuit],
            &[instance],
            &mut rng,
            &mut transcript,
        )?;
        Ok(Proof(transcript.finalize()))
    }

    /// Verifies this proof with the given instances.
    pub fn verify(
        &self,
        vk: &VerifyingKey,
        instance: &[&[pallas::Base]],
    ) -> Result<(), plonk::Error> {
        let strategy = SingleVerifier::new(&vk.params);
        let mut transcript = Blake2bRead::init(&self.0[..]);
        plonk::verify_proof(&vk.params, &vk.vk, strategy, &[instance], &mut transcript)
    }

    /// Constructs a new Proof value.
    pub fn new(bytes: Vec<u8>) -> Self {
        Proof(bytes)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use ff::Field;
    use halo2_gadgets::poseidon::primitives::P128Pow5T5;
    use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash, P128Pow5T3};
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::plonk::Circuit as PlonkCircuit;
    use halo2_proofs::plonk::ConstraintSystem;
    use pasta_curves::pallas;
    use rand::rngs::OsRng;

    use super::{Proof, ProvingKey, VerifyingKey};

    use super::Circuit;

    #[test]
    fn test_estim_2() {
        type Fp = pallas::Base;

        let mut rng = OsRng;
        let x = Fp::random(&mut rng);
        let y = Fp::random(&mut rng);
        let z = Fp::random(&mut rng);
        let t = Fp::random(&mut rng);

        let hasher2 = Hash::<_, P128Pow5T3, ConstantLength<2>, 3, 2>::init();
        let h_x_y = hasher2.hash([x, y]);

        let hasher4 = Hash::<_, P128Pow5T5, ConstantLength<4>, 5, 4>::init();
        let h_x_y_z_t = hasher4.hash([x, y, z, t]);

        let _instance = [
            [h_x_y_z_t.clone(); super::NB_POSEIDON4].as_slice(),
            [h_x_y.clone(); super::NB_POSEIDON2].as_slice(),
        ]
        .concat();
        let instance = _instance.as_slice();

        let circuit = Circuit { x, y, z, t };

        // // this lets you know the minimum number for K from the config:
        // let mut cs = ConstraintSystem::<Fp>::default();
        // let config = <Circuit as PlonkCircuit<Fp>>::configure(&mut cs);
        // println!("{}", cs.minimum_rows());

        // // I don't know how to get the actual K... so I kind of do it by hand...
        // let mut k:usize = 18;
        // while MockProver::run(k.try_into().unwrap(), &circuit, vec![instance.to_vec()]).unwrap().verify() == Ok(()) {
        //     println!("k={}", k);
        //     k = k-1;
        // }

        assert_eq!(
            MockProver::run(super::K, &circuit, vec![instance.to_vec()])
                .unwrap()
                .verify(),
            Ok(())
        );

        let time = Instant::now();
        let vk = VerifyingKey::build();
        let pk = ProvingKey::build();
        println!(
            "key generation: \t{:?}ms",
            (Instant::now() - time).as_millis()
        );

        let mut rng = OsRng;
        let time = Instant::now();
        let proof = Proof::create(&pk, circuit, &[instance], &mut rng).unwrap();
        println!("proof: \t\t\t{:?}ms", (Instant::now() - time).as_millis());

        let time = Instant::now();
        assert!(proof.verify(&vk, &[instance]).is_ok());
        println!(
            "verification: \t\t{:?}ms",
            (Instant::now() - time).as_millis()
        );
    }
}
