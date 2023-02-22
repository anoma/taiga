use std::ops::Mul;

use ff::PrimeField;
use group::Curve;
use halo2_proofs::{
    arithmetic::{CurveExt, FieldExt, SqrtRatio},
    circuit::{floor_planner, AssignedCell, Layouter, Value},
    plonk::{self, Advice, Column, Instance as InstanceColumn},
};
use pasta_curves::{pallas, Fp};

use crate::{
    circuit::gadgets::{
        assign_free_advice, assign_free_instance, AddChip, AddConfig, AddInstructions, MulChip,
        MulConfig, MulInstructions, SubChip, SubConfig, SubInstructions,
    },
    constant::{
        NoteCommitmentDomain, NoteCommitmentFixedBases, NoteCommitmentFixedBasesFull,
        NoteCommitmentHashDomain, NullifierK, NOTE_COMMIT_DOMAIN,
    },
};
use halo2_gadgets::{
    ecc::{
        chip::{EccChip, EccConfig},
        FixedPoint, FixedPointBaseField, FixedPoints, NonIdentityPoint, ScalarFixed, ScalarVar,
    },
    poseidon::{
        primitives::{self as poseidon, ConstantLength, P128Pow5T3},
        Hash as PoseidonHash, Pow5Chip as PoseidonChip, Pow5Config as PoseidonConfig,
    },
    sinsemilla::chip::{SinsemillaChip, SinsemillaConfig},
    utilities::lookup_range_check::LookupRangeCheckConfig,
};

use group::prime::PrimeCurveAffine;
use group::Group;
#[derive(Clone, Debug)]
pub struct SchnorrConfig {
    primary: Column<InstanceColumn>,
    advices: [Column<Advice>; 10],
    add_config: AddConfig,
    sub_config: SubConfig,
    mul_config: MulConfig,
    ecc_config: EccConfig<NoteCommitmentFixedBases>, // TODO: Maybe replace
    poseidon_config: PoseidonConfig<pallas::Base, 3, 2>,
    sinsemilla_config:
        SinsemillaConfig<NoteCommitmentHashDomain, NoteCommitmentDomain, NoteCommitmentFixedBases>,
}

impl SchnorrConfig {
    pub(super) fn add_chip(&self) -> AddChip<pallas::Base> {
        AddChip::construct(self.add_config.clone(), ())
    }

    pub(super) fn sub_chip(&self) -> SubChip<pallas::Base> {
        SubChip::construct(self.sub_config.clone(), ())
    }

    pub(super) fn mul_chip(&self) -> MulChip<pallas::Base> {
        MulChip::construct(self.mul_config.clone())
    }

    pub(super) fn ecc_chip(&self) -> EccChip<NoteCommitmentFixedBases> {
        EccChip::construct(self.ecc_config.clone())
    }

    pub(super) fn poseidon_chip(&self) -> PoseidonChip<pallas::Base, 3, 2> {
        PoseidonChip::construct(self.poseidon_config.clone())
    }
}

#[derive(Clone, Debug, Default)]
pub struct SchnorrCircuit {
    // message
    m: pallas::Base,
    // public key
    pk: pallas::Point,
    // signature (r,s)
    r: pallas::Point,
    s: pallas::Scalar,
}

impl plonk::Circuit<pallas::Base> for SchnorrCircuit {
    type Config = SchnorrConfig;
    type FloorPlanner = floor_planner::V1;

    fn without_witnesses(&self) -> Self {
        const K: u32 = 13;
        let G = NOTE_COMMIT_DOMAIN.R();
        // Message hash: m
        let m = pallas::Base::one();
        // Private key: sk
        let sk = pallas::Scalar::from(7);
        // Public key: P = sk*G
        let pk = G * sk;
        let (p, _, _) = pk.jacobian_coordinates();
        // Generate a random number: z
        let z = pallas::Scalar::from(9);
        // Calculate: R = z*G
        let R = G * z;
        // where: r = X-coordinate of curve point R
        //        and || denotes binary concatenation
        let (r, _, _) = R.jacobian_coordinates();
        // Calculate: s = z + Hash(r||P||m)*sk
        // let h = mod_r_p(poseidon_hash_4(r, p, m));
        let h = pallas::Scalar::one();
        let s = z + h * sk;
        SchnorrCircuit { m, pk, r: R, s }
        // sG = R + hP
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

        // Addition of two field elements.
        let add_config = AddChip::configure(meta, [advices[0], advices[1]]);

        // Substraction of two field elements.
        let sub_config = SubChip::configure(meta, [advices[0], advices[1]]);

        // Multiplication of two field elements.
        let mul_config = MulChip::configure(meta, [advices[0], advices[1]]);

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

        let table_idx = meta.lookup_table_column();

        let range_check = LookupRangeCheckConfig::configure(meta, advices[9], table_idx);

        let lookup = (
            table_idx,
            meta.lookup_table_column(),
            meta.lookup_table_column(),
        );
        let sinsemilla_config = SinsemillaChip::<
            NoteCommitmentHashDomain,
            NoteCommitmentDomain,
            NoteCommitmentFixedBases,
        >::configure(
            meta,
            advices[..5].try_into().unwrap(),
            advices[2],
            lagrange_coeffs[0],
            lookup,
            range_check,
        );

        let ecc_config = EccChip::<NoteCommitmentFixedBases>::configure(
            meta,
            advices,
            lagrange_coeffs,
            range_check,
        );
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
        ];
        let rc_a = lagrange_coeffs[2..5].try_into().unwrap();
        let rc_b = lagrange_coeffs[5..8].try_into().unwrap();

        // Also use the first Lagrange coefficient column for loading global constants.
        // It's free real estate :)
        meta.enable_constant(lagrange_coeffs[0]);

        // Configuration for the Poseidon hash.
        let poseidon_config = PoseidonChip::configure::<poseidon::P128Pow5T3>(
            meta,
            // We place the state columns after the partial_sbox column so that the
            // pad-and-add region can be laid out more efficiently.
            advices[0..3].try_into().unwrap(),
            advices[4],
            rc_a,
            rc_b,
        );

        SchnorrConfig {
            primary,
            advices,
            add_config,
            sub_config,
            mul_config,
            ecc_config,
            poseidon_config,
            sinsemilla_config,
        }
    }

    #[allow(non_snake_case)]
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), plonk::Error> {
        SinsemillaChip::<
                NoteCommitmentHashDomain,
                NoteCommitmentDomain,
                NoteCommitmentFixedBases,
            >::load(config.sinsemilla_config, &mut layouter)?;
        // We implement the verification algorithm first
        // and assume that the signature is given
        // Construct an ECC chip
        let ecc_chip = EccChip::construct(config.ecc_config);
        let zero_cell = assign_free_advice(
            layouter.namespace(|| "zero"),
            config.advices[0],
            Value::known(Fp::zero()),
        )?;
        // TODO: Message length (256bits) is bigger than the size of Fp (255bits)
        // Obtain message: m
        let m_cell = assign_free_advice(
            layouter.namespace(|| "message"),
            config.advices[0],
            Value::known(self.m),
        )?;
        // Obtain the signature: (r,s)
        let r_cell = {
            let (r, _, _) = self.r.jacobian_coordinates();
            assign_free_advice(
                layouter.namespace(|| "r"),
                config.advices[0],
                Value::known(r),
            )?
        };
        let s_scalar = ScalarFixed::new(
            ecc_chip.clone(),
            layouter.namespace(|| "s"),
            Value::known(self.s),
        )?;
        // Obtain public key : P
        let p_cell = {
            let (p, _, _) = self.pk.jacobian_coordinates();
            assign_free_advice(
                layouter.namespace(|| "p"),
                config.advices[0],
                Value::known(p),
            )?
        };

        // Verify: s*G = R + Hash(r||P||m)*P
        // s*G
        let generator = FixedPoint::from_inner(ecc_chip.clone(), NoteCommitmentFixedBasesFull);
        let (sG, _) = generator.mul(layouter.namespace(|| "s_scalar * generator"), &s_scalar)?;

        // Hash(r||P||m)
        let h_scalar = {
            let poseidon_chip = PoseidonChip::construct(config.poseidon_config.clone());
            let poseidon_message = [r_cell, p_cell, m_cell, zero_cell];
            let poseidon_hasher =
                PoseidonHash::<_, _, poseidon::P128Pow5T3, ConstantLength<4>, 3, 2>::init(
                    poseidon_chip,
                    layouter.namespace(|| "Poseidon init"),
                )?;
            let h = poseidon_hasher.hash(
                layouter.namespace(|| "Poseidon_hash(r, P, m)"),
                poseidon_message,
            )?;

            let tmp = assign_free_advice(
                layouter.namespace(|| "tmp"),
                config.advices[0],
                Value::known(pallas::Base::one()),
            )?;

            ScalarVar::from_base(
                ecc_chip.clone(),
                layouter.namespace(|| "ScalarVar from_base"),
                &tmp,
                // &h,
            )?
        };

        let R = NonIdentityPoint::new(
            ecc_chip.clone(),
            layouter.namespace(|| "non-identity R"),
            Value::known(self.r.to_affine()),
        )?;
        // Hash(r||P||m)*P
        let (hP, _) = {
            let P = NonIdentityPoint::new(
                ecc_chip.clone(),
                layouter.namespace(|| "non-identity P"),
                Value::known(self.pk.to_affine()),
            )?;
            P.mul(layouter.namespace(|| "hP"), h_scalar)?
        };

        // R + Hash(r||P||m)*P
        let rhs = R.add(layouter.namespace(|| "R + Hash(r||P||m)*P"), &hP)?;

        sG.constrain_equal(layouter.namespace(|| "s*G = R + Hash(r||P||m)*P"), &rhs)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ff::Field;
    use halo2_proofs::{arithmetic::FieldExt, dev::MockProver, plonk::Circuit};
    use plotters::style::full_palette::WHITE;
    use rand::{rngs::OsRng, RngCore};

    use super::SchnorrCircuit;

    use crate::{
        constant::{NOTE_COMMITMENT_R_GENERATOR, NOTE_COMMIT_DOMAIN},
        proof::Proof,
        utils::{mod_r_p, poseidon_hash_4},
    };
    use halo2_proofs::{
        plonk::{self, ProvingKey, VerifyingKey},
        poly::commitment::Params,
    };
    use pasta_curves::{pallas, vesta};
    use std::time::Instant;

    use std::{
        collections::hash_map::DefaultHasher,
        hash::{Hash, Hasher},
    };

    fn calculate_hash<T: Hash + ?Sized>(t: &T) -> u64 {
        let mut s = DefaultHasher::new();
        t.hash(&mut s);
        s.finish()
    }

    fn plot_it<F: Field, ConcreteCircuit: Circuit<F>>(circuit: &ConcreteCircuit) {
        // ------- PLOTTING SECTION --------
        use plotters::prelude::*;
        let root = BitMapBackend::new("schnorr.png", (1024, 768)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root.titled("Schnorr Layout", ("sans-serif", 40)).unwrap();

        halo2_proofs::dev::CircuitLayout::default()
            // You can optionally render only a section of the circuit.
            // .view_width(0..7)
            // .view_height(0..60)
            // You can hide labels, which can be useful with smaller areas.
            .show_labels(true)
            // Render the circuit onto your area!
            // The first argument is the size parameter for the circuit.
            .render(9, circuit, &root)
            .unwrap();

        let dot_string = halo2_proofs::dev::circuit_dot_graph(circuit);

        // Now you can either handle it in Rust, or just
        // print it out to use with command-line tools.
        print!("{}", dot_string);
        // ---- END OF PLOTTING SECTION --------
    }

    #[test]
    fn test_schnorr() {
        use group::{prime::PrimeCurveAffine, Curve, Group};
        use pasta_curves::{arithmetic::CurveExt, pallas::Point};
        let mut rng = OsRng;
        const K: u32 = 13;
        let G = NOTE_COMMIT_DOMAIN.R();
        // Message hash: m
        let m = pallas::Base::from(calculate_hash(
            "Every day you play with the light of the universe. Subtle visitor",
        ));
        // Private key: sk
        let sk = pallas::Scalar::from(rng.next_u64());
        // Public key: P = sk*G
        let pk = G * sk;
        let (p, _, _) = pk.jacobian_coordinates();
        // Generate a random number: z
        let z = pallas::Scalar::from(rng.next_u64());
        // Calculate: R = z*G
        let r = G * z;
        // Calculate: s = z + Hash(r||P||m)*sk
        // let h = mod_r_p(poseidon_hash_4(r, p, m));
        let h = pallas::Scalar::one();
        let s = z + h * sk;
        // Signature = (r, s)
        let circuit = SchnorrCircuit { m, pk, r, s };

        plot_it(&circuit);

        let prover = MockProver::run(K, &circuit, vec![vec![]]).unwrap();
        prover.assert_satisfied();

        let time = Instant::now();
        let params = Params::new(K);

        let vk = plonk::keygen_vk(&params, &circuit).unwrap();
        let pk = plonk::keygen_pk(&params, vk.clone(), &circuit).unwrap();
        println!(
            "key generation: \t{:?}ms",
            (Instant::now() - time).as_millis()
        );

        let time = Instant::now();
        let proof = Proof::create(&pk, &params, circuit, &[&[]], &mut rng).unwrap();
        println!("proof: \t\t\t{:?}ms", (Instant::now() - time).as_millis());

        let time = Instant::now();
        assert!(proof.verify(&vk, &params, &[&[]]).is_ok());
        println!(
            "verification: \t\t{:?}ms",
            (Instant::now() - time).as_millis()
        );
    }
}
