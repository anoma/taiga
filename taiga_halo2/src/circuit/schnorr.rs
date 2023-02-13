use ff::PrimeField;
use halo2_proofs::{
    arithmetic::{FieldExt, CurveExt},
    circuit::{floor_planner, AssignedCell, Layouter, Value},
    plonk::{self, Advice, Column, Instance as InstanceColumn},
};
use pasta_curves::{pallas, Fp};

use halo2_gadgets::{
    poseidon::{
    primitives::{self as poseidon, P128Pow5T3, ConstantLength},
    Pow5Chip as PoseidonChip, Pow5Config as PoseidonConfig, Hash as PoseidonHash
    },
    ecc::{chip::{EccConfig, EccChip}, FixedPoints, FixedPoint, FixedPointBaseField, ScalarFixed}, utilities::lookup_range_check::LookupRangeCheckConfig
};
use crate::{circuit::gadgets::{
    assign_free_advice, assign_free_instance, AddChip, AddConfig, AddInstructions, MulChip,
    MulConfig, MulInstructions, SubChip, SubConfig, SubInstructions,
}, constant::{NoteCommitmentFixedBases, NullifierK, NoteCommitmentFixedBasesFull}};

#[derive(Clone, Debug)]
pub struct SchnorrConfig {
    primary: Column<InstanceColumn>,
    advices: [Column<Advice>; 10],
    add_config: AddConfig,
    sub_config: SubConfig,
    mul_config: MulConfig,
    ecc_config: EccConfig<NoteCommitmentFixedBases>, // TODO: Maybe replace
    poseidon_config: PoseidonConfig<pallas::Base, 3, 2>,
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
    vk: pallas::Point,
    // signature (r,s)
    r: pallas::Base,
    s: pallas::Scalar
}

impl plonk::Circuit<pallas::Base> for SchnorrCircuit {
    type Config = SchnorrConfig;
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


        let ecc_config = EccChip::<NoteCommitmentFixedBases>::configure(meta, advices, lagrange_coeffs, range_check);
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
        }
    }

    #[allow(non_snake_case)]
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), plonk::Error> {
        // We implement the verification algorithm first
        // and assume that the signature is given
        // Obtain the signature: (r,s)
        // Obtain public key : P
        // Obtain message: m
        // TODO: Obtain signature, public key and message from witness
        // Calculate the random point R from r
        // Verify: s*G = R + Hash(r||P||m)*P
        // Construct an ECC chip
        let ecc_chip = EccChip::construct(config.ecc_config);
        let m_cell = assign_free_advice(
            layouter.namespace(|| "message"),
            config.advices[0],
            Value::known(self.m),
        )?;
        let r_cell = assign_free_advice(
            layouter.namespace(|| "message"),
            config.advices[0],
            Value::known(self.r),
        )?;
        let p_cell = {
            let (p, _, _) = self.vk.jacobian_coordinates();
            assign_free_advice(
                layouter.namespace(|| "message"),
                config.advices[0],
                Value::known(p),
            )?
        };
    
        let s_scalar = ScalarFixed::new(
            ecc_chip.clone(),
            layouter.namespace(|| "s"),
            Value::known(self.s),
        )?;

        let generator = FixedPoint::from_inner(ecc_chip, NoteCommitmentFixedBasesFull);
        let (sG, _) = generator.mul(
            layouter.namespace(|| "s_scalar * generator"),
            &s_scalar,
        )?;

        let poseidon_chip = PoseidonChip::construct(config.poseidon_config.clone());
        let poseidon_message = [r_cell, p_cell, m_cell];
        let poseidon_hasher =
            PoseidonHash::<_, _, poseidon::P128Pow5T3, ConstantLength<3>, 3, 2>::init(
                poseidon_chip,
                layouter.namespace(|| "Poseidon init"),
            )?;
        let h = poseidon_hasher.hash(
            layouter.namespace(|| "Poseidon_hash(r, P, m)"),
            poseidon_message,
        )?;
    
        // let _ = add_chip.add(
        //     layouter.namespace(|| ""),
        //     &hash_nk_rho,
        //     &psi,
        // )?;


        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::{arithmetic::FieldExt, dev::MockProver};
    use rand::{rngs::OsRng, RngCore};

    use super::SchnorrCircuit;

    use halo2_proofs::{
        plonk::{self, ProvingKey, VerifyingKey},
        poly::commitment::Params,
    };
    use pasta_curves::{pallas, vesta};
    use std::time::Instant;
    use crate::proof::Proof;

    use std::{collections::hash_map::DefaultHasher, hash::{Hasher, Hash}};

    fn calculate_hash<T: Hash + ?Sized>(t: &T) -> u64 {
        let mut s = DefaultHasher::new();
        t.hash(&mut s);
        s.finish()
    }

    #[test]
    fn test_schnorr() {
        use group::{prime::PrimeCurveAffine, Curve, Group};
        use pasta_curves::arithmetic::CurveExt;


        let mut rng = OsRng;
        let G = pallas::Point::generator();
        let m = pallas::Base::from(calculate_hash("Every day you play with the light of the universe"));
        let sk = pallas::Scalar::from(rng.next_u64());
        let vk = G * sk;

        let z = pallas::Scalar::from(rng.next_u64());
        let R = G * z;
        let (r, _, _) = R.jacobian_coordinates();
        let mut rb = {
            let r2 = <[u8; 32]>::from(r);
            vec!(r2)
        };

        let mb = {
            let m1 = <[u8; 32]>::from(m);
            vec!(m1) 
        };
        let s = z + pallas::Scalar::from(calculate_hash(&rb.extend(mb)));
        let circuit = SchnorrCircuit { m, vk, r, s };

        // const K: u32 = 13;
        // let zeros = [pallas::Base::zero(); 27];
        // let mut pub_instance_vec = zeros.to_vec();
        // pub_instance_vec.append(&mut vec_puzzle);
        // assert_eq!(
        //     MockProver::run(13, &circuit, vec![pub_instance_vec.clone()])
        //         .unwrap()
        //         .verify(),
        //     Ok(())
        // );
        // let pub_instance: [pallas::Base; 108] = pub_instance_vec.try_into().unwrap();

        // println!("Success!");
        // let time = Instant::now();
        // let params = Params::new(K);

        // let vk = plonk::keygen_vk(&params, &circuit).unwrap();
        // let pk = plonk::keygen_pk(&params, vk.clone(), &circuit).unwrap();
        // println!(
        //     "key generation: \t{:?}ms",
        //     (Instant::now() - time).as_millis()
        // );

        // let time = Instant::now();
        // let proof = Proof::create(&pk, &params, circuit, &[&pub_instance], &mut rng).unwrap();
        // println!("proof: \t\t\t{:?}ms", (Instant::now() - time).as_millis());

        // let time = Instant::now();
        // assert!(proof.verify(&vk, &params, &[&pub_instance]).is_ok());
        // println!(
        //     "verification: \t\t{:?}ms",
        //     (Instant::now() - time).as_millis()
        // );
    }
}