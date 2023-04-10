use crate::circuit::gadgets::{
    add::{AddChip, AddInstructions},
    assign_free_constant,
};
use crate::constant::{NoteCommitmentFixedBases, NullifierK, POSEIDON_RATE, POSEIDON_WIDTH};
use halo2_gadgets::{
    ecc::{chip::EccChip, FixedPointBaseField, NonIdentityPoint, Point, ScalarVar},
    poseidon::{
        primitives::{self as poseidon, Absorbing, ConstantLength},
        PaddedWord, PoseidonInstructions, PoseidonSpongeInstructions, Pow5Chip as PoseidonChip,
        Pow5Config as PoseidonConfig, StateWord,
    },
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter},
    plonk::{Advice, Column, Error},
};
use pasta_curves::{arithmetic::FieldExt, pallas};

pub struct NoteEncryptionResult {
    pub cipher: Vec<AssignedCell<pallas::Base, pallas::Base>>,
    pub nonce: AssignedCell<pallas::Base, pallas::Base>,
    pub sender_pk: Point<pallas::Affine, EccChip<NoteCommitmentFixedBases>>,
}

#[allow(clippy::too_many_arguments)]
pub fn note_encryption_gadget(
    mut layouter: impl Layouter<pallas::Base>,
    advice: Column<Advice>,
    poseidon_config: PoseidonConfig<pallas::Base, POSEIDON_WIDTH, POSEIDON_RATE>,
    add_chip: AddChip<pallas::Base>,
    ecc_chip: EccChip<NoteCommitmentFixedBases>,
    nonce: AssignedCell<pallas::Base, pallas::Base>,
    sender_sk: AssignedCell<pallas::Base, pallas::Base>,
    rcv_pk: NonIdentityPoint<pallas::Affine, EccChip<NoteCommitmentFixedBases>>,
    message: &Vec<AssignedCell<pallas::Base, pallas::Base>>,
) -> Result<NoteEncryptionResult, Error> {
    // Compute symmetric secret key
    let sk = ScalarVar::from_base(
        ecc_chip.clone(),
        layouter.namespace(|| "ScalarVar from_base"),
        &sender_sk,
    )?;
    let generator = FixedPointBaseField::from_inner(ecc_chip, NullifierK);
    let sender_pk = generator.mul(layouter.namespace(|| "sender_sk * generator"), sender_sk)?;
    let (secret_key, _) = rcv_pk.mul(layouter.namespace(|| "sender_sk * rcv_pk"), sk)?;

    // length_nonce = length * 2^128 + nonce
    let length_var = assign_free_constant(
        layouter.namespace(|| "constant zero"),
        advice,
        pallas::Base::from(message.len() as u64) * pallas::Base::from_u128(1 << 64).square(),
    )?;
    let length_nonce = add_chip.add(
        layouter.namespace(|| "length_nonce = length || nonce"),
        &length_var,
        &nonce,
    )?;

    // Init poseidon sponge state
    let poseidon_chip = PoseidonChip::construct(poseidon_config);
    let init_state = vec![
        StateWord::from(secret_key.inner().x()),
        StateWord::from(secret_key.inner().y()),
        StateWord::from(length_nonce),
    ];
    let mut state = init_state.try_into().unwrap();

    // Encrypt
    let mut cipher: Vec<AssignedCell<pasta_curves::Fp, pasta_curves::Fp>> = vec![];
    for chunk in message.chunks(POSEIDON_RATE) {
        state = <PoseidonChip<_, POSEIDON_WIDTH, POSEIDON_RATE> as PoseidonInstructions<
            pallas::Base,
            poseidon::P128Pow5T3,
            POSEIDON_WIDTH,
            POSEIDON_RATE,
        >>::permute(&poseidon_chip, &mut layouter, &state)?;
        let mut input: Absorbing<_, POSEIDON_RATE> =
            Absorbing::init_with(PaddedWord::Message(chunk[0].clone()));
        chunk
            .iter()
            .enumerate()
            .skip(1)
            .for_each(|(i, m)| input.0[i] = Some(PaddedWord::Message(m.clone())));
        for idx in chunk.len()..POSEIDON_RATE {
            input.0[idx] = Some(PaddedWord::Padding(pallas::Base::zero()));
        }

        state = <PoseidonChip<_, POSEIDON_WIDTH, POSEIDON_RATE> as PoseidonSpongeInstructions<
            pallas::Base,
            poseidon::P128Pow5T3,
            ConstantLength<2>, // ConstantLength<2> is not used
            POSEIDON_WIDTH,
            POSEIDON_RATE,
        >>::add_input(&poseidon_chip, &mut layouter, &state, &input)?;
        state
            .iter()
            .take(chunk.len())
            .for_each(|s| cipher.push(s.clone().into()));
    }

    // Compute MAC
    state = <PoseidonChip<_, POSEIDON_WIDTH, POSEIDON_RATE> as PoseidonInstructions<
        pallas::Base,
        poseidon::P128Pow5T3,
        POSEIDON_WIDTH,
        POSEIDON_RATE,
    >>::permute(&poseidon_chip, &mut layouter, &state)?;
    cipher.push(state[0].clone().into());

    Ok(NoteEncryptionResult {
        cipher,
        nonce,
        sender_pk,
    })
}

#[test]
fn test_halo2_note_encryption_circuit() {
    use crate::circuit::gadgets::add::AddConfig;
    use crate::circuit::gadgets::assign_free_advice;
    use crate::constant::{
        NoteCommitmentDomain, NoteCommitmentFixedBases, NoteCommitmentHashDomain,
    };
    use crate::note_encryption::{NoteCipher, SecretKey};
    use crate::utils::mod_r_p;
    use ff::Field;
    use group::Curve;
    use group::Group;
    use halo2_gadgets::{
        ecc::chip::EccConfig,
        poseidon::{
            primitives as poseidon, Pow5Chip as PoseidonChip, Pow5Config as PoseidonConfig,
        },
        sinsemilla::chip::{SinsemillaChip, SinsemillaConfig},
        utilities::lookup_range_check::LookupRangeCheckConfig,
    };
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error},
    };
    use rand::rngs::OsRng;

    #[derive(Default)]
    struct MyCircuit {
        nonce: pallas::Base,
        sk: pallas::Base,
        rcv_pk: pallas::Point,
        message: [pallas::Base; 3],
    }

    impl Circuit<pallas::Base> for MyCircuit {
        #[allow(clippy::type_complexity)]
        type Config = (
            [Column<Advice>; 10],
            PoseidonConfig<pallas::Base, 3, 2>,
            AddConfig,
            EccConfig<NoteCommitmentFixedBases>,
            // add SinsemillaConfig to load look table, just for test
            SinsemillaConfig<
                NoteCommitmentHashDomain,
                NoteCommitmentDomain,
                NoteCommitmentFixedBases,
            >,
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

            for advice in advices.iter() {
                meta.enable_equality(*advice);
            }

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

            let table_idx = meta.lookup_table_column();
            let lookup = (
                table_idx,
                meta.lookup_table_column(),
                meta.lookup_table_column(),
            );

            let constants = meta.fixed_column();
            meta.enable_constant(constants);

            let range_check = LookupRangeCheckConfig::configure(meta, advices[9], table_idx);
            let poseidon_config = PoseidonChip::configure::<poseidon::P128Pow5T3>(
                meta,
                advices[6..9].try_into().unwrap(),
                advices[5],
                lagrange_coeffs[2..5].try_into().unwrap(),
                lagrange_coeffs[5..8].try_into().unwrap(),
            );

            let add_config = AddChip::configure(meta, advices[0..2].try_into().unwrap());

            let ecc_config = EccChip::<NoteCommitmentFixedBases>::configure(
                meta,
                advices,
                lagrange_coeffs,
                range_check,
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
            (
                advices,
                poseidon_config,
                add_config,
                ecc_config,
                sinsemilla_config,
            )
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<pallas::Base>,
        ) -> Result<(), Error> {
            let (advices, poseidon_config, add_config, ecc_config, sinsemilla_config) = config;
            let ecc_chip = EccChip::construct(ecc_config);
            let add_chip = AddChip::<pallas::Base>::construct(add_config, ());
            SinsemillaChip::<
                NoteCommitmentHashDomain,
                NoteCommitmentDomain,
                NoteCommitmentFixedBases,
            >::load(sinsemilla_config, &mut layouter)?;

            let nonce = assign_free_advice(
                layouter.namespace(|| "witness nonce"),
                advices[0],
                Value::known(self.nonce),
            )?;

            let sk = assign_free_advice(
                layouter.namespace(|| "witness sk"),
                advices[0],
                Value::known(self.sk),
            )?;

            let rcv_pk = NonIdentityPoint::new(
                ecc_chip.clone(),
                layouter.namespace(|| "witness rcv_pv"),
                Value::known(self.rcv_pk.to_affine()),
            )?;

            let message = self
                .message
                .iter()
                .map(|m| {
                    assign_free_advice(
                        layouter.namespace(|| "witness message"),
                        advices[0],
                        Value::known(*m),
                    )
                    .unwrap()
                })
                .collect();

            let ret = note_encryption_gadget(
                layouter.namespace(|| "note encryption"),
                advices[0],
                poseidon_config,
                add_chip,
                ecc_chip,
                nonce,
                sk,
                rcv_pk,
                &message,
            )?;

            let key = SecretKey::from_dh_exchange(&self.rcv_pk, &mod_r_p(self.sk));
            let expect_cipher = NoteCipher::encrypt(&self.message, &key, &self.nonce);
            let expect_cipher_var: Vec<AssignedCell<pallas::Base, pallas::Base>> = expect_cipher
                .cipher
                .iter()
                .map(|c| {
                    assign_free_advice(
                        layouter.namespace(|| "witness message"),
                        advices[0],
                        Value::known(*c),
                    )
                    .unwrap()
                })
                .collect();

            ret.cipher
                .iter()
                .zip(expect_cipher_var.iter())
                .for_each(|(c, expect_c)| {
                    layouter
                        .assign_region(
                            || "constrain result",
                            |mut region| region.constrain_equal(c.cell(), expect_c.cell()),
                        )
                        .unwrap()
                });

            Ok(())
        }
    }

    let mut rng = OsRng;
    let circuit = MyCircuit {
        nonce: pallas::Base::random(&mut rng),
        sk: pallas::Base::random(&mut rng),
        rcv_pk: pallas::Point::random(&mut rng),
        message: vec![
            pallas::Base::random(&mut rng),
            pallas::Base::random(&mut rng),
            pallas::Base::random(&mut rng),
        ]
        .try_into()
        .unwrap(),
    };

    let prover = MockProver::run(11, &circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()))
}
