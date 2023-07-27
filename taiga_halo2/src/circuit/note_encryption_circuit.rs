use crate::circuit::gadgets::{
    add::{AddChip, AddInstructions},
    assign_free_advice, assign_free_constant,
};
use crate::constant::{
    BaseFieldGenerators, TaigaFixedBases, NOTE_ENCRYPTION_PLAINTEXT_NUM, POSEIDON_RATE,
    POSEIDON_WIDTH, VP_CIRCUIT_NOTE_ENCRYPTION_PUBLIC_INPUT_BEGIN_IDX,
};
use ff::PrimeField;
use halo2_gadgets::{
    ecc::{chip::EccChip, FixedPointBaseField, NonIdentityPoint, ScalarVar},
    poseidon::{
        primitives::{self as poseidon, Absorbing, ConstantLength},
        PaddedWord, PoseidonInstructions, PoseidonSpongeInstructions, Pow5Chip as PoseidonChip,
        Pow5Config as PoseidonConfig, StateWord,
    },
};
use halo2_proofs::plonk::Instance;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, Error},
};
use pasta_curves::pallas;

#[allow(clippy::too_many_arguments)]
pub fn note_encryption_gadget(
    mut layouter: impl Layouter<pallas::Base>,
    advice: Column<Advice>,
    instances: Column<Instance>,
    poseidon_config: PoseidonConfig<pallas::Base, POSEIDON_WIDTH, POSEIDON_RATE>,
    add_chip: AddChip<pallas::Base>,
    ecc_chip: EccChip<TaigaFixedBases>,
    nonce: AssignedCell<pallas::Base, pallas::Base>,
    sender_sk: AssignedCell<pallas::Base, pallas::Base>,
    rcv_pk: NonIdentityPoint<pallas::Affine, EccChip<TaigaFixedBases>>,
    message: &mut Vec<AssignedCell<pallas::Base, pallas::Base>>,
) -> Result<(), Error> {
    // message padding
    let padding_zero = assign_free_advice(
        layouter.namespace(|| "padding zero"),
        advice,
        Value::known(pallas::Base::zero()),
    )?;
    let paddings =
        std::iter::repeat(padding_zero).take(NOTE_ENCRYPTION_PLAINTEXT_NUM - message.len());
    message.extend(paddings);

    // Compute symmetric secret key
    let sk = ScalarVar::from_base(
        ecc_chip.clone(),
        layouter.namespace(|| "ScalarVar from_base"),
        &sender_sk,
    )?;
    let generator = FixedPointBaseField::from_inner(ecc_chip, BaseFieldGenerators::BaseGenerator);
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

    // Add nonce
    cipher.push(nonce);

    // Compute MAC
    state = <PoseidonChip<_, POSEIDON_WIDTH, POSEIDON_RATE> as PoseidonInstructions<
        pallas::Base,
        poseidon::P128Pow5T3,
        POSEIDON_WIDTH,
        POSEIDON_RATE,
    >>::permute(&poseidon_chip, &mut layouter, &state)?;
    cipher.push(state[0].clone().into());

    // Add sender's pk
    cipher.push(sender_pk.inner().x());
    cipher.push(sender_pk.inner().y());

    // Publicize the cipher
    for (i, ele) in cipher.iter().enumerate() {
        layouter.constrain_instance(
            ele.cell(),
            instances,
            VP_CIRCUIT_NOTE_ENCRYPTION_PUBLIC_INPUT_BEGIN_IDX + i,
        )?;
    }

    Ok(())
}
