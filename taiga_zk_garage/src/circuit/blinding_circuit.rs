use crate::circuit::circuit_parameters::CircuitParameters;
use crate::circuit::vp_examples::field_addition::FieldAdditionValidityPredicate;
use crate::constant::BLINDING_CIRCUIT_SIZE;
use crate::poseidon::WIDTH_9;
use crate::vp_description::ValidityPredicateDescription;
use ark_ec::twisted_edwards_extended::GroupAffine as TEGroupAffine;
use ark_ff::UniformRand;
use ark_ff::{BigInteger, PrimeField};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::PolynomialCommitment;

use plonk_core::{
    circuit::Circuit, constraint_system::StandardComposer, prelude::Error, prelude::Variable,
    proof_system::Blinding,
};
use plonk_hashing::poseidon::{
    constants::PoseidonConstants,
    poseidon::{PlonkSpec, Poseidon},
};
use rand::RngCore;
const BLINDING_PC_NUM: usize = 6;

pub struct BlindingCircuit<CP: CircuitParameters> {
    vp_desc: ValidityPredicateDescription<CP>,
    blinding: Blinding<CP::CurveScalarField>,
    zh: [CP::CurveBaseField; 2],
}

impl<CP> Circuit<CP::CurveBaseField, CP::Curve> for BlindingCircuit<CP>
where
    CP: CircuitParameters,
{
    const CIRCUIT_ID: [u8; 32] = [0x01; 32];

    // Default implementation
    fn gadget(
        &mut self,
        composer: &mut StandardComposer<CP::CurveBaseField, CP::Curve>,
    ) -> Result<(), Error> {
        // parse the public inputs (todo is Com(Z_H) a public input?)
        let com_z_h = TEGroupAffine::<CP::Curve>::new(self.zh[0], self.zh[1]);

        let blind_vec = vec![
            self.blinding.q_m,
            self.blinding.q_l,
            self.blinding.q_r,
            self.blinding.q_o,
            self.blinding.q_4,
            self.blinding.q_c,
        ];
        assert_eq!(blind_vec.len(), BLINDING_PC_NUM);
        let vp_desc = self.vp_desc.get_pack().unwrap();

        // Constrain vp blinding
        for (point, blind) in vp_desc[0..2 * BLINDING_PC_NUM]
            .chunks(2)
            .zip(blind_vec.iter())
        {
            let q = composer.add_affine(TEGroupAffine::<CP::Curve>::new(point[0], point[1]));
            let blind_convert =
                CP::CurveBaseField::from_le_bytes_mod_order(&blind.into_repr().to_bytes_le());
            let b = composer.add_input(blind_convert);
            let b_zh = composer.fixed_base_scalar_mul(b, com_z_h);
            let b_zh_add_q = composer.point_addition_gate(q, b_zh);

            // public blinded point
            composer.public_inputize(b_zh_add_q.x());
            composer.public_inputize(b_zh_add_q.y());
        }

        // Constrain Com_q(vp_desc)
        let poseidon_param_9: PoseidonConstants<CP::CurveBaseField> =
            PoseidonConstants::generate::<WIDTH_9>();
        let mut poseidon_circuit =
            Poseidon::<_, PlonkSpec<WIDTH_9>, WIDTH_9>::new(composer, &poseidon_param_9);

        let hash_vec = vp_desc
            .chunks_exact(8)
            .map(|chunk| {
                poseidon_circuit.reset(composer);
                for x in chunk.iter() {
                    let var = composer.add_input(*x);
                    poseidon_circuit.input(var).unwrap();
                }
                poseidon_circuit.output_hash(composer)
            })
            .collect::<Vec<Variable>>();

        poseidon_circuit.reset(composer);
        for v in hash_vec.iter() {
            poseidon_circuit.input(*v).unwrap();
        }
        let compressed_vp_desc = poseidon_circuit.output_hash(composer);

        // public compressed_vp_desc for test, remove it when implemented com_vp.
        composer.public_inputize(&compressed_vp_desc);

        // TODO: Constrain com_vp

        println!("circuit size: {}", composer.circuit_bound());
        composer.check_circuit_satisfied();
        Ok(())
    }

    fn padded_circuit_size(&self) -> usize {
        BLINDING_CIRCUIT_SIZE
    }
}

impl<CP: CircuitParameters> BlindingCircuit<CP> {
    pub fn new(
        rng: &mut impl RngCore,
        vp_desc: ValidityPredicateDescription<CP>,
        vp_setup: &<CP::CurvePC as PolynomialCommitment<
            CP::CurveScalarField,
            DensePolynomial<CP::CurveScalarField>,
        >>::UniversalParams,
        vp_circuit_size: usize,
    ) -> Result<Self, Error> {
        let blinding = Blinding::<CP::CurveScalarField>::rand(rng);
        let zh = CP::get_zh(vp_setup, vp_circuit_size);

        Ok(Self {
            vp_desc,
            blinding,
            zh,
        })
    }

    pub fn get_blinding(&self) -> Blinding<CP::CurveScalarField> {
        self.blinding
    }

    pub fn dummy(rng: &mut impl RngCore) -> Self {
        let blinding = Blinding::<CP::CurveScalarField>::rand(rng);
        let mut dummy_vp = FieldAdditionValidityPredicate::<CP>::dummy(rng);
        let vp_circuit_size = dummy_vp.padded_circuit_size();
        let vp_setup = CP::get_pc_setup_params(vp_circuit_size);
        let vp_desc = ValidityPredicateDescription::from_vp(&mut dummy_vp, vp_setup).unwrap();
        let zh = CP::get_zh(vp_setup, vp_circuit_size);

        Self {
            vp_desc,
            blinding,
            zh,
        }
    }
}

#[ignore]
#[test]
fn test_blinding_circuit() {
    // creation of a (balance) VP
    // creation of the corresponding blinding circuit
    // checking the blinding circuit

    use crate::circuit::circuit_parameters::PairingCircuitParameters as CP;
    use crate::circuit::validity_predicate::NUM_NOTE;
    use crate::circuit::vp_examples::balance::BalanceValidityPredicate;
    use crate::note::Note;
    use crate::utils::ws_to_te;
    use crate::vp_description::ValidityPredicateDescription;
    use plonk_core::circuit::{verify_proof, VerifierData};
    use plonk_core::proof_system::pi::PublicInputs;
    type Fr = <CP as CircuitParameters>::CurveScalarField;
    type Fq = <CP as CircuitParameters>::CurveBaseField;
    type P = <CP as CircuitParameters>::InnerCurve;
    type OP = <CP as CircuitParameters>::Curve;
    type PC = <CP as CircuitParameters>::CurvePC;
    type Opc = <CP as CircuitParameters>::OuterCurvePC;
    use ark_std::test_rng;

    let mut rng = test_rng();

    // A balance VP
    let input_notes = [(); NUM_NOTE].map(|_| Note::<CP>::dummy(&mut rng));
    let output_notes = input_notes.clone();
    let mut balance_vp = BalanceValidityPredicate::new(input_notes, output_notes);
    balance_vp
        .gadget(&mut StandardComposer::<Fr, P>::new())
        .unwrap();

    // we blind the VP desc
    let pp = CP::get_pc_setup_params(balance_vp.padded_circuit_size());
    let vp_desc = ValidityPredicateDescription::from_vp(&mut balance_vp, pp).unwrap();
    let vp_desc_compressed = vp_desc.get_compressed();

    // the blinding circuit, containing the random values used to blind
    let mut blinding_circuit =
        BlindingCircuit::<CP>::new(&mut rng, vp_desc, pp, balance_vp.padded_circuit_size())
            .unwrap();

    // verifying key with the blinding
    let (_, vk_blind) = balance_vp
        .compile_with_blinding::<PC>(pp, &blinding_circuit.get_blinding())
        .unwrap();

    let blinding_circuit_size = blinding_circuit.padded_circuit_size();
    let pp_blind = CP::get_opc_setup_params(blinding_circuit_size);

    let pk = CP::get_blind_vp_pk();
    let vk = CP::get_blind_vp_vk();

    // Blinding Prover
    let (proof, blinding_public_input) = blinding_circuit
        .gen_proof::<Opc>(pp_blind, pk.clone(), b"Test")
        .unwrap();

    // Expecting vk_blind(out of circuit)
    let mut expect_public_input = PublicInputs::new();
    let q_m = ws_to_te(vk_blind.arithmetic.q_m.0);
    expect_public_input.insert(392, q_m.x);
    expect_public_input.insert(393, q_m.y);
    let q_l = ws_to_te(vk_blind.arithmetic.q_l.0);
    expect_public_input.insert(782, q_l.x);
    expect_public_input.insert(783, q_l.y);
    let q_r = ws_to_te(vk_blind.arithmetic.q_r.0);
    expect_public_input.insert(1172, q_r.x);
    expect_public_input.insert(1173, q_r.y);
    let q_o = ws_to_te(vk_blind.arithmetic.q_o.0);
    expect_public_input.insert(1562, q_o.x);
    expect_public_input.insert(1563, q_o.y);
    let q_4 = ws_to_te(vk_blind.arithmetic.q_4.0);
    expect_public_input.insert(1952, q_4.x);
    expect_public_input.insert(1953, q_4.y);
    let q_c = ws_to_te(vk_blind.arithmetic.q_c.0);
    expect_public_input.insert(2342, q_c.x);
    expect_public_input.insert(2343, q_c.y);
    expect_public_input.insert(21388, vp_desc_compressed);

    assert_eq!(blinding_public_input, expect_public_input);

    // Blinding Verifier
    let verifier_data = VerifierData::new(vk.clone(), blinding_public_input);
    verify_proof::<Fq, OP, Opc>(
        pp_blind,
        verifier_data.key,
        &proof,
        &verifier_data.pi,
        b"Test",
    )
    .unwrap();
}
