use crate::action::Action;
use crate::circuit::action_circuit::ActionCircuit;
use crate::circuit::blinding_circuit::BlindingCircuit;
use crate::circuit::circuit_parameters::CircuitParameters;
use crate::circuit::validity_predicate::{ValidityPredicate, NUM_NOTE};
use crate::constant::{
    ACTION_CIRCUIT_SIZE, ACTION_PUBLIC_INPUT_CM_INDEX, ACTION_PUBLIC_INPUT_NF_INDEX,
    ACTION_PUBLIC_INPUT_ROOT_INDEX, BLINDING_CIRCUIT_SIZE,
};
use crate::error::TaigaError;
use crate::vp_description::ValidityPredicateDescription;
use plonk_core::circuit::Circuit;
use plonk_core::circuit::{verify_proof, VerifierData};
use plonk_core::proof_system::{pi::PublicInputs, Proof, VerifierKey};
use rand::RngCore;

pub const NUM_TX_SLICE: usize = NUM_NOTE;

pub struct Transaction<CP: CircuitParameters> {
    pub action_slices: [ActionSlice<CP>; NUM_TX_SLICE],
    pub spend_slices: [SpendSlice<CP>; NUM_TX_SLICE],
    pub output_slices: [OutputSlice<CP>; NUM_TX_SLICE],
}

pub struct ActionSlice<CP: CircuitParameters> {
    pub action_proof: Proof<CP::CurveScalarField, CP::CurvePC>,
    pub action_public: Action<CP>,
}

pub struct SpendSlice<CP: CircuitParameters> {
    spend_addr_vp: VPCheck<CP>,
    spend_token_vp: VPCheck<CP>,
}

pub struct OutputSlice<CP: CircuitParameters> {
    output_addr_vp: VPCheck<CP>,
    output_token_vp: VPCheck<CP>,
}

pub struct VPCheck<CP: CircuitParameters> {
    // VP circuit size
    pub vp_circuit_size: usize,
    // VP proof
    pub vp_proof: Proof<CP::CurveScalarField, CP::CurvePC>,
    // The public inputs for vp proof
    // TODO: maybe the PublicInputs<CP::CurveScalarField> should be serialized from Vec<CP::CurveScalarField>, like the action_public in ActionSlice?
    pub vp_public_inputs: PublicInputs<CP::CurveScalarField>,
    // The vk of vp is blinded partially, blinded parts can be constructed from blinded_vp_public_inputs.
    // The unblinded_vp_vk is the unblinded parts.
    // TODO:
    pub unblinded_vp_vk: VerifierKey<CP::CurveScalarField, CP::CurvePC>,
    // blind vp proof
    pub blind_vp_proof: Proof<CP::CurveBaseField, CP::OuterCurvePC>,
    // The public inputs for blind vp proof
    pub blinded_vp_public_inputs: PublicInputs<CP::CurveBaseField>,
    // TODO:
    // pub vp_com
    // pub vp_param
    // pub vp_memo
}

impl<CP: CircuitParameters> SpendSlice<CP> {
    pub fn new(spend_addr_vp: VPCheck<CP>, spend_token_vp: VPCheck<CP>) -> Self {
        Self {
            spend_addr_vp,
            spend_token_vp,
        }
    }
}

impl<CP: CircuitParameters> OutputSlice<CP> {
    pub fn new(output_addr_vp: VPCheck<CP>, output_token_vp: VPCheck<CP>) -> Self {
        Self {
            output_addr_vp,
            output_token_vp,
        }
    }
}

impl<CP: CircuitParameters> ActionSlice<CP> {
    pub fn build(
        action_public: Action<CP>,
        action_circuit: &mut ActionCircuit<CP>,
    ) -> Result<Self, TaigaError> {
        let setup = CP::get_pc_setup_params(ACTION_CIRCUIT_SIZE);
        // Compile the circuit
        let pk_p = CP::get_action_pk();
        let vk = CP::get_action_vk();

        // Prover
        let (action_proof, pi) =
            action_circuit.gen_proof::<CP::CurvePC>(setup, pk_p.clone(), b"Test")?;

        // Verifier
        let verifier_data = VerifierData::new(vk.clone(), pi);
        verify_proof::<CP::CurveScalarField, CP::InnerCurve, CP::CurvePC>(
            setup,
            verifier_data.key,
            &action_proof,
            &verifier_data.pi,
            b"Test",
        )?;

        Ok(Self {
            action_public,
            action_proof,
        })
    }

    pub fn verify(&self) -> Result<(), TaigaError> {
        let mut action_pi = PublicInputs::new(ACTION_CIRCUIT_SIZE);
        action_pi.insert(ACTION_PUBLIC_INPUT_NF_INDEX, self.action_public.nf.inner());
        action_pi.insert(ACTION_PUBLIC_INPUT_ROOT_INDEX, self.action_public.root);
        action_pi.insert(ACTION_PUBLIC_INPUT_CM_INDEX, self.action_public.cm.inner());

        let action_vk = CP::get_action_vk();
        let verifier_data = VerifierData::new(action_vk.clone(), action_pi);
        let action_setup = CP::get_pc_setup_params(ACTION_CIRCUIT_SIZE);
        verify_proof::<CP::CurveScalarField, CP::InnerCurve, CP::CurvePC>(
            action_setup,
            verifier_data.key,
            &self.action_proof,
            &verifier_data.pi,
            b"Test",
        )?;
        Ok(())
    }
}

impl<CP: CircuitParameters> VPCheck<CP> {
    pub fn build<VP>(vp: &mut VP, rng: &mut impl RngCore) -> Result<Self, TaigaError>
    where
        VP: ValidityPredicate<CP>,
    {
        let vp_circuit_size = vp.padded_circuit_size();
        // Get vp proof setup
        let vp_setup = CP::get_pc_setup_params(vp_circuit_size);
        // Generate blinding circuit for vp
        let vp_desc = ValidityPredicateDescription::from_vp(vp, vp_setup)?;
        // let vp_desc_compressed = vp_desc.get_compress();
        let mut blinding_circuit =
            BlindingCircuit::<CP>::new(rng, vp_desc, vp_setup, vp_circuit_size)?;

        // Compile vp(must use compile_with_blinding)
        let (pk_p, vk_blind) =
            vp.compile_with_blinding::<CP::CurvePC>(vp_setup, &blinding_circuit.get_blinding())?;

        // VP Prover
        let (vp_proof, pi) = vp.gen_proof::<CP::CurvePC>(vp_setup, pk_p, b"Test")?;

        // VP verifier
        let vp_verifier_data = VerifierData::new(vk_blind.clone(), pi);
        verify_proof::<CP::CurveScalarField, CP::InnerCurve, CP::CurvePC>(
            vp_setup,
            vp_verifier_data.key,
            &vp_proof,
            &vp_verifier_data.pi,
            b"Test",
        )?;

        // Generate blinding circuit CRS
        let blinding_setup = CP::get_opc_setup_params(BLINDING_CIRCUIT_SIZE);
        let pk_p = CP::get_blind_vp_pk();
        let vk = CP::get_blind_vp_vk();

        // Blinding Prover
        let (blind_vp_proof, pi) = blinding_circuit.gen_proof::<CP::OuterCurvePC>(
            blinding_setup,
            pk_p.clone(),
            b"Test",
        )?;

        // Blinding Verifier
        let blinding_verifier_data = VerifierData::new(vk.clone(), pi);
        verify_proof::<CP::CurveBaseField, CP::Curve, CP::OuterCurvePC>(
            blinding_setup,
            blinding_verifier_data.key,
            &blind_vp_proof,
            &blinding_verifier_data.pi,
            b"Test",
        )?;

        Ok(Self {
            vp_circuit_size,
            vp_proof,
            vp_public_inputs: vp_verifier_data.pi,
            unblinded_vp_vk: vk_blind,
            blind_vp_proof,
            blinded_vp_public_inputs: blinding_verifier_data.pi,
        })
    }

    pub fn verify(&self) -> Result<(), TaigaError> {
        // verify vp proof
        let vp_setup = CP::get_pc_setup_params(self.vp_circuit_size);
        let vp_verifier_data =
            VerifierData::new(self.unblinded_vp_vk.clone(), self.vp_public_inputs.clone());
        verify_proof::<CP::CurveScalarField, CP::InnerCurve, CP::CurvePC>(
            vp_setup,
            vp_verifier_data.key,
            &self.vp_proof,
            &vp_verifier_data.pi,
            b"Test",
        )?;

        // verify blind proof
        let blind_vp_setup = CP::get_opc_setup_params(BLINDING_CIRCUIT_SIZE);
        let blind_vp_vk = CP::get_blind_vp_vk();
        let blinding_verifier_data =
            VerifierData::new(blind_vp_vk.clone(), self.blinded_vp_public_inputs.clone());
        verify_proof::<CP::CurveBaseField, CP::Curve, CP::OuterCurvePC>(
            blind_vp_setup,
            blinding_verifier_data.key,
            &self.blind_vp_proof,
            &blinding_verifier_data.pi,
            b"Test",
        )?;
        Ok(())
    }
}

impl<CP: CircuitParameters> Transaction<CP> {
    pub fn new(
        action_slices: Vec<ActionSlice<CP>>,
        spend_slices: Vec<SpendSlice<CP>>,
        output_slices: Vec<OutputSlice<CP>>,
    ) -> Self {
        assert_eq!(action_slices.len(), NUM_TX_SLICE);
        assert_eq!(spend_slices.len(), NUM_TX_SLICE);
        assert_eq!(output_slices.len(), NUM_TX_SLICE);

        Self {
            action_slices: action_slices
                .try_into()
                .unwrap_or_else(|_| panic!("slice with incorrect length")),
            spend_slices: spend_slices
                .try_into()
                .unwrap_or_else(|_| panic!("slice with incorrect length")),
            output_slices: output_slices
                .try_into()
                .unwrap_or_else(|_| panic!("slice with incorrect length")),
        }
    }
    pub fn verify(
        &self,
        // ledger state
        // ledger: &Ledger,
    ) -> Result<(), TaigaError> {
        // verify action proof
        for action in self.action_slices.iter() {
            action.verify()?
        }

        // verify spend vp proof and blind proof
        for spend in self.spend_slices.iter() {
            spend.spend_addr_vp.verify()?;
            spend.spend_token_vp.verify()?;
        }

        // verify output vp proof and blind proof
        for output in self.output_slices.iter() {
            output.output_addr_vp.verify()?;
            output.output_token_vp.verify()?;
        }

        // check public input consistency(nf, output_cm, com_vp) among action, vp, vp blind.

        // check ledger state
        // check root existence, nf non-existence, etc.

        Ok(())
    }
}

#[ignore]
#[test]
fn test_tx() {
    use crate::circuit::circuit_parameters::PairingCircuitParameters as CP;
    type Fr = <CP as CircuitParameters>::CurveScalarField;
    type P = <CP as CircuitParameters>::InnerCurve;
    type PC = <CP as CircuitParameters>::CurvePC;
    type Fq = <CP as CircuitParameters>::CurveBaseField;
    type OP = <CP as CircuitParameters>::Curve;
    type Opc = <CP as CircuitParameters>::OuterCurvePC;
    use crate::action::ActionInfo;
    use crate::circuit::vp_examples::field_addition::FieldAdditionValidityPredicate;
    use crate::note::Note;
    use ark_std::test_rng;

    let mut rng = test_rng();

    // Construct action infos
    let mut actions: Vec<(Action<CP>, ActionCircuit<CP>)> = (0..NUM_TX_SLICE)
        .map(|_| {
            let action_info = ActionInfo::<CP>::dummy(&mut rng);
            action_info.build(&mut rng).unwrap()
        })
        .collect();

    // Generate action proofs
    let action_slices: Vec<ActionSlice<CP>> = actions
        .iter_mut()
        .map(|action| ActionSlice::<CP>::build(action.0, &mut action.1).unwrap())
        .collect();

    // Collect input notes from actions
    let input_notes_vec: Vec<Note<CP>> = actions
        .iter()
        .map(|action| action.1.spend_note.clone())
        .collect();
    let input_notes: [Note<CP>; NUM_NOTE] = input_notes_vec.try_into().unwrap();

    // Collect output notes from actions
    let output_notes_vec: Vec<Note<CP>> = actions
        .iter()
        .map(|action| action.1.output_note.clone())
        .collect();
    let output_notes: [Note<CP>; NUM_NOTE] = output_notes_vec.try_into().unwrap();

    // Construct VPs and generate VP proofs and blind VP proofs
    let mut spend_slices = vec![];
    let mut output_slices = vec![];
    for _action_index in 0..NUM_TX_SLICE {
        // Construct dummy spend slice
        let mut spend_addr_vp = FieldAdditionValidityPredicate::<CP>::new(
            input_notes.clone(),
            output_notes.clone(),
            &mut rng,
        );
        let spend_addr_vp_check = VPCheck::build(&mut spend_addr_vp, &mut rng).unwrap();
        let mut spend_token_vp = FieldAdditionValidityPredicate::<CP>::new(
            input_notes.clone(),
            output_notes.clone(),
            &mut rng,
        );
        let spend_token_vp_check = VPCheck::build(&mut spend_token_vp, &mut rng).unwrap();
        let spend_slice = SpendSlice::new(spend_addr_vp_check, spend_token_vp_check);
        spend_slices.push(spend_slice);

        // Construct dummy output vps
        let mut output_addr_vp = FieldAdditionValidityPredicate::<CP>::new(
            input_notes.clone(),
            output_notes.clone(),
            &mut rng,
        );
        let output_addr_vp_check = VPCheck::build(&mut output_addr_vp, &mut rng).unwrap();
        let mut output_token_vp = FieldAdditionValidityPredicate::<CP>::new(
            input_notes.clone(),
            output_notes.clone(),
            &mut rng,
        );
        let output_token_vp_check = VPCheck::build(&mut output_token_vp, &mut rng).unwrap();
        let output_slice = OutputSlice::new(output_addr_vp_check, output_token_vp_check);
        output_slices.push(output_slice);
    }

    // Construct a tx
    let tx = Transaction::<CP>::new(action_slices, spend_slices, output_slices);
    tx.verify().unwrap();
}
