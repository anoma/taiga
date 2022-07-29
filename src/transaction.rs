use crate::action::{Action, ActionInfo};
use crate::circuit::blinding_circuit::BlindingCircuit;
use crate::circuit::circuit_parameters::CircuitParameters;
use crate::circuit::validity_predicate::{ValidityPredicate, NUM_NOTE};
use crate::constant::{
    ACTION_CIRCUIT_SIZE, ACTION_PUBLIC_INPUT_CM_INDEX, ACTION_PUBLIC_INPUT_NF_INDEX,
    ACTION_PUBLIC_INPUT_ROOT_INDEX, BLINDING_CIRCUIT_SIZE,
};
use crate::error::TaigaError;
use crate::vp_description::ValidityPredicateDescription;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::PolynomialCommitment;
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

impl<CP: CircuitParameters> ActionSlice<CP> {
    pub fn from_action_info(
        action_info: ActionInfo<CP>,
        rng: &mut impl RngCore,
        setup: &<CP::CurvePC as PolynomialCommitment<
            CP::CurveScalarField,
            DensePolynomial<CP::CurveScalarField>,
        >>::UniversalParams,
    ) -> Self {
        let (action_public, mut action_circuit) = action_info.build(rng).unwrap();
        // Compile the circuit
        let (pk_p, vk) = action_circuit.compile::<CP::CurvePC>(setup).unwrap();

        // Prover
        let (action_proof, pi) = action_circuit
            .gen_proof::<CP::CurvePC>(setup, pk_p, b"Test")
            .unwrap();

        // Verifier
        let verifier_data = VerifierData::new(vk, pi);
        verify_proof::<CP::CurveScalarField, CP::InnerCurve, CP::CurvePC>(
            setup,
            verifier_data.key,
            &action_proof,
            &verifier_data.pi,
            b"Test",
        )
        .unwrap();

        ActionSlice {
            action_public,
            action_proof,
        }
    }

    pub fn verify(
        &self,
        action_vk: &VerifierKey<CP::CurveScalarField, CP::CurvePC>,
    ) -> Result<(), TaigaError> {
        let mut action_pi = PublicInputs::new(ACTION_CIRCUIT_SIZE);
        action_pi.insert(ACTION_PUBLIC_INPUT_NF_INDEX, self.action_public.nf.inner());
        action_pi.insert(ACTION_PUBLIC_INPUT_ROOT_INDEX, self.action_public.root);
        action_pi.insert(ACTION_PUBLIC_INPUT_CM_INDEX, self.action_public.cm.inner());

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
    pub fn build<VP>(
        vp: &mut VP,
        vp_setup: &<CP::CurvePC as PolynomialCommitment<
            CP::CurveScalarField,
            DensePolynomial<CP::CurveScalarField>,
        >>::UniversalParams,
        rng: &mut impl RngCore,
    ) -> Self
    where
        VP: ValidityPredicate<CP>,
    {
        let vp_circuit_size = vp.padded_circuit_size();
        // Generate blinding circuit for vp
        let vp_desc = ValidityPredicateDescription::from_vp(vp, vp_setup).unwrap();
        // let vp_desc_compressed = vp_desc.get_compress();
        let mut blinding_circuit =
            BlindingCircuit::<CP>::new(rng, vp_desc, vp_setup, vp_circuit_size).unwrap();

        // Compile vp(must use compile_with_blinding)
        let (pk_p, vk_blind) = vp
            .compile_with_blinding::<CP::CurvePC>(vp_setup, &blinding_circuit.blinding)
            .unwrap();

        // VP Prover
        let (vp_proof, pi) = vp
            .gen_proof::<CP::CurvePC>(vp_setup, pk_p, b"Test")
            .unwrap();

        // VP verifier
        let vp_verifier_data = VerifierData::new(vk_blind.clone(), pi);
        verify_proof::<CP::CurveScalarField, CP::InnerCurve, CP::CurvePC>(
            vp_setup,
            vp_verifier_data.key,
            &vp_proof,
            &vp_verifier_data.pi,
            b"Test",
        )
        .unwrap();

        // Generate blinding circuit CRS
        let blinding_setup = CP::get_opc_setup_params(BLINDING_CIRCUIT_SIZE);
        let (pk_p, vk) = blinding_circuit
            .compile::<CP::OuterCurvePC>(blinding_setup)
            .unwrap();

        // Blinding Prover
        let (blind_vp_proof, pi) = blinding_circuit
            .gen_proof::<CP::OuterCurvePC>(blinding_setup, pk_p, b"Test")
            .unwrap();

        // Blinding Verifier
        let blinding_verifier_data = VerifierData::new(vk, pi);
        verify_proof::<CP::CurveBaseField, CP::Curve, CP::OuterCurvePC>(
            blinding_setup,
            blinding_verifier_data.key,
            &blind_vp_proof,
            &blinding_verifier_data.pi,
            b"Test",
        )
        .unwrap();

        Self {
            vp_circuit_size,
            vp_proof,
            vp_public_inputs: vp_verifier_data.pi,
            unblinded_vp_vk: vk_blind,
            blind_vp_proof,
            blinded_vp_public_inputs: blinding_verifier_data.pi,
        }
    }

    pub fn verify(
        &self,
        // TODO: blind_vp_setup and blind_vp_vk are fixed parameters, make it a static const later.
        blind_vp_vk: &VerifierKey<CP::CurveBaseField, CP::OuterCurvePC>,
    ) -> Result<(), TaigaError> {
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
    pub fn verify(
        &self,
        action_vk: &VerifierKey<CP::CurveScalarField, CP::CurvePC>,
        blind_vp_vk: &VerifierKey<CP::CurveBaseField, CP::OuterCurvePC>,
        // ledger state
        // ledger: &Ledger,
    ) -> Result<(), TaigaError> {
        // verify action proof
        for action in self.action_slices.iter() {
            action.verify(action_vk)?
        }

        // verify spend vp proof and blind proof
        for spend in self.spend_slices.iter() {
            spend.spend_addr_vp.verify(blind_vp_vk)?;
            spend.spend_token_vp.verify(blind_vp_vk)?;
        }

        // verify output vp proof and blind proof
        for output in self.output_slices.iter() {
            output.output_addr_vp.verify(blind_vp_vk)?;
            output.output_token_vp.verify(blind_vp_vk)?;
        }

        // check public input consistency(nf, output_cm, com_vp) among action, vp, vp blind.

        // check ledger state
        // check root existence, nf non-existence, etc.

        Ok(())
    }
}
