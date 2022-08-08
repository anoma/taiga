use crate::circuit::circuit_parameters::CircuitParameters;
use crate::circuit::gadgets::merkle_tree::merkle_tree_gadget;
use crate::circuit::integrity::{input_note_constraint, output_note_constraint};
use crate::constant::ACTION_CIRCUIT_SIZE;
use crate::merkle_tree::TAIGA_COMMITMENT_TREE_DEPTH;
use crate::note::Note;
use crate::poseidon::WIDTH_3;
//use plonk_core::{circuit::Circuit, constraint_system::StandardComposer};
//use plonk_hashing::poseidon::constants::PoseidonConstants;

use crate::nullifier::Nullifier;
use halo2_gadgets::poseidon::{primitives::P128Pow5T3, Pow5Chip, Pow5Config};
use halo2_gadgets::utilities::cond_swap::{CondSwapChip, CondSwapConfig};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Chip, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector},
    poly::Rotation,
};
use pasta_curves::vesta;

#[derive(Clone, Debug)]
struct ExecuteConfig {

    /// For this chip, we will use five advice columns to implement our instructions.
    /// These are also the columns through which we communicate with other parts of
    /// the circuit.
    advice: [Column<Advice>; 5],
    rc_a: Column<Fixed>,
    rc_b: Column<Fixed>,

    /// This is the public input (instance) column.
    instance: Column<Instance>,

    // We need a selector to enable the multiplication gate, so that we aren't placing
    // any constraints on cells where `NumericInstructions::mul` is not being used.
    // This is important when building larger circuits, where columns are used by
    // multiple sets of instructions.
    s_mul: Selector,

    // Poseidon configuration
    poseidon: Pow5Config<vesta::Scalar, 3, 2>,

    // CondSwap configuration
    cond_swap : CondSwapConfig,
}

/// Action circuit
#[derive(Debug, Clone)]
pub struct ExecuteCircuit<CP: CircuitParameters> {
    /// Spent note
    pub spend_note: Note<CP>,
    pub auth_path: [(CP::CurveScalarField, bool); TAIGA_COMMITMENT_TREE_DEPTH],
    /// Output note
    pub output_note: Note<CP>,
}

impl<CP: CircuitParameters> Circuit<CP::CurveScalarField> for ExecuteCircuit<CP> {
    // Since we are using a single chip for everything, we can just reuse its config.
    type Config = ExecuteConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<CP::CurveScalarField>) -> Self::Config {
        // We create the five advice columns for I/O.
        let advice = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];

        let poseidon_state = advice[0..3];

        let poseidon_sbox = advice[3];

        // We also need an instance column to store public inputs.
        let instance = meta.instance_column();

        // Create a fixed column to load constants.
        let rc_a = meta.fixed_column();
        let rc_b = meta.fixed_column();

        let s_mul = meta.selector();

        let poseidon =
            Pow5Chip::configure::<P128Pow5T3>(meta, poseidon_state, poseidon_sbox, rc_a, rc_b);

            let cond_swap = CondSwapChip::configure(meta, advice);
        ExecuteConfig {
            advice,
            instance,
            rc_a,
            rc_b,
            s_mul,
            poseidon,
            cond_swap,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<CP::CurveScalarField>,
    ) -> Result<(), Error> {
        let poseidon_chip = Pow5Chip::<CP::CurveScalarField>::construct(config.poseidon);

        let cond_swap = CondSwapChip::construct(config.cond_swap);
        // spent note
        let nf = {
            let input_note_var = input_note_constraint(&self.spend_note, Self::Config::advice[0], layouter)?;
            // check merkle tree and publish root
            let root = merkle_tree_gadget::<
                CP::CurveScalarField,
                CP::InnerCurve,
                //PoseidonConstants<CP::CurveScalarField>,
            >(
                layouter,
                Self::Config::advice[0],
                &input_note_var.cm,
                &self.auth_path,
                &poseidon_chip,
                &cond_swap,
            )?;
            layouter.public_inputize(&root);

            // TODO: user send address VP commitment and token VP commitment
            input_note_var.nf
        };

        // output note
        {
            let _output_note_var = output_note_constraint(&self.output_note, &nf,Self::Config::advice[0], layouter)?;

            // TODO: add user receive address VP commitment and token VP commitment

            // TODO: add note encryption
        }

        layouter.check_circuit_satisfied();
        println!("circuit size: {}", layouter.circuit_bound());

        Ok(())

        // Load our private values into the circuit.
        //let a = field_chip.load_private(layouter.namespace(|| "load a"), self.a)?;
        //let b = field_chip.load_private(layouter.namespace(|| "load b"), self.b)?;

        // Load the constant factor into the circuit.
        //let constant =
        //    field_chip.load_constant(layouter.namespace(|| "load constant"), self.constant)?;

        // We only have access to plain multiplication.
        // We could implement our circuit as:
        //     asq  = a*a
        //     bsq  = b*b
        //     absq = asq*bsq
        //     c    = constant*asq*bsq
        //
        // but it's more efficient to implement it as:
        //     ab   = a*b
        //     absq = ab^2
        //     c    = constant*absq
        //let ab = field_chip.mul(layouter.namespace(|| "a * b"), a, b)?;
        //let absq = field_chip.mul(layouter.namespace(|| "ab * ab"), ab.clone(), ab)?;
        //let c = field_chip.mul(layouter.namespace(|| "constant * absq"), constant, absq)?;

        // Expose the result as a public input to the circuit.
        //field_chip.expose_public(layouter.namespace(|| "expose c"), c, 0)
    }
}

#[test]
fn test_execute_circuit() {
    use halo2_proofs::{dev::MockProver, pasta::Fp};

    // ANCHOR: test-circuit
    // The number of rows in our circuit cannot exceed 2^k. Since our example
    // circuit is very small, we can pick a very small value here.
    let k = 4;

    // Prepare the private and public inputs to the circuit!
    let auth_path = [Fp::from(7); TAIGA_COMMITMENT_TREE_DEPTH];
    let a = Fp::from(2);
    let b = Fp::from(3);
    let c = constant * a.square() * b.square();

    // Instantiate the circuit with the private inputs.
    let circuit = ExecuteCircuit {
        auth_path,
        a: Value::known(a),
        b: Value::known(b),
    };

    // Arrange the public input. We expose the multiplication result in row 0
    // of the instance column, so we position it there in our public inputs.
    let mut public_inputs = vec![c];

    // Given the correct public input, our circuit will verify.
    let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]).unwrap();
    assert_eq!(prover.verify(), Ok(()));

    // If we try some other public input, the proof will fail!
    public_inputs[0] += Fp::one();
    let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
    assert!(prover.verify().is_err());
    // ANCHOR_END: test-circuit
}

#[test]
fn action_circuit_test() {
    use crate::circuit::circuit_parameters::{CircuitParameters, HaloCircuitParameters as CP};
    type Fr = <CP as CircuitParameters>::CurveScalarField;
    type P = <CP as CircuitParameters>::InnerCurve;
    type PC = <CP as CircuitParameters>::CurvePC;
    use crate::action::*;
    use crate::constant::{
        ACTION_PUBLIC_INPUT_CM_INDEX, ACTION_PUBLIC_INPUT_NF_INDEX, ACTION_PUBLIC_INPUT_ROOT_INDEX,
    };
    use ark_std::test_rng;
    use plonk_core::circuit::{verify_proof, VerifierData};
    use plonk_core::proof_system::pi::PublicInputs;

    let mut rng = test_rng();
    let action_info = ActionInfo::<CP>::dummy(&mut rng);
    let (action, mut action_circuit) = action_info.build(&mut rng).unwrap();

    // Generate CRS
    let pp = CP::get_pc_setup_params(ACTION_CIRCUIT_SIZE);

    // Compile the circuit
    let pk = CP::get_action_pk();
    let vk = CP::get_action_vk();

    // Prover
    let (proof, action_public_input) = action_circuit
        .gen_proof::<PC>(pp, pk.clone(), b"Test")
        .unwrap();

    // Check the public inputs
    let mut expect_public_input = PublicInputs::new(action_circuit.padded_circuit_size());
    expect_public_input.insert(ACTION_PUBLIC_INPUT_NF_INDEX, action.nf.inner());
    expect_public_input.insert(ACTION_PUBLIC_INPUT_ROOT_INDEX, action.root);
    expect_public_input.insert(ACTION_PUBLIC_INPUT_CM_INDEX, action.cm.inner());
    assert_eq!(action_public_input, expect_public_input);
    // Verifier
    let verifier_data = VerifierData::new(vk.clone(), expect_public_input);
    verify_proof::<Fr, P, PC>(pp, verifier_data.key, &proof, &verifier_data.pi, b"Test").unwrap();
}
