use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Chip, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector},
    poly::Rotation,
};
use pasta_curves::vesta;
use crate::note::Note;
use crate::nullifier::Nullifier;
use crate::merkle_tree::TAIGA_COMMITMENT_TREE_DEPTH;

#[derive(Clone, Debug)]
struct ExecuteConfig {
    /// For this chip, we will use two advice columns to implement our instructions.
    /// These are also the columns through which we communicate with other parts of
    /// the circuit.
    advice: [Column<Advice>; 2],

    /// This is the public input (instance) column.
    instance: Column<Instance>,

    // We need a selector to enable the multiplication gate, so that we aren't placing
    // any constraints on cells where `NumericInstructions::mul` is not being used.
    // This is important when building larger circuits, where columns are used by
    // multiple sets of instructions.
    s_mul: Selector,
}

/// The full circuit implementation.
///
/// In this struct we store the private input variables. We use `Option<F>` because
/// they won't have any value during key generation. During proving, if any of these
/// were `None` we would get an error.
#[derive(Default)]
struct Execute {
    /// The path note commitment Merkle tree.
    auth_path: [(vesta::Scalar, bool); TAIGA_COMMITMENT_TREE_DEPTH],
    /// The spent note.
    spent_note: Note,
    /// The output note.
    output_note: Note
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
    let circuit = Execute {
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

impl<F: FieldExt> Circuit<F> for Execute {
    // Since we are using a single chip for everything, we can just reuse its config.
    type Config = ExecuteConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        // We create the two advice columns that FieldChip uses for I/O.
        let advice = [meta.advice_column(), meta.advice_column()];

        // We also need an instance column to store public inputs.
        let instance = meta.instance_column();

        // Create a fixed column to load constants.
        let constant = meta.fixed_column();

        //FieldChip::configure(meta, advice, instance, constant)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let field_chip = FieldChip::<F>::construct(config);

        // Load our private values into the circuit.
        let a = field_chip.load_private(layouter.namespace(|| "load a"), self.a)?;
        let b = field_chip.load_private(layouter.namespace(|| "load b"), self.b)?;

        // Load the constant factor into the circuit.
        let constant =
            field_chip.load_constant(layouter.namespace(|| "load constant"), self.constant)?;

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
        let ab = field_chip.mul(layouter.namespace(|| "a * b"), a, b)?;
        let absq = field_chip.mul(layouter.namespace(|| "ab * ab"), ab.clone(), ab)?;
        let c = field_chip.mul(layouter.namespace(|| "constant * absq"), constant, absq)?;

        // Expose the result as a public input to the circuit.
        field_chip.expose_public(layouter.namespace(|| "expose c"), c, 0)
    }
}