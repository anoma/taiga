pub mod gadget {
    use crate::circuit::circuit_parameters::CircuitParameters;
    use crate::poseidon::WIDTH_3;
    use ark_ec::{twisted_edwards_extended::GroupAffine as TEGroupAffine, AffineCurve};
    use ark_ff::{One, Zero};
    use plonk_core::{
        constraint_system::Variable,
        prelude::{Point, StandardComposer},
    };
    use plonk_hashing::poseidon::{
        constants::PoseidonConstants,
        poseidon::{NativeSpec, PlonkSpec, Poseidon},
    };

    pub fn trivial_gadget<CP: CircuitParameters>(
        composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
        _private_inputs: &[CP::CurveScalarField],
        _public_inputs: &[CP::CurveScalarField],
    ) {
        // no input in this trivial gadget...
        let var_one = composer.add_input(CP::CurveScalarField::one());
        composer.arithmetic_gate(|gate| {
            gate.witness(var_one, var_one, None)
                .add(CP::CurveScalarField::one(), CP::CurveScalarField::one())
        });
    }

    pub fn poseidon_hash_curve_scalar_field_gadget<CP: CircuitParameters>(
        composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
        private_inputs: &[CP::CurveScalarField],
        _public_inputs: &[CP::CurveScalarField],
    ) -> Variable {
        // no public input here
        // private_inputs are the inputs for the Poseidon hash
        let inputs_var = private_inputs
            .iter()
            .map(|x| composer.add_input(*x))
            .collect::<Vec<_>>();

        // params for poseidon TODO make it const
        let poseidon_hash_param_bls12_377_scalar_arity2 = PoseidonConstants::generate::<WIDTH_3>();
        let mut poseidon_circuit = Poseidon::<_, PlonkSpec<WIDTH_3>, WIDTH_3>::new(
            composer,
            &poseidon_hash_param_bls12_377_scalar_arity2,
        );
        inputs_var.iter().for_each(|x| {
            let _ = poseidon_circuit.input(*x).unwrap();
        });
        poseidon_circuit.output_hash(composer)
    }

    pub fn bad_hash_to_curve_gadget<CP: CircuitParameters>(
        composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
        private_inputs: &[CP::CurveScalarField],
        _public_inputs: &[CP::CurveScalarField],
    ) -> Point<CP::InnerCurve> {
        // (bad) hash to curve:
        // 1. hash a scalar using poseidon
        let poseidon_hash_param_bls12_377_scalar_arity2 = PoseidonConstants::generate::<WIDTH_3>();
        let mut poseidon = Poseidon::<
            (),
            NativeSpec<<CP as CircuitParameters>::CurveScalarField, WIDTH_3>,
            WIDTH_3,
        >::new(&mut (), &poseidon_hash_param_bls12_377_scalar_arity2);
        private_inputs.iter().for_each(|x| {
            poseidon.input(*x).unwrap();
        });
        let hash = poseidon.output_hash(&mut ());
        poseidon_hash_curve_scalar_field_gadget::<CP>(composer, private_inputs, &[hash]);
        // 2. multiply by the generator
        let generator = TEGroupAffine::prime_subgroup_generator();
        let scalar_variable = composer.add_input(hash);
        composer.fixed_base_scalar_mul(scalar_variable, generator)
    }

    pub fn field_addition_gadget<CP: CircuitParameters>(
        composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
        private_inputs: &[CP::CurveScalarField],
        public_inputs: &[CP::CurveScalarField],
    ) {
        // simple circuit that checks that a + b == c
        let (a, b) = if private_inputs.is_empty() {
            (CP::CurveScalarField::zero(), CP::CurveScalarField::zero())
        } else {
            (private_inputs[0], private_inputs[1])
        };
        let c = public_inputs[0];
        let one = <CP as CircuitParameters>::CurveScalarField::one();
        let var_a = composer.add_input(a);
        let var_b = composer.add_input(b);
        let var_zero = composer.zero_var();
        // Make first constraint a + b = c (as public input)
        composer.arithmetic_gate(|gate| {
            gate.witness(var_a, var_b, Some(var_zero))
                .add(one, one)
                .pi(-c)
        });
    }
}

pub mod tests {

    #[test]
    fn test_bad_hash_to_curve_gadget() {
        use crate::circuit::circuit_parameters::{
            CircuitParameters, PairingCircuitParameters as CP,
        };
        use crate::circuit::gadgets::gadget::bad_hash_to_curve_gadget;
        use crate::crh;
        use crate::poseidon::WIDTH_3;
        use ark_std::UniformRand;
        use plonk_core::constraint_system::StandardComposer;
        type F = <CP as CircuitParameters>::CurveScalarField;

        let mut rng = rand::thread_rng();
        let random_inputs = (0..(WIDTH_3 - 1))
            .map(|_| F::rand(&mut rng))
            .collect::<Vec<_>>();

        let hash = crh::<CP>(&random_inputs);

        let mut composer = StandardComposer::<
            <CP as CircuitParameters>::CurveScalarField,
            <CP as CircuitParameters>::InnerCurve,
        >::new();

        let gadget_hash_variable =
            bad_hash_to_curve_gadget::<CP>(&mut composer, &random_inputs, &[]);
        composer.assert_equal_public_point(gadget_hash_variable, hash);
        composer.check_circuit_satisfied();
    }

    #[test]
    fn test_trivial_gadget() {
        use crate::circuit::circuit_parameters::{
            CircuitParameters, PairingCircuitParameters as CP,
        };
        use crate::circuit::gadgets::gadget::trivial_gadget;
        use plonk_core::constraint_system::StandardComposer;

        let mut composer = StandardComposer::<
            <CP as CircuitParameters>::CurveScalarField,
            <CP as CircuitParameters>::InnerCurve,
        >::new();
        trivial_gadget::<CP>(&mut composer, &[], &[]);
        composer.check_circuit_satisfied();
    }

    #[test]
    fn test_field_addition_gadget() {
        use crate::circuit::circuit_parameters::{
            CircuitParameters, PairingCircuitParameters as CP,
        };
        use crate::circuit::gadgets::gadget::field_addition_gadget;
        use plonk_core::constraint_system::StandardComposer;

        let a = <CP as CircuitParameters>::CurveScalarField::from(2u64);
        let b = <CP as CircuitParameters>::CurveScalarField::from(1u64);
        let c = <CP as CircuitParameters>::CurveScalarField::from(3u64);
        let mut composer = StandardComposer::<
            <CP as CircuitParameters>::CurveScalarField,
            <CP as CircuitParameters>::InnerCurve,
        >::new();
        field_addition_gadget::<CP>(&mut composer, &[a, b], &[c]);
        composer.check_circuit_satisfied();
    }

    #[test]
    fn test_poseidon_gadget() {
        use crate::circuit::circuit_parameters::{
            CircuitParameters, PairingCircuitParameters as CP,
        };
        use crate::circuit::gadgets::gadget::poseidon_hash_curve_scalar_field_gadget;
        use crate::WIDTH_3;
        use ark_std::UniformRand;
        use plonk_core::constraint_system::StandardComposer;
        use plonk_hashing::poseidon::constants::PoseidonConstants;
        use plonk_hashing::poseidon::poseidon::NativeSpec;
        use plonk_hashing::poseidon::poseidon::Poseidon;

        let mut rng = rand::thread_rng();
        let ω = (0..(WIDTH_3 - 1))
            .map(|_| <CP as CircuitParameters>::CurveScalarField::rand(&mut rng))
            .collect::<Vec<_>>();
        let poseidon_hash_param_bls12_377_scalar_arity2 = PoseidonConstants::generate::<WIDTH_3>();
        let mut poseidon = Poseidon::<
            (),
            NativeSpec<<CP as CircuitParameters>::CurveScalarField, WIDTH_3>,
            WIDTH_3,
        >::new(&mut (), &poseidon_hash_param_bls12_377_scalar_arity2);
        ω.iter().for_each(|x| {
            poseidon.input(*x).unwrap();
        });
        let hash = poseidon.output_hash(&mut ());
        let mut composer = StandardComposer::<
            <CP as CircuitParameters>::CurveScalarField,
            <CP as CircuitParameters>::InnerCurve,
        >::new();
        let native_hash_variable = composer.add_public_input_variable(hash);
        let gadget_hash_variable =
            poseidon_hash_curve_scalar_field_gadget::<CP>(&mut composer, &ω, &[hash]);
        composer.assert_equal(native_hash_variable, gadget_hash_variable);
        composer.check_circuit_satisfied();
    }
}
