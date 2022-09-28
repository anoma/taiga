use criterion::{criterion_group, criterion_main, Criterion};
use plonk_core::circuit::{verify_proof, VerifierData};
use plonk_core::prelude::Circuit;
use plonk_core::proof_system::pi::PublicInputs;
use rand::rngs::OsRng;
use taiga_zk_garage::action::ActionInfo;
use taiga_zk_garage::circuit::circuit_parameters::CircuitParameters;
use taiga_zk_garage::circuit::circuit_parameters::PairingCircuitParameters as CP;
use taiga_zk_garage::constant::ACTION_CIRCUIT_SIZE;
use taiga_zk_garage::constant::ACTION_PUBLIC_INPUT_NF_INDEX;

fn bench_action_proof(name: &str, c: &mut Criterion) {
    type Fr = <CP as CircuitParameters>::CurveScalarField;
    type P = <CP as CircuitParameters>::InnerCurve;
    type PC = <CP as CircuitParameters>::CurvePC;

    let mut rng = OsRng;
    let action_info = ActionInfo::<CP>::dummy(&mut rng);
    let (action, mut action_circuit) = action_info.build(&mut rng).unwrap();

    // Generate CRS
    let pp = CP::get_pc_setup_params(ACTION_CIRCUIT_SIZE);

    // Compile the circuit
    let pk = CP::get_action_pk();
    let vk = CP::get_action_vk();

    // Prover bench
    let prover_name = name.to_string() + "-prover";
    c.bench_function(&prover_name, |b| {
        b.iter(|| {
            action_circuit
                .gen_proof::<PC>(pp, pk.clone(), b"Test")
                .unwrap();
        })
    });
    let (proof, action_public_input) = action_circuit
        .gen_proof::<PC>(pp, pk.clone(), b"Test")
        .unwrap();

    // Verifier bench
    let verifier_name = name.to_string() + "-verifier";
    c.bench_function(&verifier_name, |b| {
        b.iter(|| {
            let mut expect_public_input = PublicInputs::new();
            expect_public_input.insert(ACTION_PUBLIC_INPUT_NF_INDEX, action.nf.inner());
            expect_public_input.insert(ACTION_PUBLIC_INPUT_NF_INDEX, action.root);
            expect_public_input.insert(ACTION_PUBLIC_INPUT_NF_INDEX, action.cm.inner());
            assert_eq!(action_public_input, expect_public_input);
            let verifier_data = VerifierData::new(vk.clone(), expect_public_input);
            assert!(verify_proof::<Fr, P, PC>(
                pp,
                verifier_data.key,
                &proof,
                &verifier_data.pi,
                b"Test"
            )
            .is_ok());
        })
    });
    let mut expect_public_input = PublicInputs::new();
    expect_public_input.insert(ACTION_PUBLIC_INPUT_NF_INDEX, action.nf.inner());
    expect_public_input.insert(ACTION_PUBLIC_INPUT_NF_INDEX, action.root);
    expect_public_input.insert(ACTION_PUBLIC_INPUT_NF_INDEX, action.cm.inner());
    assert_eq!(action_public_input, expect_public_input);
    let verifier_data = VerifierData::new(vk.clone(), expect_public_input);
    verify_proof::<Fr, P, PC>(pp, verifier_data.key, &proof, &verifier_data.pi, b"Test").unwrap();
}
fn criterion_benchmark(c: &mut Criterion) {
    bench_action_proof("action-proof", c);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
