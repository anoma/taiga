use criterion::{criterion_group, criterion_main, Criterion};
use halo2_proofs::plonk::{keygen_pk, keygen_vk};
use rand::rngs::OsRng;
use taiga_halo2::{
    circuit::{
        resource_logic_circuit::ResourceLogicCircuit,
        resource_logic_examples::TrivialResourceLogicCircuit,
    },
    constant::{RESOURCE_LOGIC_CIRCUIT_PARAMS_SIZE, SETUP_PARAMS_MAP},
    proof::Proof,
};

fn bench_resource_logic_proof(name: &str, c: &mut Criterion) {
    let mut rng = OsRng;

    let resource_logic_circuit = TrivialResourceLogicCircuit::default();
    let params = SETUP_PARAMS_MAP
        .get(&RESOURCE_LOGIC_CIRCUIT_PARAMS_SIZE)
        .unwrap();
    let empty_circuit: TrivialResourceLogicCircuit = Default::default();
    let vk = keygen_vk(params, &empty_circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(params, vk, &empty_circuit).expect("keygen_pk should not fail");
    let public_inputs = resource_logic_circuit.get_public_inputs(&mut rng);

    // Prover bench
    let prover_name = name.to_string() + "-prover";
    c.bench_function(&prover_name, |b| {
        b.iter(|| {
            Proof::create(
                &pk,
                &params,
                resource_logic_circuit.clone(),
                &[public_inputs.inner()],
                &mut rng,
            )
            .unwrap();
        })
    });

    // Verifier bench
    // Create a proof for verifier
    let proof = Proof::create(
        &pk,
        &params,
        resource_logic_circuit.clone(),
        &[public_inputs.inner()],
        &mut rng,
    )
    .unwrap();

    let verifier_name = name.to_string() + "-verifier";
    c.bench_function(&verifier_name, |b| {
        b.iter(|| {
            assert!(proof
                .verify(pk.get_vk(), &params, &[public_inputs.inner()])
                .is_ok());
        })
    });
}
fn criterion_benchmark(c: &mut Criterion) {
    bench_resource_logic_proof("halo2-resource-logic-proof", c);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
