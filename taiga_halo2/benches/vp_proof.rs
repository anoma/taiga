use criterion::{criterion_group, criterion_main, Criterion};
use halo2_proofs::plonk::{keygen_pk, keygen_vk};

use rand::rngs::OsRng;
use taiga_halo2::circuit::vp_circuit::ValidityPredicateInfo;
use taiga_halo2::circuit::vp_examples::TrivialValidityPredicateCircuit;
use taiga_halo2::constant::SETUP_PARAMS_MAP;
use taiga_halo2::proof::Proof;

fn bench_vp_proof(name: &str, c: &mut Criterion) {
    let mut rng = OsRng;

    let vp_circuit = TrivialValidityPredicateCircuit::dummy(&mut rng);
    let params = SETUP_PARAMS_MAP.get(&12).unwrap();
    let empty_circuit: TrivialValidityPredicateCircuit = Default::default();
    let vk = keygen_vk(params, &empty_circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(params, vk, &empty_circuit).expect("keygen_pk should not fail");
    let instances = vp_circuit.get_instances();

    // Prover bench
    let prover_name = name.to_string() + "-prover";
    c.bench_function(&prover_name, |b| {
        b.iter(|| {
            Proof::create(&pk, &params, vp_circuit.clone(), &[&instances], &mut rng);
        })
    });

    // Verifier bench
    // Create a proof for verifier
    let proof = Proof::create(&pk, &params, vp_circuit.clone(), &[&instances], &mut rng).unwrap();

    let verifier_name = name.to_string() + "-verifier";
    c.bench_function(&verifier_name, |b| {
        b.iter(|| {
            proof.verify(pk.get_vk(), &params, &[&instances]).is_ok();
        })
    });
}
fn criterion_benchmark(c: &mut Criterion) {
    bench_vp_proof("vp-proof", c);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
