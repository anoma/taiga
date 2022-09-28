use criterion::{criterion_group, criterion_main, Criterion};
use halo2_proofs::{
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite},
};
use pasta_curves::vesta;
use rand::rngs::OsRng;
use taiga_halo2::circuit::vp_examples::DummyValidityPredicateCircuit;

fn bench_vp_proof(name: &str, c: &mut Criterion) {
    let mut rng = OsRng;

    let vp_circuit = DummyValidityPredicateCircuit::dummy(&mut rng);
    let params = Params::new(12);
    let empty_circuit: DummyValidityPredicateCircuit = Default::default();
    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");
    let instances = vp_circuit.get_instances();

    // Prover bench
    let prover_name = name.to_string() + "-prover";
    c.bench_function(&prover_name, |b| {
        b.iter(|| {
            let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
            create_proof(
                &params,
                &pk,
                &[vp_circuit.clone()],
                &[&[&instances]],
                &mut rng,
                &mut transcript,
            )
            .unwrap();
            let _proof = transcript.finalize();
        })
    });

    // Verifier bench
    // Create a proof for verifier
    let proof = {
        let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
        create_proof(
            &params,
            &pk,
            &[vp_circuit.clone()],
            &[&[&instances]],
            &mut rng,
            &mut transcript,
        )
        .unwrap();
        transcript.finalize()
    };

    let verifier_name = name.to_string() + "-verifier";
    c.bench_function(&verifier_name, |b| {
        b.iter(|| {
            let strategy = SingleVerifier::new(&params);
            let mut transcript = Blake2bRead::init(&proof[..]);
            assert!(verify_proof(
                &params,
                pk.get_vk(),
                strategy,
                &[&[&instances]],
                &mut transcript
            )
            .is_ok());
        })
    });
}
fn criterion_benchmark(c: &mut Criterion) {
    bench_vp_proof("vp-proof", c);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
