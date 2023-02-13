use criterion::{criterion_group, criterion_main, Criterion};
use halo2_proofs::{
    plonk::{create_proof, verify_proof, SingleVerifier},
    transcript::{Blake2bRead, Blake2bWrite},
};
use pasta_curves::vesta;
use rand::rngs::OsRng;
use taiga_halo2::{
    action::ActionInfo,
    constant::{
        ACTION_CIRCUIT_PARAMS_SIZE, ACTION_PROVING_KEY, ACTION_VERIFYING_KEY, SETUP_PARAMS_MAP,
    },
};

fn bench_action_proof(name: &str, c: &mut Criterion) {
    let mut rng = OsRng;
    let action_info = ActionInfo::dummy(&mut rng);
    let (action, action_circuit) = action_info.build();
    let params = SETUP_PARAMS_MAP.get(&ACTION_CIRCUIT_PARAMS_SIZE).unwrap();

    // Prover bench
    let prover_name = name.to_string() + "-prover-halo2";
    c.bench_function(&prover_name, |b| {
        b.iter(|| {
            let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
            create_proof(
                params,
                &ACTION_PROVING_KEY,
                &[action_circuit.clone()],
                &[&[&action.to_instance()]],
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
            params,
            &ACTION_PROVING_KEY,
            &[action_circuit],
            &[&[&action.to_instance()]],
            &mut rng,
            &mut transcript,
        )
        .unwrap();
        transcript.finalize()
    };

    let verifier_name = name.to_string() + "-verifier-halo2";
    c.bench_function(&verifier_name, |b| {
        b.iter(|| {
            let strategy = SingleVerifier::new(params);
            let mut transcript = Blake2bRead::init(&proof[..]);
            assert!(verify_proof(
                params,
                &ACTION_VERIFYING_KEY,
                strategy,
                &[&[&action.to_instance()]],
                &mut transcript
            )
            .is_ok());
        })
    });
}
fn criterion_benchmark(c: &mut Criterion) {
    bench_action_proof("action-proof", c);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
