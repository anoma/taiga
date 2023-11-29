use criterion::{criterion_group, criterion_main, Criterion};
use halo2_proofs::{
    arithmetic::Field,
    plonk::{create_proof, verify_proof, SingleVerifier},
    transcript::{Blake2bRead, Blake2bWrite},
};
use pasta_curves::{pallas, vesta};
use rand::rngs::OsRng;
use rand::Rng;
use taiga_halo2::{
    compliance::ComplianceInfo,
    constant::{
        COMPLIANCE_CIRCUIT_PARAMS_SIZE, COMPLIANCE_PROVING_KEY, COMPLIANCE_VERIFYING_KEY,
        SETUP_PARAMS_MAP, TAIGA_COMMITMENT_TREE_DEPTH,
    },
    merkle_tree::MerklePath,
    nullifier::{Nullifier, NullifierKeyContainer},
    resource::{RandomSeed, Resource, ResourceKind},
};

fn bench_compliance_proof(name: &str, c: &mut Criterion) {
    let mut rng = OsRng;
    let compliance_info = {
        let input_resource = {
            let nonce = Nullifier::from(pallas::Base::random(&mut rng));
            let nk = NullifierKeyContainer::from_key(pallas::Base::random(&mut rng));
            let kind = {
                let logic = pallas::Base::random(&mut rng);
                let label = pallas::Base::random(&mut rng);
                ResourceKind::new(logic, label)
            };
            let value = pallas::Base::random(&mut rng);
            let quantity: u64 = rng.gen();
            let rseed = RandomSeed::random(&mut rng);
            Resource {
                kind,
                value,
                quantity,
                nk_container: nk,
                is_ephemeral: false,
                psi: rseed.get_psi(&nonce),
                rcm: rseed.get_rcm(&nonce),
                nonce,
            }
        };
        let mut output_resource = {
            let nonce = input_resource.get_nf().unwrap();
            let npk = NullifierKeyContainer::from_npk(pallas::Base::random(&mut rng));
            let kind = {
                let logic = pallas::Base::random(&mut rng);
                let label = pallas::Base::random(&mut rng);
                ResourceKind::new(logic, label)
            };
            let value = pallas::Base::random(&mut rng);
            let quantity: u64 = rng.gen();
            let rseed = RandomSeed::random(&mut rng);
            Resource {
                kind,
                value,
                quantity,
                nk_container: npk,
                is_ephemeral: false,
                psi: rseed.get_psi(&nonce),
                rcm: rseed.get_rcm(&nonce),
                nonce,
            }
        };
        let input_merkle_path = MerklePath::random(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);
        ComplianceInfo::new(
            input_resource,
            input_merkle_path,
            None,
            &mut output_resource,
            &mut rng,
        )
    };
    let (compliance, compliance_circuit) = compliance_info.build();
    let params = SETUP_PARAMS_MAP
        .get(&COMPLIANCE_CIRCUIT_PARAMS_SIZE)
        .unwrap();

    // Prover bench
    let prover_name = name.to_string() + "-prover";
    c.bench_function(&prover_name, |b| {
        b.iter(|| {
            let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
            create_proof(
                params,
                &COMPLIANCE_PROVING_KEY,
                &[compliance_circuit.clone()],
                &[&[&compliance.to_instance()]],
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
            &COMPLIANCE_PROVING_KEY,
            &[compliance_circuit],
            &[&[&compliance.to_instance()]],
            &mut rng,
            &mut transcript,
        )
        .unwrap();
        transcript.finalize()
    };

    let verifier_name = name.to_string() + "-verifier";
    c.bench_function(&verifier_name, |b| {
        b.iter(|| {
            let strategy = SingleVerifier::new(params);
            let mut transcript = Blake2bRead::init(&proof[..]);
            assert!(verify_proof(
                params,
                &COMPLIANCE_VERIFYING_KEY,
                strategy,
                &[&[&compliance.to_instance()]],
                &mut transcript
            )
            .is_ok());
        })
    });
}
fn criterion_benchmark(c: &mut Criterion) {
    bench_compliance_proof("halo2-compliance-proof", c);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
