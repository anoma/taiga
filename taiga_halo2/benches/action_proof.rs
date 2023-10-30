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
    action::ActionInfo,
    constant::{
        ACTION_CIRCUIT_PARAMS_SIZE, ACTION_PROVING_KEY, ACTION_VERIFYING_KEY, SETUP_PARAMS_MAP,
        TAIGA_COMMITMENT_TREE_DEPTH,
    },
    merkle_tree::MerklePath,
    note::{Note, NoteType, RandomSeed},
    nullifier::{Nullifier, NullifierKeyContainer},
};

fn bench_action_proof(name: &str, c: &mut Criterion) {
    let mut rng = OsRng;
    let action_info = {
        let input_note = {
            let rho = Nullifier::from(pallas::Base::random(&mut rng));
            let nk = NullifierKeyContainer::from_key(pallas::Base::random(&mut rng));
            let note_type = {
                let app_vk = pallas::Base::random(&mut rng);
                let app_data_static = pallas::Base::random(&mut rng);
                NoteType::new(app_vk, app_data_static)
            };
            let app_data_dynamic = pallas::Base::random(&mut rng);
            let value: u64 = rng.gen();
            let rseed = RandomSeed::random(&mut rng);
            Note {
                note_type,
                app_data_dynamic,
                value,
                nk_container: nk,
                is_merkle_checked: true,
                psi: rseed.get_psi(&rho),
                rcm: rseed.get_rcm(&rho),
                rho,
            }
        };
        let output_note = {
            let rho = input_note.get_nf().unwrap();
            let nk_com = NullifierKeyContainer::from_commitment(pallas::Base::random(&mut rng));
            let note_type = {
                let app_vk = pallas::Base::random(&mut rng);
                let app_data_static = pallas::Base::random(&mut rng);
                NoteType::new(app_vk, app_data_static)
            };
            let app_data_dynamic = pallas::Base::random(&mut rng);
            let value: u64 = rng.gen();
            let rseed = RandomSeed::random(&mut rng);
            Note {
                note_type,
                app_data_dynamic,
                value,
                nk_container: nk_com,
                is_merkle_checked: true,
                psi: rseed.get_psi(&rho),
                rcm: rseed.get_rcm(&rho),
                rho,
            }
        };
        let input_merkle_path = MerklePath::random(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);
        let anchor = input_note.calculate_root(&input_merkle_path);
        ActionInfo::new(input_note, input_merkle_path, anchor, output_note, &mut rng)
    };
    let (action, action_circuit) = action_info.build();
    let params = SETUP_PARAMS_MAP.get(&ACTION_CIRCUIT_PARAMS_SIZE).unwrap();

    // Prover bench
    let prover_name = name.to_string() + "-prover";
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

    let verifier_name = name.to_string() + "-verifier";
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
    bench_action_proof("halo2-action-proof", c);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
