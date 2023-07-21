use criterion::{criterion_group, criterion_main, Criterion};
use halo2_proofs::plonk::{keygen_pk, keygen_vk};

use halo2_proofs::arithmetic::Field;
use pasta_curves::pallas;
use rand::rngs::OsRng;
use rand::Rng;
use taiga_halo2::{
    circuit::{vp_circuit::ValidityPredicateInfo, vp_examples::TrivialValidityPredicateCircuit},
    constant::{NUM_NOTE, SETUP_PARAMS_MAP},
    note::{Note, NoteType, RandomSeed},
    nullifier::{Nullifier, NullifierKeyContainer},
    proof::Proof,
};

fn bench_vp_proof(name: &str, c: &mut Criterion) {
    let mut rng = OsRng;

    let vp_circuit = {
        let input_notes = [(); NUM_NOTE].map(|_| {
            let rho = Nullifier::new(pallas::Base::random(&mut rng));
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
        });
        let output_notes = input_notes
            .iter()
            .map(|input| {
                let rho = input.get_nf().unwrap();
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
            })
            .collect::<Vec<_>>();
        let owned_note_pub_id = input_notes[0].get_nf().unwrap().inner();
        TrivialValidityPredicateCircuit::new(
            owned_note_pub_id,
            input_notes,
            output_notes.try_into().unwrap(),
        )
    };
    let params = SETUP_PARAMS_MAP.get(&12).unwrap();
    let empty_circuit: TrivialValidityPredicateCircuit = Default::default();
    let vk = keygen_vk(params, &empty_circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(params, vk, &empty_circuit).expect("keygen_pk should not fail");
    let instances = vp_circuit.get_instances();

    // Prover bench
    let prover_name = name.to_string() + "-prover";
    c.bench_function(&prover_name, |b| {
        b.iter(|| {
            Proof::create(&pk, &params, vp_circuit.clone(), &[&instances], &mut rng).unwrap();
        })
    });

    // Verifier bench
    // Create a proof for verifier
    let proof = Proof::create(&pk, &params, vp_circuit.clone(), &[&instances], &mut rng).unwrap();

    let verifier_name = name.to_string() + "-verifier";
    c.bench_function(&verifier_name, |b| {
        b.iter(|| {
            assert!(proof.verify(pk.get_vk(), &params, &[&instances]).is_ok());
        })
    });
}
fn criterion_benchmark(c: &mut Criterion) {
    bench_vp_proof("halo2-vp-proof", c);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
