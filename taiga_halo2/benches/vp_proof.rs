use criterion::{criterion_group, criterion_main, Criterion};
use halo2_proofs::plonk::{keygen_pk, keygen_vk};

use halo2_proofs::arithmetic::Field;
use pasta_curves::pallas;
use rand::rngs::OsRng;
use rand::Rng;
use taiga_halo2::{
    circuit::{vp_circuit::ValidityPredicateCircuit, vp_examples::TrivialValidityPredicateCircuit},
    constant::{NUM_RESOURCE, SETUP_PARAMS_MAP, VP_CIRCUIT_PARAMS_SIZE},
    nullifier::{Nullifier, NullifierKeyContainer},
    proof::Proof,
    resource::{RandomSeed, Resource, ResourceKind},
};

fn bench_vp_proof(name: &str, c: &mut Criterion) {
    let mut rng = OsRng;

    let vp_circuit = {
        let input_resources = [(); NUM_RESOURCE].map(|_| {
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
                is_merkle_checked: true,
                psi: rseed.get_psi(&nonce),
                rcm: rseed.get_rcm(&nonce),
                nonce,
            }
        });
        let output_resources = input_resources
            .iter()
            .map(|input| {
                let nonce = input.get_nf().unwrap();
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
                    is_merkle_checked: true,
                    psi: rseed.get_psi(&nonce),
                    rcm: rseed.get_rcm(&nonce),
                    nonce,
                }
            })
            .collect::<Vec<_>>();
        let owned_resource_id = input_resources[0].get_nf().unwrap().inner();
        TrivialValidityPredicateCircuit::new(
            owned_resource_id,
            input_resources,
            output_resources.try_into().unwrap(),
        )
    };
    let params = SETUP_PARAMS_MAP.get(&VP_CIRCUIT_PARAMS_SIZE).unwrap();
    let empty_circuit: TrivialValidityPredicateCircuit = Default::default();
    let vk = keygen_vk(params, &empty_circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(params, vk, &empty_circuit).expect("keygen_pk should not fail");
    let public_inputs = vp_circuit.get_public_inputs(&mut rng);

    // Prover bench
    let prover_name = name.to_string() + "-prover";
    c.bench_function(&prover_name, |b| {
        b.iter(|| {
            Proof::create(
                &pk,
                &params,
                vp_circuit.clone(),
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
        vp_circuit.clone(),
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
    bench_vp_proof("halo2-vp-proof", c);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
