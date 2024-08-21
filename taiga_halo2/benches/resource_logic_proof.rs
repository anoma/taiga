use criterion::{criterion_group, criterion_main, Criterion};
use halo2_proofs::plonk::{keygen_pk, keygen_vk};

use halo2_proofs::arithmetic::Field;
use pasta_curves::pallas;
use rand::rngs::OsRng;
use rand::Rng;
use taiga_halo2::{
    circuit::{
        resource_logic_circuit::ResourceLogicCircuit,
        resource_logic_examples::TrivialResourceLogicCircuit,
    },
    constant::{NUM_RESOURCE, RESOURCE_LOGIC_CIRCUIT_PARAMS_SIZE, SETUP_PARAMS_MAP},
    nullifier::{Nullifier, NullifierKeyContainer},
    proof::Proof,
    resource::{Resource, ResourceKind},
};

fn bench_resource_logic_proof(name: &str, c: &mut Criterion) {
    let mut rng = OsRng;

    let resource_logic_circuit = {
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
            let rseed = pallas::Base::random(&mut rng);
            Resource {
                kind,
                value,
                quantity,
                nk_container: nk,
                is_ephemeral: false,
                nonce,
                rseed,
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
                let rseed = pallas::Base::random(&mut rng);
                Resource {
                    kind,
                    value,
                    quantity,
                    nk_container: npk,
                    is_ephemeral: false,
                    nonce,
                    rseed,
                }
            })
            .collect::<Vec<_>>();
        let owned_resource_id = input_resources[0].get_nf().unwrap().inner();
        TrivialResourceLogicCircuit::new(
            owned_resource_id,
            input_resources,
            output_resources.try_into().unwrap(),
        )
    };
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
