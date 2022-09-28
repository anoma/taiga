use criterion::{criterion_group, criterion_main, Criterion};
use plonk_core::{
    circuit::{verify_proof, VerifierData},
    prelude::{Circuit, StandardComposer},
};
use rand::rngs::OsRng;
use taiga_zk_garage::app::App;
use taiga_zk_garage::circuit::circuit_parameters::PairingCircuitParameters as CP;
use taiga_zk_garage::circuit::validity_predicate::NUM_NOTE;
use taiga_zk_garage::{
    circuit::{
        circuit_parameters::CircuitParameters, vp_examples::balance::BalanceValidityPredicate,
    },
    note::Note,
};
type Fr = <CP as CircuitParameters>::CurveScalarField;
type P = <CP as CircuitParameters>::InnerCurve;
type PC = <CP as CircuitParameters>::CurvePC;

fn bench_vp_proof(name: &str, c: &mut Criterion) {
    let mut rng = OsRng;

    let xan = App::<CP>::dummy(&mut rng);
    // input notes
    let input_notes = [(); NUM_NOTE].map(|_| Note::<CP>::dummy_from_app(xan.clone(), &mut rng));
    // output notes
    let mut output_notes = input_notes.clone();
    let tmp = output_notes[0].value;
    output_notes[0].value = output_notes[1].value;
    output_notes[1].value = tmp;

    let mut balance_vp = BalanceValidityPredicate::new(input_notes, output_notes);

    let mut composer = StandardComposer::<Fr, P>::new();
    balance_vp.gadget(&mut composer).unwrap();
    composer.check_circuit_satisfied();

    let pp = CP::get_pc_setup_params(balance_vp.padded_circuit_size());
    let (pk, vk) = balance_vp.compile::<PC>(pp).unwrap();

    // Prover bench
    // ! TOO SLOW !
    // let prover_name = name.to_string() + "-prover";
    // c.bench_function(&prover_name, |b| {
    //     b.iter(|| {
    //         balance_vp.gen_proof::<PC>(pp, pk.clone(), b"Test").unwrap();
    //     })
    // });
    let (proof, public_input) = balance_vp.gen_proof::<PC>(pp, pk, b"Test").unwrap();

    // Verifier bench
    let verifier_name = name.to_string() + "-verifier";
    c.bench_function(&verifier_name, |b| {
        b.iter(|| {
            let verifier_data = VerifierData::new(vk.clone(), public_input.clone());
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
    let verifier_data = VerifierData::new(vk, public_input);
    assert!(
        verify_proof::<Fr, P, PC>(pp, verifier_data.key, &proof, &verifier_data.pi, b"Test")
            .is_ok()
    );
}

fn criterion_benchmark(c: &mut Criterion) {
    bench_vp_proof("vp-proof", c);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
