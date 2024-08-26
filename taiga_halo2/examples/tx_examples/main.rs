// mod partial_fulfillment_token_swap;
mod token;
// mod token_swap_with_intent;
mod token_swap_without_intent;
fn main() {
    use rand::rngs::OsRng;

    let rng = OsRng;
    let tx = token_swap_without_intent::create_token_swap_transaction(rng);
    tx.execute().unwrap();

    // let tx = token_swap_with_intent::create_token_swap_intent_transaction(rng);
    // tx.execute().unwrap();

    // let tx = partial_fulfillment_token_swap::create_token_swap_transaction(rng);
    // tx.execute().unwrap();
}
