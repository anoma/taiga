mod basic_swap_without_intent_note;
mod token;
fn main() {
    use rand::rngs::OsRng;

    let rng = OsRng;
    let tx = basic_swap_without_intent_note::create_token_swap_transaction(rng);
    tx.execute().unwrap();
}
