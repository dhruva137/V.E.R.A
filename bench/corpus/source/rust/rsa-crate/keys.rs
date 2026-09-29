use rsa::RsaPrivateKey;

fn make(rng: &mut rand::rngs::OsRng) {
    let _key = RsaPrivateKey::new(rng, 2048).unwrap();
}
