use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

fn load(pkcs8: &[u8], rng: &dyn ring::rand::SecureRandom) {
    let _kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8, rng);
}
