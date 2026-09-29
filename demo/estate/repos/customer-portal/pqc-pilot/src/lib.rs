use ml_kem::MlKem768;
use ring::signature::EcdsaKeyPair;

pub fn pilot_keys(rng: &mut impl rand_core::CryptoRngCore) {
    let (dk, ek) = MlKem768::generate(rng);
    let _ = (dk, ek);
}

pub fn legacy_signer(pkcs8: &[u8]) {
    let _ = EcdsaKeyPair::from_pkcs8(&ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8);
}
