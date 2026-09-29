use aes_gcm::{Aes256Gcm, KeyInit};

fn cipher(key: &[u8; 32]) {
    let _c = Aes256Gcm::new(key.into());
}
