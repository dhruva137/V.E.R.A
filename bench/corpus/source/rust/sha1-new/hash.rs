use sha1::{Digest, Sha1};

fn h(data: &[u8]) {
    let mut hasher = Sha1::new();
    hasher.update(data);
}
