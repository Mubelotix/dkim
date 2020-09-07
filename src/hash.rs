pub fn body_hash_sha1(data: &str) -> Vec<u8> {
    use sha1::{Digest, Sha1};

    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

pub fn data_hash_sha1(headers: &str, dkim_header: (Option<&str>, &str, &str)) -> Vec<u8> {
    use sha1::{Digest, Sha1};

    let mut hasher = Sha1::new();
    hasher.update(headers);
    if let Some(name) = dkim_header.0 {
        hasher.update(name);
        hasher.update(":");
    }
    hasher.update(dkim_header.1);
    hasher.update(dkim_header.2);
    hasher.finalize().to_vec()
}

pub fn body_hash_sha256(data: &str) -> Vec<u8> {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

pub fn data_hash_sha256(headers: &str, dkim_header: (Option<&str>, &str, &str)) -> Vec<u8> {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(headers);
    if let Some(name) = dkim_header.0 {
        hasher.update(name);
        hasher.update(":");
    }
    hasher.update(dkim_header.1);
    hasher.update(dkim_header.2);
    hasher.finalize().to_vec()
}
