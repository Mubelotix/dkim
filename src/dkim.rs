/// The hashing algorithm used when signing or verifying.
/// Should be sha256 but may be sha1.
#[derive(Debug, PartialEq)]
pub enum SigningAlgorithm {
    RsaSha1,
    RsaSha256,
}

/// The DKIM canonicalization algorithm.
#[derive(Debug, PartialEq)]
pub enum CanonicalizationType {
    /// Disallows modifications expect header addition during mail transit
    Simple,
    /// Allows space duplication and header addition during mail transit
    Relaxed,
}
