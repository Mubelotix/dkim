//! A complete DKIM Rust library.  
//! It is still experimental and not ready for production.  
//!   
//! # Goals  
//!
//! 1. Make it work
//!     - [x] Relaxed canonicalization algorithm
//!     - [x] Simple canonicalization algorithm
//!     - [x] Verifying
//!     - [x] Signing
//!     - [x] Documentation
//!     - [x] Sha256
//!     - [x] Sha1
//! 2. Make it stable and robust
//!     - [x] Stabilize parsing
//!     - [ ] Improve project structure
//!     - [ ] Fulfill each "MUST" of the RFC
//!     - [ ] Fulfill each "SHOULD" of the RFC
//!     - [ ] Write tests
//!     - [ ] Eradicate unwraps
//! 3. Make it fast
//!     - [ ] Benchmarks
//!     - [ ] Compare to other implementations
//!     - [ ] Optimize

/// Canonicalization functions
pub mod canonicalization;
/// DKIM related types
pub mod dkim;
/// Hash functions
pub mod hash;
/// Parsing functions
pub mod parsing;
/// Common objects
pub mod prelude;
/// The PublicKey struct
pub mod public_key;
/// The Signature struct
pub mod signature;
/// Signing functions
pub mod signing;
/// Verification functions
pub mod verifying;
