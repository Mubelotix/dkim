# dkim

A complete DKIM Rust library.
It is still experimental and not ready for production.

## Goals

When one of the three steps is completed, the minor version is incremented.
As long as the major version is 0, any update can introduce breaking changes.

1. Make it work
    - [x] Relaxed canonicalization algorithm
    - [x] Simple canonicalization algorithm
    - [x] Verifying
    - [x] Signing
    - [x] Documentation
    - [x] Sha256
    - [x] Sha1
2. Make it stable and robust
    - [ ] Fulfill each "MUST" of the RFC
    - [ ] Fulfill each "SHOULD" of the RFC
    - [ ] Write tests
    - [ ] Eradicate unwraps
3. Make it fast
    - [ ] Benchmarks
    - [ ] Compare to other implementations
    - [ ] Optimize

License: MIT
