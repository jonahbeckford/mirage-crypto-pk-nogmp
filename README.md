# mirage-crypto-pk-nogmp

The library `mirage-crypto-pk` 2.0.2 without arithmetic, for Windows MSVC, which has no easy way to get GMP.

Consequence: no RSA and no DHE. Server and client certificates must be ECDSA or Ed25519.

The packages `tls-nogmp` and `x509-nogmp` of `diskuv-opam-repository` use it in place of `mirage-crypto-pk`.
