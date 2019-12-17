# Details of the ECDAA Algorithm Used

## Existing Literature and Specifications

The signature algorithm is that
of [Camenisch et al., 2017](https://eprint.iacr.org/2017/639), with the following differences:
- We don't use the "split-keys" functionality
  - This is for interoperability with the existing FIDO ECDAA specification.
  - Also, this allows the entire credential to be held on a TPM, if necessary.
- We don't prepend a `0` to the issuer's nonce before hashing, during the JOIN protocol.
  - This is for interoperability with the existing FIDO ECDAA specification.
  - Instead, this implementation only generates issuer nonces that begin with `1`,
    and rejects any externally-provided nonce that doesn't begin with `1`.
- Similarly, we don't prepend a `1` to the basename before hashing during a SIGN or VERIFY.
  - This is for backwards-compatibility with existing implementations.
  - Instead, the leading byte of the basename is bitwise-`AND`d with `0b0111 = 0x07`
    before hashing during a SIGN or VERIFY, to ensure it begins with a `0`.
  - The reason for swapping the roles of `0` and `1` relative to
    [Camenisch et al., 2017](https://eprint.iacr.org/2017/639) is, again,
    backwards-compatibility with existing implementations.
- The implementations of "private-key-based revocation" and "signature-based revocation"
  are slightly different from those in [Camenisch et al., 2017](https://eprint.iacr.org/2017/639).
  - For private-key-based revocation, we use the implementation of 
    [Camenisch et al., 2016](https://doi.org/10.1007/978-3-662-49387-8_10).
    - This allows for private-key-based revocation even if a basename isn't used.
    - This also allows interoperability with the existing FIDO ECDAA specification.
    - Note, however, that if a basename is being used, the more-efficient private-key-based
      revocation check of [Camenisch et al., 2017](https://eprint.iacr.org/2017/639)
      can be used by adding `[sk_i]*H_g1(0x07 ^ basename)` to the *signature* revocation
      list, for each revoked `sk_i` (cf. the discussion of signature revocation below).
  - Signature-based revocation in this implementation is actually just an example of the LINK functionality.
    - The signature-revocation-list is verifier-local, and is just a list of revoked `nym`s.
    - During the VERIFY, the signer's `nym` is checked against this list. 
    - This means revoked signatures can only be checked when using the same basename.
    - However, it alleviates the signer from having to obtain the signature-revocation-list
      before each signature.
  

## FIDO ECDAA Interoperability

This implementation is also compatible with Version 2.0 Implementation Draft of the
[FIDO ECDAA](https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-ecdaa-algorithm-v2.0-id-20180227.html)
specification, with the following exception:
- TPM-based signatures in this implementation do *not* use the `TPM2_Certify` function
  - Instead, this implementation uses `TPM2_sign` and thus is generic,
    in the sense that it can be used to sign
    *any* message, not just a TPM-generated public key.

## Generating Elliptic Curve Points from Hashes
