# TIP-1136 private multisig on Lean / BitZ / binary WHIR

This is a port of the [`tip-1136-private-multisig`](../tip-1136-private-multisig) Noir circuit to the stack that may succeed Noir/Spartan/WHIR:

| Layer | Noir reference | This example |
| --- | --- | --- |
| Specification and gadget proofs | Noir source | Lean 4: relation spec and gadget lemmas in [`lean/`](lean); the P-256 and SHA-256 gadgets are ports of [Freigen](https://github.com/reilabs/freigen)'s verified Lean circuits |
| Arithmetization | R1CS over BN254 | [BitZ](https://github.com/worldfnd/BitZ) ([paper](https://eprint.iacr.org/2026/2141)): integer R1CS over bit-decomposed witnesses, so range checks are free |
| Commitment and opening | WHIR over a prime field | GF(2^128) commitment, ring switching, and Ligerito (binary-field WHIR-style) openings through Flock |

> Research reference. Unaudited, **not zero-knowledge**, test keys only. Not for custody.

## Relation

The public statement and the private witness are the same as in the Noir example: a hidden, committed roster of members with hidden weights reaches a hidden threshold, and each counted member approved the exact `authorization_digest`.

Hashing changes from Poseidon2 to SHA-256. SHA-256 is native to the binary-field backend, and Poseidon2 is not:

```text
leaf              = SHA256("tempo:member:v1\0" || kind || weight_be32 || 0^11 || pkX || pkY || rpIdHash)
roster_root       = depth-4 SHA-256 Merkle tree (16 slots; unused = 0^32)
policy_commitment = SHA256("tempo:policy:v1\0" || threshold_be32 || 0^12 || roster_root || salt)
```

Each of the 4 approval slots runs one secp256k1 verifier and one P-256 verifier. A verifier that does not match the slot's kind, and both verifiers of a disabled slot, check the trivial signature `(Q = G, r = Gx, s = e + r)`, which anyone can produce. Only the matching verifier is tied to the member's committed key. This keeps member kinds private with a fixed circuit shape.

The checks are the same as in the Noir example:

- **Policy opening.** The commitment opens, and `threshold >= 1`.
- **Membership.** Each enabled slot is a Merkle member, and its leaf commits to the member's kind and weight.
- **Ordering.** Enabled slots are packed first with strictly increasing roster positions.
- **Signatures.**
  - secp256k1 members sign the digest directly.
  - Passkey members use strict WebAuthn: the `clientDataJSON` must start with the canonical prefix, with `challenge` equal to `base64url(digest)`. The committed RP ID hash and the UP and UV flags are required, and the signature is P-256 over `sha256(authData || sha256(clientDataJSON))`.
- **Threshold.** The enabled weights sum to at least the threshold.

## Lean

`lake build` in [`lean/`](lean) checks two files. The only axioms are Lean's standard `propext`, `Quot.sound`, and `Classical.choice`, and there is no `sorry`.

- **`Tip1136/Relation.lean`** abstracts the hashes and signatures:
  - `quorum_of_holds` proves that any satisfying assignment exhibits pairwise-distinct roster positions whose approving members' committed weights reach the threshold. Padding contributes nothing.
  - `holds_of_quorum` proves the converse: any such quorum, listed in increasing order, can be encoded.
- **`Tip1136/Arithmetic.lean`** proves that each integer gadget in `src/relation.rs` is sound modulo `Q100 = 2^100 - 15`, given the lifted-bit widths. The gadgets covered are gated 64-bit chunk equality (`gated_chunk_eq`), the Merkle direction selector, `threshold >= 1`, the slack-based threshold comparison, packing, and the ordering gap.

The Lean model is written separately from the Rust circuit. It does not verify the Rust code, which was neither extracted from Lean nor checked against it. Closing that gap means expressing this circuit in Freigen and loading Freigen's exported `M`, `A`, `B`, and `C` matrices into BitZ; BitZ `main` cannot load that format yet.

## Run

The toolchain is pinned to Rust 1.97.1 by `rust-toolchain.toml`, matching BitZ.

```sh
cargo test --release          # 3 accepting and 15 rejected witnesses, prove/verify, encodings
RAYON_NUM_THREADS=1 cargo run --release --example bench
(cd lean && lake build)       # Lean 4 v4.31.0-rc1, no mathlib
```

## Measurements

Approval by alice (secp256k1), carol (passkey), and eve (secp256k1). Measured on an x86-64 sandbox at BitZ `d7e7257`, with a 100-bit PCS round budget:

| | 1 thread | 8 threads |
| --- | --- | --- |
| R1CS constraints | 69,648 | |
| Committed bits | 10,192,772 (padded to 2^24) | |
| Setup (per statement) | 10.8 s | 10.9 s |
| Witness + commit + prove | 64.4 s | 28.4 s |
| Verify | 6.6 s | 1.9 s |
| Proof | 2.26 MB | |

The 8 ECDSA verifiers account for about 9.7M of the committed bits.

These numbers come from BitZ's open-source end-to-end path. For calibration, its own `sha256-2kb` circuit takes 3.45 s to prove and 0.46 s to verify on one thread in the same sandbox, so the paper's figures (for example, ECDSA+SHA-256 in 32 ms) come from a more optimized pipeline. Do not quote either set of numbers as this circuit's production cost.

## Gaps before this can replace the Noir path

1. **Zero knowledge.** The BitZ prover and the Ligerito openings do not hide the witness. TIP-1136 requires the inner proof itself to hide the policy and credentials. Until then, a proof leaks information about the roster, the keys, and which members signed.
2. **Public inputs.** The commitment and digest enter the circuit as constants, so setup is per statement and the verifier repeats it (10.8 s). Production needs public-input columns, so that setup runs once per circuit profile.
3. **Proof size and verification.** A 2.26 MB proof with seconds of verification is not usable onchain. A fixed onchain verifier needs either the paper's optimizations or a recursive wrapper. A Groth16 wrapper would reintroduce the BN254/setup assumptions that a hash-based stack avoids.
4. **secp256k1.** The ECDSA gadget is a curve-parameterized fork of BitZ's Freigen-ported P-256 circuit. Freigen's proofs cover P-256 only.
5. **WebAuthn padding.** The prover supplies the SHA-256 padding of `clientDataJSON` and selects a hash over 2–4 blocks; the padding itself is not constrained.
   - **Soundness argument:** the checked 80-byte prefix lies inside the hashed blocks. Reusing a signature made for another challenge therefore requires a different block sequence with the same compression-chain output, which is a SHA-256 collision.
   - **Profile limits:** `clientDataJSON` is at most 247 bytes, and `authenticatorData` must be exactly 37 bytes.
6. Origin checks, signature counters, and the OIDC and SMS factors are out of scope, as in the Noir example.
