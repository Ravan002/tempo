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
- **`Tip1136/Arithmetic.lean`** proves the integer gadgets in `src/relation.rs` sound modulo `Q100 = 2^100 - 15`, given the lifted-bit widths: gated 64-bit chunk equality (`gated_chunk_eq`), the Merkle direction selector, `threshold >= 1`, the slack-based threshold comparison, packing, and the ordering gap. The one-hot lookup that computes `base64url(digest)` in-circuit is not yet covered.

The Lean model is written separately from the Rust circuit. It does not verify the Rust code, which was neither extracted from Lean nor checked against it. Closing that gap means expressing this circuit in Freigen and loading Freigen's exported `M`, `A`, `B`, and `C` matrices into BitZ; BitZ `main` cannot load that format yet.

## BitZ revision

The crate pins [`decofe/BitZ@73ab1fe`](https://github.com/decofe/BitZ/compare/d7e7257...73ab1fe), which is BitZ `d7e7257` plus two commits:

- **`feat(field): add PCLMULQDQ GF(2^128) kernel for x86_64`.** Upstream uses a hardware carryless multiply only on aarch64. On x86-64, every GF(2^128) multiplication fell back to a 64-step software loop. With this kernel, BitZ's own `sha256-2kb` takes 136 ms to prove instead of 3.45 s, and 39 ms to verify instead of 465 ms (one thread).
- **`feat(cli): check public inputs with a PCS opening`.** Statement values become leading input bits, checked by one random multilinear opening of the committed witness. Previously they were circuit constants. The constraint system is therefore identical for every statement, so setup runs once per circuit profile instead of once per proof, on both the prover and the verifier.

`.cargo/config.toml` enables `pclmulqdq` on x86-64. Without it, the crate silently builds the slow portable kernel.

## Run

The toolchain is pinned to Rust 1.97.1 by `rust-toolchain.toml`, matching BitZ.

```sh
cargo test --release          # accepting and rejected witnesses, statement independence, prove/verify
RAYON_NUM_THREADS=1 cargo run --release --example bench
cargo run --release --example profile   # per-stage timing tree
(cd lean && lake build)       # Lean 4 v4.31.0-rc1, no mathlib
```

## Measurements

Approval by alice (secp256k1), carol (passkey), and eve (secp256k1), on an x86-64 sandbox with a 100-bit PCS round budget:

| | 1 thread | 8 threads |
| --- | --- | --- |
| R1CS constraints | 69,890 | |
| Committed bits | 10,196,036 (padded to 2^24) | |
| Setup (once per profile, not per proof) | 10.8 s | 11.9 s |
| Witness + commit + prove | 2.62 s | 1.29 s |
| Verify | 0.77 s | 0.43 s |
| Proof | 2.41 MB | |

**Where the time goes** (one thread):
- **Proving:** Spartan takes 0.9 s, the integer-to-binary bridge (grand-product GKR and inner-product sumcheck) takes 1.3 s, and Ligerito takes about 10 ms.
- **Verification:** the verifier evaluates the sparse constraint matrices and the bit-to-integer map directly, which is linear in circuit size. Spartan takes 0.27 s and the bridge 0.46 s.
- **Proof size:** about 2.1 MB of the proof is one column-length vector sent by BitZ's virtual opening (2^17 GF(2^128) elements at the current matrix shape).

**Circuit size:** the 8 ECDSA verifiers (one per curve per slot, half of them trivial) are about 9.7M of the committed bits. A profile with fixed slot kinds, for example two secp256k1 and two passkey slots, would halve the circuit. The trade-off is limiting how many approvals of each kind a quorum can use.

## Gaps before this can replace the Noir path

1. **Zero knowledge.** The BitZ prover and the Ligerito openings do not hide the witness. TIP-1136 requires the inner proof itself to hide the policy and credentials. Until then, a proof leaks information about the roster, the keys, and which members signed.
2. **Proof size and verification.** A 2.4 MB proof with linear-time verification is not usable onchain. A fixed onchain verifier needs either the paper's optimizations or a recursive wrapper. A Groth16 wrapper would reintroduce the BN254/setup assumptions that a hash-based stack avoids.
3. **secp256k1.** The ECDSA gadget is a curve-parameterized fork of BitZ's Freigen-ported P-256 circuit. Freigen's proofs cover P-256 only.
4. **WebAuthn padding.** The prover supplies the SHA-256 padding of `clientDataJSON` and selects a hash over 2–4 blocks; the padding itself is not constrained.
   - **Soundness argument:** the checked 80-byte prefix (canonical prefix, `base64url(digest)` computed in-circuit, closing quote) lies inside the hashed blocks. Reusing a signature made for another challenge therefore requires a different block sequence with the same compression-chain output, which is a SHA-256 collision.
   - **Profile limits:** `clientDataJSON` is at most 247 bytes, and `authenticatorData` must be exactly 37 bytes.
5. Origin checks, signature counters, and the OIDC and SMS factors are out of scope, as in the Noir example.
