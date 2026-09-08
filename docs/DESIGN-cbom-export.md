# CBOM export — QS-2 and CAMP-3

**Status:** proposed, not built. One design, two releases:
QryptoScan `release/v0.9.13` and CAMP `release/v0.9.42`.

Both products emit a CycloneDX 1.6 CBOM. They are designed together because
CAMP-5 has to merge the two documents, and two independently-written emitters
merge only by luck.

---

## The finding: the two products cannot join on algorithm name

This is what designing them together was for.

**QryptoScan's `algorithm` is a rule label, not an identifier.** Every distinct
value in the pack:

```
RSA   ECC   DH   MD5   SHA-1   PRNG   AES-ECB   MD5/SHA-1   DES/3DES/RC4
```

`DES/3DES/RC4` names three algorithms. `MD5/SHA-1` names two. `PRNG` is a
category. `ECC` is a family.

**CAMP names things precisely**, because it reads them off the wire —
`KindAlgorithm` carries the IANA group name (`X25519MLKEM768`, `secp256r1`,
`ffdhe2048`) and SSH algorithm names; `KindCipher` carries full suite names.

So `ECC` and `secp256r1` are not joinable, and `DES/3DES/RC4` is not an
identifier at all. **A merge on the existing names would silently produce
garbage** — components that never unify, and one component that is three
algorithms.

## What a component is

Merge at the **primitive**, diverge at the **parameters**, and never guess.

A component is `primitive` plus parameters where known, in CycloneDX's own terms
— `algorithmProperties.primitive` (`kem`, `signature`, `key-agree`, `hash`,
`block-cipher`…) with `parameterSetIdentifier` or `curve`.

The rule that matters:

> **A coarse observation is its own component. It is never merged into a specific
> one.**

QryptoScan sees `KeyPairGenerator.getInstance("EC")` and cannot know the curve.
CAMP sees `secp256r1` on `db-04:443`. Asserting these are the same component is a
fabrication — plausible, unverifiable, and it would make an agency's count wrong
in a document they submit.

So the merged CBOM holds `EC (curve unspecified)` and `EC/secp256r1` as separate
components sharing a primitive. They are *related*, not identical, and the
grouping belongs in the view, not in the identity.

This is unsatisfying and it is correct. The alternative is a product that quietly
invents facts about a customer's estate.

### Risk is algorithmic; agility is not

`pqc_risk` is a property of the algorithm — RSA is `QUANTUM_BROKEN` wherever it
appears — so it belongs on the component.

`agility_grade` is a property of the *usage*: "hardcoded but behind one internal
wrapper" describes code, not RSA. It belongs on the occurrence. Today the rule
pack assigns it statically per rule, so every RSA finding carries `B` regardless
of the actual call site — putting it on the occurrence now costs nothing and is
where it will need to live when QS-5 refines it.

## What each product contributes

| CycloneDX `assetType` | QryptoScan | CAMP |
|---|---|---|
| `algorithm` | Findings — the overlap, and the only place a merge happens | `KindAlgorithm` — TLS kex groups, SSH algorithms |
| `protocol` | — | `KindProtocol` (TLS versions), `KindCipher` (suites) |
| `certificate` | — | `KindCertificate` |
| `related-crypto-material` | — | `KindKey` |
| `algorithm` (library-provided) | `kind=DEPENDENCY` findings, from the catalogue | `KindLibrary` |

The overlap is narrow — a handful of primitives — and that is fine. An agency
asking "where do we use RSA" wants both answers in one document; it does not need
them to be the same row.

## Occurrences

CycloneDX `evidence.occurrences[]`. One component, many sightings.

- **QryptoScan**: `finding.file_path` and `start_line`, plus repository and
  commit. The occurrence also carries `agility_grade`, the triage state, and any
  waiver.
- **CAMP**: asset address, port, site and zone, plus `observed_at` and — after
  CAMP-1 — `first_seen`, so the CBOM can say how long something has been there.

This is what makes the algorithm-level component workable: "we have an RSA
problem" as one component, "and here are 4,000 places" as evidence. The
alternative — 4,000 components — is a document no one can read and a count no one
can report.

## Triage state travels with the occurrence

An inventory that hides accepted risk is wrong. One that shows it without saying
it was accepted is misleading.

So suppressed, accepted and waived findings **appear**, with their state attached
as CycloneDX `properties` on the occurrence (`qryptex:state`, `qryptex:waiver`,
`qryptex:expires`). `FALSE_POSITIVE` is the one exclusion — it is an assertion
that the observation was wrong, not that the risk was accepted.

QryptoScan's acceptances already expire and return for re-confirmation, so the
expiry is real data and belongs in the document. CAMP has no waiver model until
CAMP-7; its occurrences simply carry no state until then.

## The watermark holds

QryptoScan's schema deliberately stores no customer source — findings carry a
file path and a line, and the code is fetched from the provider on demand.

The CBOM carries **path and line only**. No snippet, ever. A path is metadata
about the customer's own repository in a document the customer generates and
holds; a snippet would make the CBOM a code-disclosure channel, which is
precisely what `0001_init.sql` was written to prevent.

## This feeds back into QS-1, which ships first

**QS-1 should also split the compound algorithm labels.**

QS-1 is already restructuring the pack to split fused rules — RSA signature from
RSA key establishment, ECDSA from ECDH — for the function dimension. Splitting
`DES/3DES/RC4` into three and `MD5/SHA-1` into two is the same work, in the same
file, in the same release.

If it waits for QS-2, the rule pack is edited twice, the estate is marked stale
twice, and every customer runs two full rescans instead of one.

The metadata is per-rule, not per-pattern, so a rule that matches three
algorithms cannot resolve which one fired. Splitting the rule is the fix, and
QS-1 is where the file is already open.

## What this does NOT do

- **No aggregation.** CAMP-5 merges. This phase makes two documents that *can*
  be merged.
- **No CycloneDX runtime library.** Per S-0: emit is structs with tags,
  conformance comes from validating against the official JSON Schema in CI.
- **No signing.** A CBOM an agency submits will eventually want an attestation.
  Not here, and worth noting PKI already signs backups and could sign this.
- **No diffing.** "What changed since the last CBOM" is a real request and it is
  CAMP-6's, on CAMP-1's history.

## For review

1. **Is `EC (curve unspecified)` a component, or a component with an unknown
   parameter?** The proposal is the former — a distinct, coarser component. The
   latter reads better in a UI and requires deciding whether two unknowns are the
   same unknown. Leaning to the former, grouped in the view.
2. **Does the normalisation table live in S-0 as data?** It must be shared, or
   the two emitters drift on the first algorithm either adds. Proposal: yes,
   alongside the App. A §2 table, and both products map their native names
   through it.
3. **What is the document's scope by default?** Whole install, or the selected
   site / repository? A CBOM of everything is what the memo asks for; a CBOM of
   one repository is what a team wants. Both, with the scope stated in
   `metadata.component`.
4. **Does CAMP export `UNKNOWN` readiness endpoints?** After CAMP-4 many
   endpoints will be `UNKNOWN` rather than ready or incapable. Omitting them
   flatters the estate; including them without explanation reads as a gap in the
   product. Leaning to include, with the coverage count in `metadata`.
