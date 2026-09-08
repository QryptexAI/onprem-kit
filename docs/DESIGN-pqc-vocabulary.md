# The PQC vocabulary and CBOM contract

**Status:** proposed, not built. Target `onprem-kit` `v0.4.0`, cut from `v0.3.1`.

M-26-15 App. A §6 asks for **a** central CBOM, not several. CAMP and QryptoScan
will each emit one (CAMP-3, QS-2) and CAMP will merge them (CAMP-5). Two
independently-written emitters produce two documents that concatenate but do not
merge. This is the package that stops that.

---

## The deliverable is the identity function, not the types

The obvious reading of "shared vocabulary" is a package of shared structs. That
is the least important part.

Types can be duplicated harmlessly — two products with their own `Risk` enums
holding the same four strings produce identical JSON. **Identity cannot.** If
CAMP decides a component is `RSA-2048 on host db-04` and QryptoScan decides it is
`RSA in payments/crypto.go:88`, the merge in CAMP-5 has two components where an
agency has one problem, and the estate is double-counted in a number somebody
reports to OMB.

So the contract is a function, not a struct:

```go
// BOMRef returns the stable identity of a cryptographic asset.
// Both products call this. Neither implements it.
func BOMRef(a Asset) string
```

Everything else in this package exists to make that function's inputs
well-defined.

## Where it lives: `onprem-kit/pqc`

The alternative was a new `pqc-kit` sibling, on the grounds that onprem-kit's
README scopes it to "shared on-prem licensing, hostname and trial logic" and
cryptographic vocabulary is domain, not infrastructure.

**That objection is already moot.** The kit contains `backupdest` and
`serviceurl`, neither of which is licensing, hostname or trial logic. The scope
sentence describes an earlier kit. (It also still documents `licence` and
`trial` packages that are not in the repository — the README has drifted in both
directions and should be corrected as part of this change.)

Deciding for `onprem-kit/pqc`:

- Both consumers already require `github.com/QryptexAI/onprem-kit v0.3.1` —
  `camp-core` and `qryptoscan-platform`, the same version, today.
- The `replace`-directive plumbing for sibling development already exists.
- A fourth sibling repository is real overhead — another tag to cut, another
  version to keep in step — for two packages.

PKI's services stay on `v0.2.0` and are untouched. Nothing here forces them
forward.

## What goes in

### `Risk` — the four-value enum

Already exists, twice: as a `CHECK` constraint on QryptoScan's `rule` and
`finding` tables, and as string keys inside CAMP's `crypto_asset.detail` JSONB.
This makes it canonical.

```
QUANTUM_BROKEN | QUANTUM_WEAKENED | PQC_READY | NOT_APPLICABLE
```

Note what this is **not**: it is not a new vocabulary. QryptoScan's constraint is
the definition, and the package restates it so CAMP-1 can adopt it without
inventing a second spelling.

### `Function` — and a decision QS-1 has to take now

QS-1's design proposes `qs-function: KEY_ESTABLISHMENT | SIGNATURE | BOTH |
UNKNOWN`, so that Phase 3 (key establishment, 2030) and Phase 4 (signatures,
2031) can be counted separately.

**CycloneDX already has this field.** `cryptoProperties.algorithmProperties.cryptoFunctions`
is a defined enumeration — `keygen`, `sign`, `verify`, `encrypt`, `decrypt`,
`encapsulate`, `decapsulate`, `digest`, `keyderive`, `tag`.

If QS-1 ships its own coarse enum and this package later adopts CycloneDX's, we
have two vocabularies for one fact — the precise failure this package exists to
prevent, introduced by the phase that runs before it.

**This does not require reordering.** The fix is a decision, not a dependency:
QS-1 stores the CycloneDX-shaped set, and `KEY_ESTABLISHMENT` / `SIGNATURE`
become a derived rollup rather than a stored value.

```go
// Phase3 reports whether this function is key establishment, which is what
// the 31 December 2030 deadline is scoped to.
func Phase3(f Function) bool   // encapsulate, decapsulate, keygen-for-KEM
func Phase4(f Function) bool   // sign, verify
```

The mapping is not one-to-one and that is the point: CycloneDX is finer-grained,
so the coarse answer can always be computed from it and never the reverse. Store
the fine one.

### The App. A §2 table, as data

Algorithm → risk, function, and the specification the memo cites (NIST SP
800-56A, FIPS 186-5, and so on). Both products' rule sets read from it, so
"which algorithms does the memo prohibit" has exactly one answer in the codebase.

As **data, not code**, so CISA extending the list — which the memo explicitly
anticipates — is not a release of three repositories.

### CBOM emit types

Minimal structs with JSON tags, shaped to CycloneDX 1.6 `cryptoProperties`.

## What this does NOT do

- **No CycloneDX runtime library.** `github.com/CycloneDX/cyclonedx-go` is not
  added. We only need to *emit*, which is a struct with tags, and a shared kit
  should not push a dependency onto every consumer for a document we produce
  ourselves. Conformance comes from **validating output against the official
  JSON Schema in CI** — a test-time dependency, not a runtime one. Revisit for
  CAMP-5, which has to *parse*, where a real parser may earn its place.
- **Nothing is emitted here.** QS-2 and CAMP-3 emit. This package only says what
  a component *is*.
- **`scan-worker` is not touched.** It is a separate module with no onprem-kit
  dependency, and it should stay that way — see below.
- **CAMP's columns are not defined here.** CAMP-1 promotes them out of JSONB,
  consuming this package's names.

## scan-worker stays out, deliberately

`qs-function` originates in rule YAML, parsed by `semgrep.go` as a free string.
The temptation is to add onprem-kit to `scan-worker` so the enum constrains it.

Don't. The existing pattern already works and is honest: the worker emits
strings from data, and the **database `CHECK` constraint is the enforcement
point** — that is exactly how `pqc_risk` is handled today. Adding a module
dependency to constrain a YAML string buys a compile-time check on a value that
comes from a file at runtime.

What the package does contribute is the canonical list, so the `CHECK`
constraint and the Go enum are generated from one source and cannot drift.

## Rollout

1. Tag `onprem-kit v0.4.0`.
2. Bump `camp-core` and `qryptoscan-platform` from `v0.3.1`.
3. PKI and the three updaters stay on `v0.2.0`. No forced upgrade.

Nothing observable changes for a customer. This phase's whole output is that the
two phases after it cannot disagree.

## For review

1. **`onprem-kit/pqc` or a new `pqc-kit`?** Recommending the former, on the
   grounds that the scope objection is already historical. If the answer is a new
   repo, it should be decided now — moving a package after two products import it
   is a three-repo change.
2. **What is a component's identity — algorithm, or occurrence?** The sharpest
   question in the package. `RSA` estate-wide is one component with many
   occurrences; `RSA at this call site` is many components. CycloneDX's
   `evidence.occurrences` suggests the former, and the former is what lets an
   agency say "we have an RSA problem" rather than "we have 4,000 RSA problems".
   Leaning to algorithm-level components with occurrence evidence — but it
   decides the shape of both emitters.
3. **Does QS-1 store CycloneDX-shaped functions?** Recommending yes, decided
   before QS-1 builds. Costs nothing now; costs a migration later.
4. **Is the App. A §2 table versioned separately from the kit?** It is data that
   will change when CISA extends it, on someone else's schedule.
