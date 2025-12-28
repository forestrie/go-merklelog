# Urkle package review  REV-01

Date: 2025-12-28

Scope: `urkle` package (public interface, implementation, tests).
Priorities: performance first, then maintainability (including testability).

## Issue summary

| Issue ID  | Category        | Severity | Area                         | Status   | Summary |
|-----------|-----------------|----------|------------------------------|----------|---------|
| REV-01-1  | Robustness      | High     | Frontier / builder resume    | Resolved | Added structural validation in `DecodeFrontierV1` and capacity/frame checks in `NewBuilderFromFrontier` so malformed frontier data is rejected instead of causing panics. |
| REV-01-2  | API semantics   | Medium   | Ordinal-based key lookups    | Resolved | Clarified that idtimestamps are strictly non-zero, and updated `LeafOrdinalKey16`/`LeafOrdinalInclusionProof` docs so a return value of 0 is an unambiguous "not present" sentinel. |
|| REV-01-3  | Invariants      | Medium   | Sizing / massif integration  | Resolved | `CheckMassifHeightFitsLeafOrdinalBytes` and `CheckLeafCount` have slightly different limits; some `(massifHeight, ordinalBytes)` pairs pass one check but not the other. |
| REV-01-4  | Consistency     | Low      | Error contracts / naming     | Resolved | Consolidated leaf-ordinal/capacity conditions under `ErrLeafOrdinalDoesNotFit`, adding contextual formatting where needed. |
| REV-01-5  | Design / API    | Low      | Key iteration helpers        | Resolved | Removed the unused `KeyData` stub; `KeyFields` remains the primary key-iteration API. |
| REV-01-6  | Test coverage   | Medium   | Frontier / sizing utilities  | Resolved | Added focused tests for frontier encode/decode (happy path and error paths) and sizing helpers (NodeCountMax, CheckLeafCount, massif height checks). |

Overall, the package is well structured, performance conscious, and already
has good invariants and tests around the core builder and proof machinery.
The issues above are mostly about hardening edge cases, tightening API
contracts, and improving clarity for future users.

---

## REV-01-1  FrontierStateV1 decode invariants

**Finding.** `DecodeFrontierV1` decodes a `FrontierStateV1` struct from a raw
byte buffer but does not validate several key invariants before returning:

- `Depth` is copied directly from `src[24]` without checking that
  `Depth  0` and `Depth  FrontierMaxDepth`.
- `Frames` entries are not validated; `Left` refs may point outside the
  range `[0, Next)`.
- `Next` and `NextLeaf` are not checked against the capacities implied by
  the backing buffers used in `NewBuilderFromFrontier`.

`NewBuilderFromFrontier` uses the decoded state directly. In particular,
`InsertMonotone` indexes into `b.st.Frames[b.st.Depth-1]` when closing
frames. If `Depth > FrontierMaxDepth` in a malformed frontier block,
this will panic with an out-of-bounds slice/array access.

Under normal operation, `Depth` and the frames are maintained by the
builder and are safe. The risk arises if frontier bytes come from a
corrupted disk block, a different implementation, or a future version.

**Impact.**

- For trusted, same-version frontiers this is not a correctness bug.
- For untrusted or corrupted frontier blocks, `NewBuilderFromFrontier`
  can panic rather than returning a clean error.

**Recommendations.**

1. In `DecodeFrontierV1`, add structural validation before returning:
   - Reject states where `Depth > FrontierMaxDepth`.
   - Optionally reject states where `Depth > 0` but `Pending == NoRef`.
2. In `NewBuilderFromFrontier`, after `DecodeFrontierV1` succeeds:
   - Check that `st.NextLeaf  b.leafCap` and `st.Next  b.nodeCap`.
   - Optionally iterate the active frames `[0..Depth-1]` and verify that
     each `Left` is `< st.Next`.
3. Treat any violation as a hard error (wrapping an `ErrFrontierBad*`
   variant), so callers never see panics from malformed frontier data.

These checks are one-time on frontier load and have negligible impact on
steady-state performance, while significantly improving robustness.

**Status.** Implemented by adding depth and pending-ref validation in
`DecodeFrontierV1` and capacity plus frame-`Left` checks in
`NewBuilderFromFrontier`, returning `ErrFrontierBadState` for invalid
frontier state instead of panicking.

---

## REV-01-2  LeafOrdinalKey16 sentinel semantics

**Finding.** `LeafOrdinalKey16` returns the `idtimestamp` for a
`leafOrdinal` if it is present, otherwise it returns `0`:

- `ord >= nextLeaf` or `ord >= v.LeafCount`  returns `0`.
- Presence is determined only by `nextLeaf`, which is expected to be
  authenticated by higher-level metadata.

This makes absence indistinguishable from a legitimate key of `0`. The
function comment documents that it returns `0` on absence, but does not
explicitly state that `0` must be impossible (or reserved) in the key
space.

**Impact.**

- If `0` is a valid `idtimestamp` in any configuration, callers cannot
  reliably distinguish "missing" from "present and equal to 0".
- The ambiguity is subtle and might only surface when a new caller uses
  key `0` without reading the fine print of the comment.

**Recommendations.**

1. If possible, tighten the contract:
   - Prefer returning `(uint64, bool)` where `ok` signals presence, or
     `(uint64, error)` using `ErrLeafOrdinalNotPresent`.
2. If the key domain truly excludes `0`, encode this more strongly:
   - Document explicitly that `idtimestamp` is strictly positive.
   - Consider asserting this at insert time in higher-level code paths.
3. At minimum, add a small test that exercises the
   `ErrLeafOrdinalNotPresent` path and verifies that `0` is used as the
   absence sentinel.

This change would improve API clarity and make the function safer for
future reuse without affecting the hot-path builder or proof code.

**Status.** Resolved by relying on the established invariant that
idtimestamps are strictly non-zero and by updating comments on
`LeafOrdinalKey16` and `LeafOrdinalInclusionProof` to document that a
return value of 0 can be treated as "not present".

---

## REV-01-3  Sizing invariants and massif integration

**Finding.** Several helpers encode limits on leaf counts, but their
contracts are slightly misaligned:

- `CheckLeafCount` rejects `leafCount > ^uint32(0)`.
- `CheckMassifHeightFitsLeafOrdinalBytes` allows up to
  `LeafCountForMassifHeight(massifHeight)  2^(8*ordinalBytes)`.
- With `ordinalBytes == LeafOrdinalBytes (4)`, a massif height of `33`
  yields `leafCount = 2^32`, which passes the massif check but fails
  `CheckLeafCount`.

In practice, massif heights are probably well below this bound, so this
is mostly a theoretical mismatch. However, it makes the combined API
harder to reason about.

**Impact.**

- A caller that relies only on `CheckMassifHeightFitsLeafOrdinalBytes`
  may believe a configuration is valid, then later hit
  `ErrLeafCountDoesNotFit32` when constructing an index.

**Recommendations.**

1. Decide on the true maximum supported `leafCount` and encode it in one
   place (either allow `2^32` or intentionally cap at `2^32-1`).
2. Make `CheckMassifHeightFitsLeafOrdinalBytes` delegate to
   `CheckLeafCount` (or share a common internal helper) so all callers
   see a consistent limit.
3. Add tests that cover boundary massif heights and ordinal byte widths
   to prevent future regressions.

**Status.**

- Resolved by:
  - Introducing `CheckMassifHeight`, which enforces the same uint32
    leafCount bound as `CheckLeafCount` for any `massifHeight` via
    `LeafCountForMassifHeight`.
  - Updating `CheckMassifHeightFitsLeafOrdinalBytes` to call
    `CheckLeafCount` first and then apply the additional
    `ordinalBytes`-based constraint only when `ordinalBytes <
    LeafOrdinalBytes`, so `(massifHeight,ordinalBytes)` pairs now see a
    consistent capacity limit.
  - Documenting in `urkle/doc.go` that the v2 index layout, with
    `LeafOrdinalBytes == 4` and uint32-backed counters, effectively caps
    the usable `massifHeight` at 32 even though the underlying MMR can
    support taller trees.
  - Extending `sizing_test.go` to exercise the `massifHeight == 32/33`
    boundary and confirm that all helpers agree on the allowed
    configurations.

---

## Consistency issues (REV-01-4  REV-01-5)

### REV-01-4  Leaf-ordinal error naming and usage

**Finding.** There were three related error values:

- `ErrLeafOrdinalDoesNotFit` (configured width).
- `ErrLeafOrdinalDoesNotFit16` (hard-coded `uint16`).
- `ErrLeafCountDoesNotFit32` (capacity check for 32-bit counters).

They were used in slightly different places (`CheckMassifHeightFits*`,
`KeyLeafOrdinal`, `Builder.initCaps`), which made it harder to reason
about which capacity constraint had actually failed.

**Resolution.**

- Introduced a single base error `ErrLeafOrdinalDoesNotFit` with a more
  general message covering both ordinal and capacity constraints.
- Updated callers to wrap this base error with context-specific
  formatting, for example:
  - `CheckLeafCount` and `Builder.initCaps` now return
    `ErrLeafOrdinalDoesNotFit` with details when `leafCount` / `leafCap`
    exceed uint32-backed capacities.
  - `CheckMassifHeightFitsLeafOrdinalBytes` wraps
    `ErrLeafOrdinalDoesNotFit` with the offending `massifHeight`,
    `ordinalBytes`, and implied capacities.
  - `KeyLeafOrdinal` reports ordinals that do not fit in `uint16` as
    wrapped `ErrLeafOrdinalDoesNotFit` errors (with the actual ordinal in
    the message).

Callers can now use `errors.Is(err, ErrLeafOrdinalDoesNotFit)` to detect
any of these failures and inspect the wrapped message if they need more
context. This keeps the exported error surface smaller while preserving
useful diagnostics.

### REV-01-5  KeyData stub API

**Finding.** `KeyData` was an exported helper that always returned
`(nil, false)` for the current fixed-size leaf-table layout and was not
used in the existing code.

**Resolution.**

- Removed the `KeyData` function entirely; `KeyFields` remains the
  primary, explicit API for iterating keys in the leaf table.

---

## REV-01-6  Test coverage gaps

**Finding.** Core functionality (builder, proofs, node-store invariants,
leaf extras, and index view APIs) was well covered, but several utility
edges were less thoroughly exercised.

**Resolution.**

- Added `frontier_test.go` to cover frontier encode/decode behaviour:
  - Happy-path round-trip of a populated `FrontierStateV1`.
  - Empty/uninitialised (all-zero) frontier blocks.
  - Truncated buffers and invalid magic/version bytes.
  - Invalid structural states (bad depth/pending combinations) and
    verification that `NewBuilderFromFrontier` rejects inconsistent
    frontier state.
- Added `sizing_test.go` to cover sizing helpers:
  - `NodeCountMax`, `LeafTableBytes`, and `NodeStoreBytes` for typical
    values.
  - `CheckLeafCount` at the uint32 boundary.
  - `LeafOrdinalBits` for several representative leaf counts.
  - `LeafCountForMassifHeight` and
    `CheckMassifHeightFitsLeafOrdinalBytes`, including a failing
    configuration that exceeds the representable capacity.

These tests exercise both happy-path and error-path behaviour and should
make future changes to the frontier layout and sizing logic safer.
