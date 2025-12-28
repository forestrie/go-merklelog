# Bloom package review - REV-02

Date: 2025-12-28

Scope: `bloom` package (public interface, implementation, tests).
Priorities: performance first, then maintainability (including testability).

## Issue summary

| Issue ID  | Category        | Severity | Area                         | Status   | Summary |
|-----------|-----------------|----------|------------------------------|----------|---------|
| REV-02-1  | Invariants      | Medium   | Sizing / leaf capacity       | Resolved | `MBitsV1` uses unchecked `uint64` multiplication; for extremely large `leafCount` the product can overflow and wrap, and `MBitsSafeCast` may accept a truncated `mBits` value that does not equal `bitsPerElement * leafCount`. |
| REV-02-2  | API semantics   | Low      | Sizing helper contracts      | Resolved | Comments around `MBitsV1` and `CheckBPE` blur responsibility for validating `leafCount`, and `ErrMBitsOverflow` / `ErrSizeOverflow` are slightly confusing in naming and usage. |
| REV-02-3  | Test coverage   | Medium   | Header decode / error paths  | Resolved | Tests exercise happy paths and some input validation, but do not cover several `DecodeHeaderV1` error branches or boundary conditions for sizing helpers. |
| REV-02-4  | Tooling / tests | Medium   | Module / CI integration      | Resolved | The `bloom` package and its tests live outside the `mmr` and `massifs` modules; `go test ./bloom` from the repository root currently fails because there is no Go module at that path, so these tests are not wired into the standard test workflow. |

Overall, the `bloom` package is compact, performance conscious, and mirrors the
`mmr` style of explicit layouts and small helpers. The main opportunities are
around making sizing invariants more explicit and tightening documentation and
 tests so that future callers cannot accidentally rely on out-of-range
configurations or untested error paths.

---

## REV-02-1 - MBitsV1 multiplication and leaf-count invariants

**Finding.** `MBitsV1` computes `mBits64 = bitsPerElement * leafCount` using a
plain `uint64` multiplication:

- `CheckBPE` constrains `bitsPerElement` to be non-zero and at most
  `^uint32(0)`.
- `InitV1` enforces `leafCount > 0` but does not otherwise constrain it.
- `MBitsSafeCast` returns `0` when `mBits64 == 0` or
  `mBits64 > uint64(^uint32(0))`, and `InitV1` maps that to
  `ErrMBitsOverflow`.

For extremely large `leafCount`, the product `bitsPerElement * leafCount` can
overflow `uint64` and wrap to a small non-zero value that is still within the
`uint32` range. In that case:

- `MBitsSafeCast` will return a non-zero `uint32` `mBits`.
- `RegionBytesV1` will size the region for the truncated `mBits`, not for the
  true mathematical product.
- The Bloom filter will still operate without panics (indices are always taken
  modulo the truncated `mBits`), but the effective bits-per-element and
  capacity assumptions will be violated.

This is a theoretical edge case, but it makes the sizing contract less
obvious: callers cannot rely on `mBits == bitsPerElement * leafCount` once the
product grows near `2^64`.

**Impact.**

- In realistic deployments, `leafCount` is unlikely to approach the range
  where `uint64` overflow becomes a concern, so this is not an immediate
  correctness bug.
- For future reuse or different domains with much larger `leafCount`, the
  silent wraparound could lead to filters that appear to accept a
  configuration but actually run with a much smaller `mBits` than intended.

**Recommendations.**

1. Make the supported `leafCount` range explicit and enforce it before the
   multiplication, for example:
   - Require `leafCount <= uint64(^uint32(0))/bitsPerElement`.
   - Treat violations as `ErrMBitsOverflow`.
2. Alternatively, introduce a helper (for example `CheckBloomSizing`) that
   validates `(leafCount, bitsPerElement)` together and is used by `InitV1`
   before calling `MBitsV1`.
3. Document the effective upper bounds in `doc.go` so callers know when they
   are close to the representable limits.

These changes would keep the low-level implementation simple while making the
sizing contract explicit and easier to audit.

**Follow-up (2025-12-28).** The `MBitsV1` comment now documents that
callers are responsible for overflow checks, and all production call
sites that use `MBitsV1` (via `InitV1` in `bloom` and the v2 index
helpers in `massifs`) perform an explicit overflow check before
relying on the result. This issue is considered resolved via
documentation and caller-side validation.

---

## REV-02-2 - Sizing helper contracts and error naming

**Finding.** The sizing helpers are small and easy to follow, and the
responsibilities are now clearly documented:

- `MBitsV1` explicitly states that it performs no overflow checks and that
  callers are responsible for validating inputs (including `leafCount`) and
  detecting overflow when it matters.
- `CheckBPE` is documented and implemented as validating only
  `bitsPerElement` (non-zero and within a `uint32`-compatible range).
- `ErrMBitsOverflow` remains the single error used for overflow-related sizing
  failures in this package.
- The previously unused `ErrSizeOverflow` error has been removed.

**Impact.**

- The contracts for `MBitsV1`, `MBitsSafeCast`, and `CheckBPE` are now
  consistent and self-contained, with no ambiguous cross-references.

**Status.**

- Resolved via documentation updates, caller-side overflow checks (see
  REV-02-1), and removal of the unused `ErrSizeOverflow` symbol.

---

## REV-02-3 - Test coverage gaps for header and sizing error paths

**Finding.** The existing tests cover the main behaviours well:

- `TestBloomV1InsertAndQuery` checks initialization, header fields, and basic
  insert/query behaviour across multiple filters.
- `TestBloomV1RejectsBadInputs` and
  `TestBloomV1RejectsUninitializedRegion` exercise bad filter indices,
  element-size checks, and uninitialized regions.
- `TestSizingV1`, `TestSizingV1_MBbitsSafeCast`, and `TestCheckBPE` cover
  normal sizing cases and some edge cases for `MBitsSafeCast` and
  `CheckBPE`.

Several error paths remain untested:

- `DecodeHeaderV1` branches for `ErrBadMagic`, `ErrBadVersion`,
  `ErrBadFilters`, `ErrBadBitOrder`, and `ErrBadMBits` are not exercised.
- The behaviour of `InsertV1` / `MaybeContainsV1` when the region is too
  small for the claimed `mBits` (triggering `ErrBadRegionSize` after
  `filterBitsetOffV1`) is not tested.
- There are no tests demonstrating the bit-ordering convention end-to-end
  (for example, by checking which byte and bit are touched for a known
  `mBits` and hash pair).

**Impact.**

- Medium: these are mostly defensive error paths, but they are the ones most
  likely to be exercised when integrating with disk formats or external
  tooling. Missing tests make it easier for future refactors to accidentally
  change error contracts.

**Recommendations.**

1. Add focused tests that construct small synthetic headers and regions to
   exercise each `DecodeHeaderV1` error case and confirm the exact error
   values.
2. Add tests that:
   - Initialize a region, then truncate the slice passed to
     `InsertV1` / `MaybeContainsV1` to force `ErrBadRegionSize`.
   - Optionally validate that `filterBitsetOffV1` is consistent with the
     layout documented in `doc.go`.
3. Add a small test that verifies the `BitOrderLSB0` convention by checking
   that a known bit index `j` maps to the expected `(byteIdx, bit)` pair in a
   single-byte bitset.

These tests are cheap and would make future changes to header layout and
sizing logic safer.

**Follow-up (2025-12-28).** New tests now cover:

- `DecodeHeaderV1` happy path, uninitialized zero regions, too-short
  regions, and each error variant (`ErrBadMagic`, `ErrBadVersion`,
  `ErrBadFilters`, `ErrBadBitOrder`, `ErrBadK`, `ErrBadMBits`).
- `EncodeHeaderV1` happy path and its error variants for bad region
  size, bit order, `K`, and `MBits`.
- `filterBitsetOffV1` offsets and out-of-range indices.
- The `BitOrderLSB0` convention end-to-end via `setBitsLSB0` and
  `testBitsLSB0`.
- `InsertV1` / `MaybeContainsV1` behaviour when the region slice is too
  small for the declared `mBits` (triggering `ErrBadRegionSize`).

Together with the existing sizing tests, this provides comprehensive
coverage of the header and sizing error paths described in this issue.

**Status.**

- Resolved via additional unit tests in `bloom/header_test.go` and
  `bloom/bloom4_test.go` that exercise the header encode/decode
  invariants, offset helpers, bit-ordering, and region-size error
  handling alongside the existing sizing tests.

---

## REV-02-4 - Module and CI integration for bloom tests

**Finding.** The `bloom` package lives at the repository root alongside the
`mmr` and `massifs` modules. It now has its own `go.mod`, and the
repository's Task-based CI runs `go test ./...` for all Go modules by
iterating over every `go.mod` in the tree. As a result, the Bloom tests
are exercised whenever `task test:unit` (and thus the CI workflow) is
run.

**Impact.**

- Low: Bloom is now a first-class Go module with tests that run under the
  same Task-based `go test ./...` workflow as the other modules, so it
  benefits from the existing CI/CD conventions in this repository.

**Status.**

- Resolved via the addition of `bloom/go.mod` and the existing
  `gotest:unit` Task, which discovers and tests all Go modules (including
  `bloom`) by iterating over every `go.mod` file.

Ensuring the Bloom tests run under the same tooling as the rest of the
project aligns with the prevailing CI/CD conventions and keeps this
package covered as the surrounding system evolves.
