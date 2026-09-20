# Changelog

Notable, consumer-affecting changes to the `go-merklelog` modules
(`mmr`, `massifs`, `urkle`, `bloom`). Each module is versioned independently;
entries note the affected module.

## Unreleased

### Breaking

- **massifs:** `SignCheckpointReceipt` now signs the consistency proof's
  `tree-size-2` in the protected header under the private label
  `CheckpointLabelTreeSize2` (-65933) (ADR-0066, FOR-568). `tree-size-1`
  stays unsigned in the consistency proof; verifiers take the origin from
  state they trust. `VerifyCheckpointReceipt` requires the label and rejects
  a receipt whose signed size differs from the declared one
  (`ErrSignedSizeMismatch`), a header without it (`ErrSignedSizeMissing`), a
  non-canonical header (`ErrProtectedHeaderInvalid`) and an incomplete
  signed size (`mmr.ErrIncompleteTreeSize`); receipts signed with the
  previous `{alg, vds}` header no longer verify. Read the signed size with
  `ProtectedHeaderTreeSize`. `ProtectedHeaderAlgorithm` now also requires a
  canonical header.
- **mmr:** `VerifyConsistency` now folds through `ConsistentRootsForSizes`:
  `MMRSizeB` must be a complete MMR size and every path must have exactly
  the length the two sizes imply. Failures wrap the new sentinels
  `ErrIncompleteTreeSize`, `ErrConsistencyPathLength`,
  `ErrConsistencyPeakCount` and `ErrConsistencyRootMismatch`.

### Added

- **mmr:** `ConsistentRootsForSizes`, the size-driven consistency fold of
  draft-bryce-cose-receipts-mmr-profile (a port of the univocity and Python
  references, pinned to the same KAT-39 vectors), and `MMRSizeForLeafCount`.
- **massifs:** `VerifyCheckpointReceiptFromState` verifies a checkpoint
  receipt from a trusted `(size, accumulator)` without log data; every proof
  node must be the hash width (`ErrNodeWidth`).

- **urkle:** Removed exported errors `ErrLeafCountDoesNotFit32` and
  `ErrLeafOrdinalDoesNotFit16`. All leaf-ordinal / capacity failures now wrap
  the single base error `ErrLeafOrdinalDoesNotFit`; detect them with
  `errors.Is(err, urkle.ErrLeafOrdinalDoesNotFit)` and inspect the wrapped
  message for context.
- **urkle:** Removed the unused `KeyData` stub. Use `KeyFields` for key
  iteration over the leaf table.
- **bloom:** Removed the unused exported error `ErrSizeOverflow`. Overflow-
  related sizing failures report `ErrMBitsOverflow`.

### Fixed

- **urkle:** `NewBuilderFromFrontier` now rejects a decoded frontier whose
  `Pending` node ref is out of range (`>= Next`, or `NoRef` on a non-empty
  trie) with `ErrFrontierBadState`, instead of panicking on out-of-bounds node
  access when resuming from a corrupted frontier block.
- **urkle:** `CheckMassifHeight` now fails closed for `massifHeight > 64`
  (previously the `1 << (massifHeight-1)` shift wrapped to `0` and spuriously
  passed). `NewIndexViewFromMassifHeight` now enforces this bound.
- **urkle:** `DecodeFrontierV1` reports an out-of-range `Depth` as
  `ErrFrontierBadState` (was `ErrFrontierBadSize`), matching
  `NewBuilderFromFrontier`.
