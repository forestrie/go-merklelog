# Changelog

Notable, consumer-affecting changes to the `go-merklelog` modules
(`mmr`, `massifs`, `urkle`, `bloom`). Each module is versioned independently;
entries note the affected module.

## Unreleased

### Breaking

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
