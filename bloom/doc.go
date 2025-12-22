package bloom

/*

# Bloom primitives for Forestrie (4-way, in-place)

This package provides primitive building blocks for Bloom filters intended to
live inside a preallocated massif index region.

It mirrors the `go-merklelog/mmr` style:

- small, composable functions
- explicit byte layouts
- index arithmetic on byte slices
- a burden of knowledge on the caller for hot paths

## What Bloom filters are (and are not)

Bloom filters provide a *probabilistic prefilter*:

- If the filter says "definitely not present", then the element is not present.
- If the filter says "maybe present", then the element may or may not be present
  (false positives are possible).

Bloom filters are NOT cryptographic commitments and do not provide proofs of
exclusion. They are only an I/O optimization.

## 4 parallel filters

Forestrie uses exactly 4 parallel Bloom filters, each indexing 32-byte elements
(the log `ValueBytes`).

The 4 bitsets share identical sizing and are stored side-by-side:

	+----------------------+  32B header (magic, version, params)
	| BloomHeaderV1        |
	+----------------------+  bitset bytes (filter 0)
	| filter0 bitset       |
	+----------------------+  bitset bytes (filter 1)
	| filter1 bitset       |
	+----------------------+  bitset bytes (filter 2)
	| filter2 bitset       |
	+----------------------+  bitset bytes (filter 3)
	| filter3 bitset       |
	+----------------------+

## Indexing and bit numbering

We use deterministic double-hashing and an explicit bit numbering convention.
See `arc-bloom-format-and-support.md` for the full rationale.

## API versioning: why the `V1` suffix exists

Functions in this package are suffixed with a format version (for example
`InitV1`, `InsertV1`, `MaybeContainsV1`).

The suffix means: **this function implements Bloom format version 1** — i.e.
it assumes a specific serialized header layout (magic/version/fields), bit
numbering convention, and hashing/index-derivation rules.

This is deliberate: it allows future incompatible changes (a new header layout,
a different hash scheme, a different bit order, etc.) to be introduced as `V2`
side-by-side, without silently breaking previously persisted data.

*/
