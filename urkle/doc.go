package urkle

/*

# Urkle primitives for Forestrie (in-place, append-only writes)

This package provides primitive building blocks for an Urkle-style radix trie
over 64-bit keys (`idtimestamp`), designed for storing inside a fixed-size,
preallocated massif index region.

It follows the same "functional primitives" style as `go-merklelog/mmr`:

- small, composable functions
- explicit byte layouts
- index/position arithmetic where possible
- a burden of knowledge on the caller for hot paths

## Core invariants

The append-only builder relies on:

1. keys are strictly increasing (`newKey > lastKey`)
2. keys are traversed MSB-first (bit index 0 is the MSB)
3. all backing storage is preallocated and zero-filled

If (1) is violated, append-only postorder emission becomes unsound (it would
require rewriting previously-emitted branch nodes).

## Why we store spans (B′) instead of child refs

An MMR can infer parent/child relationships from indices alone because its
shape is determined solely by the append count.

A trie is key-shaped, not append-shaped, so we persist minimal structure to
support pointer-free navigation:

- branch nodes store `rightSpan` (node count of the right subtree)

Then for a branch node at record index i:

	rightRoot = i - 1
	leftRoot  = i - 1 - rightSpan

This is the closest trie analogue to the `mmr.IndexHeight` style arithmetic.

## Layout (high level)

The package standardizes record formats for:

- a fixed-size `leafTable` storing `(key,valueBytes[32])`
- a fixed-size `nodeStore` storing postorder node records
- a fixed-size `FrontierStateV1` snapshot to resume building across batches

See `arbor/docs/arc-urkle-format-and-support.md` for the full rationale.

*/

