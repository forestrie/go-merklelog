# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this
repository.

## Repository structure (big picture)
This repo contains two Go modules (there is no `go.mod` at the repo root):

- `mmr/` (`github.com/forestrie/go-merklelog/mmr`)
  - Core Merkle Mountain Range (MMR) algorithms and proofs.
  - Key areas:
    - Append/backfill logic: `mmr/add.go`.
    - Tree navigation math (heights/peaks/indexing): `mmr/indexheight.go`,
      `mmr/peaks*.go`, `mmr/bits.go`.
    - Proof generation: `mmr/proof*.go`.
    - Proof verification: `mmr/verify*.go`.

- `massifs/` (`github.com/forestrie/go-merklelog/massifs`)
  - Stores an MMR in fixed-size "massif" blobs (chunks) and provides APIs for
    reading/writing/verifying those blobs.
  - Depends on `mmr/` and uses a local replace in `massifs/go.mod`.
  - Key areas:
    - Blob format constants and section layout: `massifs/logformat.go`.
    - Blob header (start record) encoding/decoding: `massifs/massifstart.go`.
    - Read/append context for a single massif blob: `massifs/massifcontext.go`.
    - Object-store abstraction for reading/writing blobs and checkpoints:
      `massifs/objectstore.go` and `massifs/storage/`.
    - Checkpoint (COSE Sign1) verification and consistency checking:
      `massifs/massifcontextverified.go`.
    - COSE receipt (MMRIVER) support: `massifs/mmriver.go`.

Developer-oriented background (terminology and math) lives in:
`term-cheatsheet.md` and `mmr-math-cheatsheet.md`.

## Common commands
### Go version
CI is configured for Go 1.24 (see `mmr/go.mod`, `massifs/go.mod`, and
`.github/workflows/ci.yml`).

### Run unit tests
Run tests per module:

```bash
(cd mmr && go test ./...)
(cd massifs && go test ./...)
```

### Run a single test
From inside a module directory:

```bash
# Run a single test function by name
go test ./... -run '^TestName$'

# Run a single package test (useful when `./...` is too broad)
go test ./path/to/pkg -run '^TestName$'
```

Tip: add `-count=1` to avoid cached results while iterating.

### Format code
Go formatting (per-file):

```bash
gofmt -w .
```

CI installs `goimports`; if you use it locally, run it per module (so module
imports resolve correctly):

```bash
(cd mmr && goimports -w .)
(cd massifs && goimports -w .)
```

### Lint
This repo includes a `.golangci.yml` for `golangci-lint`.

Run per module:

```bash
(cd mmr && golangci-lint run ./...)
(cd massifs && golangci-lint run ./...)
```

### Task-based workflow (bootstrap + tests)
This repo includes `Taskfile.dist.yml` (but not a checked-in `Taskfile.yml`).
CI uses `task` targets like `bootstrap`, `test:unit`, and `test:integration`.

Typical setup:

```bash
cp Taskfile.dist.yml Taskfile.yml
task bootstrap
```

Then:

```bash
task test
# or
task test:unit
task test:integration
```

Note: `Taskfile.dist.yml` references shared taskfiles in `../taskfiles/`
(cloned by `task bootstrap` using `.env.bootstrap`) and includes an `azurite`
taskfile for integration testing.