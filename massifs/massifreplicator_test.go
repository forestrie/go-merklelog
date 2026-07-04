package massifs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"

	commoncose "github.com/forestrie/go-merklelog/massifs/cose"
	"github.com/forestrie/go-merklelog/massifs/storage"
	"github.com/forestrie/go-merklelog/mmr"
	"github.com/stretchr/testify/require"
	"github.com/veraison/go-cose"
)

// memStore extends memReader with writes, for replicator sinks.
type memStore struct {
	memReader
}

func (m *memStore) Put(ctx context.Context, massifIndex uint32, ty storage.ObjectType, data []byte, failIfExists bool) error {
	_ = ctx
	_ = failIfExists
	switch ty {
	case storage.ObjectMassifData:
		m.massifs[massifIndex] = append([]byte(nil), data...)
	case storage.ObjectCheckpoint:
		m.checkpoint[massifIndex] = append([]byte(nil), data...)
	default:
		return fmt.Errorf("unsupported object type: %v", ty)
	}
	return nil
}

func newMemStore(massifData, checkpointData []byte) *memStore {
	s := &memStore{memReader{
		massifs:    map[uint32][]byte{},
		checkpoint: map[uint32][]byte{},
	}}
	if massifData != nil {
		s.massifs[0] = massifData
	}
	if checkpointData != nil {
		s.checkpoint[0] = checkpointData
	}
	return s
}

// signCheckpointV3WithSigner seals mc's current range with the provided
// signer, chaining from fromSize (0 for a first seal).
func signCheckpointV3WithSigner(t *testing.T, mc *MassifContext, signer cose.Signer, fromSize uint64) []byte {
	t.Helper()
	proof, err := BuildConsistencyProof(mc, fromSize, mc.RangeCount())
	require.NoError(t, err)
	accumulator, err := mmr.PeakHashes(mc, mc.RangeCount()-1)
	require.NoError(t, err)
	signed, err := SignCheckpointReceipt(signer, proof, accumulator)
	require.NoError(t, err)
	return signed
}

func newReplicatorFixture(t *testing.T, leafCount int) (*MassifContext, *commoncose.TestCoseSigner, cose.Verifier) {
	t.Helper()
	mc := buildLegacyBlobMassif0(t, 1 /*blobVersion*/, 3 /*massifHeight*/, leafCount)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return &mc, commoncose.NewTestCoseSigner(t, *key), newES256Verifier(t, &key.PublicKey)
}

func TestReplicateVerifiedUpdatesBootstrapsEmptySink(t *testing.T) {
	mc, signer, verifier := newReplicatorFixture(t, 2)
	signed := signCheckpointV3WithSigner(t, mc, signer, 0)

	source := newMemStore(mc.Data, signed)
	sink := newMemStore(nil, nil)

	v := &VerifyingReplicator{COSEVerifier: verifier, Source: source, Sink: sink}
	require.NoError(t, v.ReplicateVerifiedUpdates(context.Background(), 0, 0))

	require.Equal(t, source.massifs[0], sink.massifs[0])
	require.Equal(t, source.checkpoint[0], sink.checkpoint[0],
		"the checkpoint object must be replicated verbatim")
}

func TestReplicateVerifiedUpdatesExtendsSinkReplica(t *testing.T) {
	mc, signer, verifier := newReplicatorFixture(t, 2)
	sealedSize := mc.RangeCount()
	signed := signCheckpointV3WithSigner(t, mc, signer, 0)

	source := newMemStore(mc.Data, signed)
	sink := newMemStore(nil, nil)

	v := &VerifyingReplicator{COSEVerifier: verifier, Source: source, Sink: sink}
	require.NoError(t, v.ReplicateVerifiedUpdates(context.Background(), 0, 0))

	// The source log grows and is re-sealed; a second replication must carry
	// the extension into the sink.
	leafHash := sha256.Sum256([]byte("extension-leaf"))
	_, err := mc.AddIndexedEntry(leafHash[:])
	require.NoError(t, err)
	source.massifs[0] = mc.Data
	source.checkpoint[0] = signCheckpointV3WithSigner(t, mc, signer, sealedSize)

	require.NoError(t, v.ReplicateVerifiedUpdates(context.Background(), 0, 0))
	require.Equal(t, source.massifs[0], sink.massifs[0])
	require.Equal(t, source.checkpoint[0], sink.checkpoint[0])

	// Replicating again with no changes is a no-op.
	require.NoError(t, v.ReplicateVerifiedUpdates(context.Background(), 0, 0))
}

func TestReplicateVerifiedUpdatesRejectsWrongSealer(t *testing.T) {
	mc, signer, _ := newReplicatorFixture(t, 2)
	signed := signCheckpointV3WithSigner(t, mc, signer, 0)

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	source := newMemStore(mc.Data, signed)
	sink := newMemStore(nil, nil)

	v := &VerifyingReplicator{
		COSEVerifier: newES256Verifier(t, &otherKey.PublicKey),
		Source:       source, Sink: sink,
	}
	err = v.ReplicateVerifiedUpdates(context.Background(), 0, 0)
	require.ErrorIs(t, err, ErrSealVerifyFailed)
	require.Empty(t, sink.massifs, "nothing may be replicated from an unverifiable source")
}

func TestReplicateVerifiedUpdatesRejectsTruncatedSource(t *testing.T) {
	mc, signer, verifier := newReplicatorFixture(t, 3)
	signed := signCheckpointV3WithSigner(t, mc, signer, 0)

	// The sink already replicated the 3-leaf log, but the source now presents
	// a shorter (truncated) log with a fresh seal.
	sink := newMemStore(mc.Data, signed)

	shorter := buildLegacyBlobMassif0(t, 1, 3, 2)
	source := newMemStore(shorter.Data, signCheckpointV3WithSigner(t, &shorter, signer, 0))

	v := &VerifyingReplicator{COSEVerifier: verifier, Source: source, Sink: sink}
	err := v.ReplicateVerifiedUpdates(context.Background(), 0, 0)
	require.Error(t, err)
	require.Equal(t, mc.Data, sink.massifs[0], "the sink replica must be untouched")
}
