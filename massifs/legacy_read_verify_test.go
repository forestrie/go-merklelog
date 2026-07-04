package massifs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	commoncose "github.com/forestrie/go-merklelog/massifs/cose"
	"github.com/forestrie/go-merklelog/massifs/storage"
	"github.com/forestrie/go-merklelog/mmr"
	"github.com/stretchr/testify/require"
	"github.com/veraison/go-cose"
)

// memReader is a minimal in-memory ObjectReader for read/verify-only tests.
type memReader struct {
	massifs    map[uint32][]byte
	checkpoint map[uint32][]byte
}

func (m *memReader) HeadIndex(ctx context.Context, otype storage.ObjectType) (uint32, error) {
	_ = ctx
	switch otype {
	case storage.ObjectMassifData:
		var max uint32
		var ok bool
		for k := range m.massifs {
			if !ok || k > max {
				max = k
				ok = true
			}
		}
		if !ok {
			return 0, storage.ErrLogEmpty
		}
		return max, nil
	case storage.ObjectCheckpoint:
		var max uint32
		var ok bool
		for k := range m.checkpoint {
			if !ok || k > max {
				max = k
				ok = true
			}
		}
		if !ok {
			return 0, storage.ErrDoesNotExist
		}
		return max, nil
	default:
		return 0, fmt.Errorf("unsupported object type: %v", otype)
	}
}

func (m *memReader) MassifData(massifIndex uint32) ([]byte, bool, error) {
	b, ok := m.massifs[massifIndex]
	if !ok {
		return nil, false, storage.ErrDoesNotExist
	}
	return b, true, nil
}

func (m *memReader) CheckpointData(massifIndex uint32) ([]byte, bool, error) {
	b, ok := m.checkpoint[massifIndex]
	if !ok {
		return nil, false, storage.ErrDoesNotExist
	}
	return b, true, nil
}

func (m *memReader) MassifReadN(ctx context.Context, massifIndex uint32, n int) ([]byte, error) {
	_ = ctx
	b, ok := m.massifs[massifIndex]
	if !ok {
		return nil, storage.ErrDoesNotExist
	}
	if n == -1 || n >= len(b) {
		return b, nil
	}
	return b[:n], nil
}

func (m *memReader) CheckpointRead(ctx context.Context, massifIndex uint32) ([]byte, error) {
	_ = ctx
	b, ok := m.checkpoint[massifIndex]
	if !ok {
		return nil, storage.ErrDoesNotExist
	}
	return b, nil
}

func buildLegacyBlobMassif0(t *testing.T, blobVersion uint16, massifHeight uint8, leafCount int) MassifContext {
	t.Helper()
	require.Greater(t, massifHeight, uint8(0))
	require.GreaterOrEqual(t, leafCount, 0)

	startBytes := EncodeMassifStart(0 /*lastID*/, blobVersion, 1 /*epoch*/, massifHeight, 0 /*massifIndex*/)
	mc := MassifContext{
		Creating:   true,
		Start:      MakeMassifStart(startBytes),
		MassifData: MassifData{Data: append([]byte(nil), startBytes...)},
	}
	mc.Data = append([]byte(nil), startBytes...)

	// Legacy v0/v1 blob layouts reserve only the 32B index header region after the fixed start header.
	// v2 introduces a new bounded index data region (Bloom + Urkle) which is not present here.
	mc.Data = append(mc.Data, make([]byte, IndexHeaderBytes)...)

	// v1+ reserves a fixed peak stack allocation of 64*32 bytes.
	if mc.Start.Version > 0 {
		padBytes := make([]byte, MaxMMRHeight*ValueBytes-(mc.Start.PeakStackLen*ValueBytes))
		mc.Data = append(mc.Data, padBytes...)
	}

	// Add a few leaves (avoid needing ancestor stack by not filling the massif).
	for i := 0; i < leafCount; i++ {
		leafHash := sha256.Sum256([]byte(fmt.Sprintf("legacy-leaf-%d", i)))
		_, err := mc.AddIndexedEntry(leafHash[:])
		require.NoError(t, err)
	}
	return mc
}

// signCheckpointV3 seals the massif with a format-v3 checkpoint receipt
// (draft-bryce COSE Receipt of Consistency) signed by a fresh ES256 key,
// returning the encoded receipt and a verifier for the signing key.
func signCheckpointV3(t *testing.T, mc *MassifContext) ([]byte, cose.Verifier) {
	t.Helper()
	require.Greater(t, mc.RangeCount(), uint64(0))

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer := commoncose.NewTestCoseSigner(t, *key)

	proof, err := BuildConsistencyProof(mc, 0, mc.RangeCount())
	require.NoError(t, err)
	accumulator, err := mmr.PeakHashes(mc, mc.RangeCount()-1)
	require.NoError(t, err)

	signed, err := SignCheckpointReceipt(signer, proof, accumulator)
	require.NoError(t, err)
	return signed, newES256Verifier(t, &key.PublicKey)
}

func TestLegacyBlobFormatV0_ReadAndVerify_CheckpointV3(t *testing.T) {
	// Blob format v0 (legacy), verified against a format-v3 checkpoint
	// receipt. Only the checkpoint (seal) format changed in the v3 cutover;
	// legacy massif blob formats remain readable.
	mc := buildLegacyBlobMassif0(t, 0 /*blobVersion*/, 3 /*massifHeight*/, 2 /*leaves*/)
	signed, verifier := signCheckpointV3(t, &mc)

	store := &memReader{
		massifs:    map[uint32][]byte{0: mc.Data},
		checkpoint: map[uint32][]byte{0: signed},
	}

	vc, err := GetContextVerified(context.Background(), store, verifier, 0)
	require.NoError(t, err)
	require.Equal(t, uint16(0), vc.Start.Version)
	require.Equal(t, mc.RangeCount(), vc.Checkpoint.MMRSize)
	require.NotEmpty(t, vc.Accumulator)
	require.NotEmpty(t, vc.ConsistentRoots)
}

func TestLegacyBlobFormatV1_ReadAndVerify_CheckpointV3(t *testing.T) {
	// Blob format v1 (legacy fixed peak stack allocation), verified against a
	// format-v3 checkpoint receipt.
	mc := buildLegacyBlobMassif0(t, 1 /*blobVersion*/, 3 /*massifHeight*/, 2 /*leaves*/)
	signed, verifier := signCheckpointV3(t, &mc)

	store := &memReader{
		massifs:    map[uint32][]byte{0: mc.Data},
		checkpoint: map[uint32][]byte{0: signed},
	}

	vc, err := GetContextVerified(context.Background(), store, verifier, 0)
	require.NoError(t, err)
	require.Equal(t, uint16(1), vc.Start.Version)
	require.Equal(t, mc.RangeCount(), vc.Checkpoint.MMRSize)
	require.NotEmpty(t, vc.Accumulator)
	require.NotEmpty(t, vc.ConsistentRoots)
}

func TestLegacyBlobFormatV0_IsRejectedByGetAppendContext(t *testing.T) {
	// Sanity check: we still do NOT support legacy blob formats for append contexts.
	mc := buildLegacyBlobMassif0(t, 0 /*blobVersion*/, 3 /*massifHeight*/, 1 /*leaves*/)
	store := &memReader{
		massifs:    map[uint32][]byte{0: mc.Data},
		checkpoint: map[uint32][]byte{},
	}

	_, err := GetAppendContext(context.Background(), store, 1, 3)
	require.Error(t, err)
	require.True(t, errors.Is(err, storage.ErrLogEmpty) || err != nil)
}
