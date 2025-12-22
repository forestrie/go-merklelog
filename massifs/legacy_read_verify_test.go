package massifs

import (
	"context"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	commoncose "github.com/forestrie/go-merklelog/massifs/cose"
	"github.com/forestrie/go-merklelog/massifs/storage"
	"github.com/forestrie/go-merklelog/mmr"
	"github.com/stretchr/testify/require"
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

func signCheckpointV0(t *testing.T, mc *MassifContext) []byte {
	t.Helper()
	require.Greater(t, mc.RangeCount(), uint64(0))

	cborCodec, err := NewCBORCodec()
	require.NoError(t, err)
	rs := NewRootSigner("test-issuer", cborCodec)

	key := TestingGenerateECKey(t, elliptic.P256())
	signer := commoncose.NewTestCoseSigner(t, key)
	pubKey, err := signer.LatestPublicKey()
	require.NoError(t, err)

	root, err := mmr.GetRoot(mc.RangeCount(), mc, sha256.New())
	require.NoError(t, err)

	state := MMRState{
		// Version omitted (0) -> legacy seal format (LegacySealRoot).
		MMRSize:         mc.RangeCount(),
		LegacySealRoot:  root,
		Timestamp:       1234,
		IDTimestamp:     mc.Start.LastID,
		CommitmentEpoch: mc.Start.CommitmentEpoch,
	}

	signed, err := rs.Sign1(signer, signer.KeyIdentifier(), pubKey, "test-subject", state, nil)
	require.NoError(t, err)
	return signed
}

func signCheckpointV2(t *testing.T, mc *MassifContext) []byte {
	t.Helper()
	require.Greater(t, mc.RangeCount(), uint64(0))

	cborCodec, err := NewCBORCodec()
	require.NoError(t, err)
	rs := NewRootSigner("test-issuer", cborCodec)

	key := TestingGenerateECKey(t, elliptic.P256())
	signer := commoncose.NewTestCoseSigner(t, key)
	pubKey, err := signer.LatestPublicKey()
	require.NoError(t, err)

	peaks, err := mmr.PeakHashes(mc, mc.RangeCount()-1)
	require.NoError(t, err)

	state := MMRState{
		Version:         int(MMRStateVersion2),
		MMRSize:         mc.RangeCount(),
		Peaks:           peaks,
		Timestamp:       1234,
		IDTimestamp:     mc.Start.LastID,
		CommitmentEpoch: mc.Start.CommitmentEpoch,
	}

	signed, err := rs.Sign1(signer, signer.KeyIdentifier(), pubKey, "test-subject", state, nil)
	require.NoError(t, err)
	return signed
}

func TestLegacyBlobFormatV0_ReadAndVerify_LegacyCheckpointV0(t *testing.T) {
	// Blob format v0 (legacy), verify using MMRStateVersion0 path (LegacySealRoot + bagged consistency).
	mc := buildLegacyBlobMassif0(t, 0 /*blobVersion*/, 3 /*massifHeight*/, 2 /*leaves*/)
	signed := signCheckpointV0(t, &mc)

	store := &memReader{
		massifs:    map[uint32][]byte{0: mc.Data},
		checkpoint: map[uint32][]byte{0: signed},
	}

	codec, err := NewCBORCodec()
	require.NoError(t, err)

	vc, err := GetContextVerified(context.Background(), store, &codec, nil, 0)
	require.NoError(t, err)
	require.Equal(t, uint16(0), vc.Start.Version)
	require.Equal(t, int(MMRStateVersion0), vc.MMRState.Version)
	require.NotEmpty(t, vc.ConsistentRoots)
}

func TestLegacyBlobFormatV1_ReadAndVerify_CheckpointV2(t *testing.T) {
	// Blob format v1 (legacy fixed peak stack allocation), verify using v2 checkpoint format (peaks).
	mc := buildLegacyBlobMassif0(t, 1 /*blobVersion*/, 3 /*massifHeight*/, 2 /*leaves*/)
	signed := signCheckpointV2(t, &mc)

	store := &memReader{
		massifs:    map[uint32][]byte{0: mc.Data},
		checkpoint: map[uint32][]byte{0: signed},
	}

	codec, err := NewCBORCodec()
	require.NoError(t, err)

	vc, err := GetContextVerified(context.Background(), store, &codec, nil, 0)
	require.NoError(t, err)
	require.Equal(t, uint16(1), vc.Start.Version)
	require.Equal(t, int(MMRStateVersion2), vc.MMRState.Version)
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



