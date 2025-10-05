package massifs

import (
	"context"
	"errors"
	"fmt"

	commoncbor "github.com/datatrails/go-datatrails-merklelog/massifs/cbor"
	"github.com/datatrails/go-datatrails-merklelog/massifs/storage"
	"github.com/veraison/go-cose"
)

// GetMassifContext retrieves the context for a given massif index from the provided ObjectReader.
//
// The function constructs a MassifContext, initializes its peak stack map, and returns it.
// Special handling is provided for the case where massif zero does not exist, returning a specific error.
// Returns the constructed MassifContext or an error if reading or initialization fails.
func GetMassifContext(ctx context.Context, reader ObjectReader, massifIndex uint32) (MassifContext, error) {

	// Allow for partial reads, its more efficient for some stores to read and cache the available start headers.
	data, _, err := reader.MassifData(massifIndex)

	if err != nil {
		if massifIndex == 0 && errors.Is(err, storage.ErrDoesNotExist) {
			return MassifContext{}, fmt.Errorf("%w: no object for massif zero", storage.ErrLogEmpty)
		}
		return MassifContext{}, err
	}

	if len(data) <= StartHeaderEnd {
		data, err = reader.MassifReadN(ctx, massifIndex, -1)
		if err != nil {
			return MassifContext{}, err
		}
	}

	mc := MassifContext{
		MassifData: MassifData{
			Data: data,
		},
		Start: MakeMassifStart(data),
	}

	// Note: log writers don't need this due to how AddLeaf works, but almost
	// everything else does. And this entry point is primarily aimed at general readers.
	// If we move to a fixed pre-allocation for the peak stack we can avoid this
	// all together.  so for now, we just maximize general caller convenience.
	// log builders that care can avoid this by using the reader directly
	err = mc.CreatePeakStackMap()
	if err != nil {
		return MassifContext{}, fmt.Errorf("failed to create peak stack map: %w", err)
	}

	return mc, nil
}

// GetMassifHeadContext retrieves the current head context of a massif from the provided ObjectReader.
// It obtains the latest massif index and then fetches the corresponding MassifContext.
// Returns an error if the head index cannot be retrieved or if fetching the MassifContext fails.
func GetMassifHeadContext(ctx context.Context, reader ObjectReader) (MassifContext, error) {
	massifIndex, err := reader.HeadIndex(ctx, storage.ObjectMassifData)
	if err != nil {
		return MassifContext{}, fmt.Errorf("failed to get head index: %w", err)
	}
	return GetMassifContext(ctx, reader, massifIndex)
}

// GetCheckpointData retrieves the checkpoint data for a given massif index using the provided ObjectReader.
//
// It first attempts to obtain the data via the CheckpointData method. If the
// data is not already available (i.e., nil), it then reads the data using the
// CheckpointRead method. Returns the checkpoint data as a byte slice or an
// error if retrieval fails.
//
// Parameters:
//   - ctx: The context for controlling cancellation and deadlines.
//   - reader: An ObjectReader used to access checkpoint data.
//   - massifIndex: The index of the massif for which to retrieve checkpoint data.
//
// Returns:
//   - []byte: The checkpoint data.
//   - error: An error if data retrieval fails.
func GetCheckpointData(ctx context.Context, reader ObjectReader, massifIndex uint32) ([]byte, error) {
	var err error
	var data []byte

	data, _, err = reader.CheckpointData(massifIndex)
	if err != nil {
		return nil, err
	}

	// is the data already available?
	if data == nil {
		data, err = reader.CheckpointRead(ctx, massifIndex)
		if err != nil {
			return nil, err
		}
	}
	return data, nil
}

// GetMassifData retrieves the data for a specified massif index from the provided ObjectReader.
//
// It first attempts to obtain the data from the native cache. If the data is
// incomplete (i.e., only the start header is present), it reads the full massif
// data using MassifReadN. The function returns the complete massif data as a
// byte slice, or an error if the data could not be retrieved.
//
// Parameters:
//   - ctx: The context for controlling cancellation and timeouts.
//   - reader: An ObjectReader used to access massif data.
//   - massifIndex: The index of the massif to retrieve.
//
// Returns:
//   - []byte: The complete massif data.
//   - error: An error if the data could not be retrieved.
func GetMassifData(ctx context.Context, reader ObjectReader, massifIndex uint32) ([]byte, error) {

	// check the native cache first, if a HeadIndex call was used, the native data has not been read.
	// If the start header was read, we need the rest of the data now.
	data, _, err := reader.MassifData(massifIndex)
	if err != nil {
		return nil, err
	}

	if len(data) <= StartHeaderEnd {
		data, err = reader.MassifReadN(ctx, massifIndex, -1)
		if err != nil {
			return nil, err
		}
	}

	return data, nil
}

// GetMassifStart retrieves the start header information for a given massif index.
//
// It first attempts to obtain the massif data using the provided
// ObjectReader.  If the data is not available, it reads the required number
// of bytes to cover the start header.  Returns a MassifStart struct populated
// from the data, or an error if the data is unavailable or incomplete.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts.
//   - reader: An ObjectReader used to access massif data.
//   - massifIndex: The index of the massif to retrieve.
//
// Returns:
//   - MassifStart: The parsed start header information.
//   - error: An error if the data could not be retrieved or is too short.
func GetMassifStart(ctx context.Context, reader ObjectReader, massifIndex uint32) (MassifStart, error) {
	var err error
	var data []byte
	var start MassifStart

	data, _, err = reader.MassifData(massifIndex)
	if err != nil {
		return MassifStart{}, err
	}

	if data == nil {
		data, err = reader.MassifReadN(ctx, massifIndex, StartHeaderEnd)
		if err != nil {
			return MassifStart{}, err
		}
	} // if data is not nil we *at least* have the start header

	if len(data) < StartHeaderEnd {
		return MassifStart{}, fmt.Errorf("massif data too short to contain start header")
	}

	start = MakeMassifStart(data)

	return start, nil
}

// GetCheckpoint retrieves and decodes a checkpoint for the specified massif index.
//
// It reads the checkpoint data using the provided ObjectReader, decodes it
// using the given CBORCodec, and returns a Checkpoint containing the signed
// message and unverified MMR state.  Returns an error if the data cannot be
// retrieved or decoded.
func GetCheckpoint(
	ctx context.Context, reader ObjectReader, codec commoncbor.CBORCodec, massifIndex uint32) (Checkpoint, error) {

	data, err := GetCheckpointData(ctx, reader, massifIndex)
	if err != nil {
		return Checkpoint{}, err
	}

	msg, unverifiedState, err := DecodeSignedRoot(codec, data)
	if err != nil {
		return Checkpoint{}, err
	}

	checkpt := Checkpoint{
		Sign1Message: *msg,
		MMRState:     unverifiedState,
	}
	return checkpt, nil
}

// GetContextVerified retrieves and verifies a massif context using the provided reader, CBOR codec, and COSE verifier.

// It applies any additional verification options supplied via opts. If a
// checkpoint is not provided in the options, it fetches the checkpoint for the
// specified massif index. The function returns a VerifiedContext if
// verification succeeds, or an error if any step fails.
//
// Parameters:
//   - ctx: The context for controlling cancellation and deadlines.
//   - reader: An ObjectReader used to access massif data.
//   - codec: The CBOR codec for decoding data.
//   - verifier: The COSE verifier for cryptographic verification.
//   - massifIndex: The index of the massif to verify.
//   - opts: Optional verification options.
//
// Returns:
//   - *VerifiedContext: The verified massif context.
//   - error: An error if retrieval or verification fails.
func GetContextVerified(
	ctx context.Context, reader ObjectReader,
	codec *commoncbor.CBORCodec,
	verifier cose.Verifier,
	massifIndex uint32, opts ...Option) (*VerifiedContext, error) {
	verifyOpts := &VerifyOptions{
		CBORCodec:    codec,
		COSEVerifier: verifier,
	}

	// Apply provided options
	for _, opt := range opts {
		opt(verifyOpts)
	}

	// Get the basic massif context
	mc, err := GetMassifContext(ctx, reader, massifIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to get massif context: %w", err)
	}

	// Get checkpoint if not provided in options
	if verifyOpts.Check == nil {
		check, err := GetCheckpoint(ctx, reader, *verifyOpts.CBORCodec, massifIndex)
		if err != nil {
			return nil, fmt.Errorf("failed to get checkpoint for verification: %w", err)
		}
		verifyOpts.Check = &check
	}

	return mc.VerifyContext(ctx, *verifyOpts)
}
