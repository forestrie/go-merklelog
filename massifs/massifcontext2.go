package massifs

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"maps"

	"github.com/datatrails/go-datatrails-common/logger"
	"github.com/datatrails/go-datatrails-merklelog/massifs/snowflakeid"
	"github.com/datatrails/go-datatrails-merklelog/mmr"
)

type MassifData struct {
	Data []byte
}

// MassifContext2 enables appending to the log
//
// The returned context is ready to accept new log entries.
//
// It is constructed entirely from data held in the massif blob and the blob
// immediately prior to it. Given the blob itself and only the 'tail nodes' from
// the preceding blob, it is possible to extend the log without knowledge of any
// further blobs.
//
// Massif blobs are defined by the _fixed_ number of _leaves_ they contain. We
// require that count to be a power of 2 and > 1. Given that, the number of
// nodes in a massif is just: n + n - 1. This follows from the binary nature of
// the tree.
//
// For example, with n leaves = 4 we get:  4 + 3 = 7
//
// This is the corresponding 'position' tree, with indication of how the MMR is
// 'chunked' into sub mountain ranges which we call 'massifs'
//
//	3        \   15   massif 1 \
//	          \/    \           \
//	 massif 0 /\     \           |    'alpine zone' is above the massif tree line
//	         /   \    \          |
//	2 ..... 7.....|....14........|...... 22 ..... Massif Root Index identifies the massif root
//	      /   \   |   /   \      |      /
//	1    3     6  | 10     13    |    18     21
//	    / \  /  \ | / \    /  \  |   /  \
//	   1   2 4   5| 8   9 11   12| 16   17 19 20
//	   0   1 3   4| 7   8 10   11| 15   16 18 19
//	   | massif 0 |  massif 1 .  | massif 2 ....>

//	1 << 3 - 1 << 2 = 8 - 4 = 4
//	1 << 4 - 1 << 3 = 16 - 8 = 8
//
// Massif Root Index                7-1 |       8+7-2  |              16 + 7-2
// Massif Last Leaf Index           5-1 |       8+5-2  |              16 + 5-2
//
// In order to require the power 2 property for the leaf count, we configure the
// massif size by its 'height'. Here, our 4 leaf tree has height 3 (level index 2)
//
// So typically instead of n + n -1, where n is the massif leaf count we instead do
//
// Massif Root Index      = (1 << h) - 2
// Massif Last Leaf Index = (1 << h) - h - 1
type MassifContext2 struct {
	MassifData

	// This context deals with the three different massif states:
	// 1. no blobs exist                                   -> creating = true
	// 2. a previous full blob exists, starting a new blob -> creating = true
	// 3. the most recent blob is not full                 -> creating = false
	Creating bool

	// Read from the first log entry in the blob. If Creating is true and Found
	// > 0, this is the Start header of the *previous* massif
	Start MassifStart

	// the following properties are for dealing with addition of the last leaf
	// in the massif they are only valid during the call to AddHashedLeaf which
	// appends the last leaf of the massif (other appends are guaranteed not to
	// reference nodes from earlier massif blobs)

	// Set to the peak stack index containing the *next* ancestor node that will
	// be needed. Initialized in AddLeafHash and only valid during that call
	nextAncestor int

	peakStackMap map[uint64]int
}

func (mc *MassifContext2) CopyPeakStack() map[uint64]int {
	if mc.peakStackMap == nil {
		return nil
	}
	m := map[uint64]int{}
	maps.Copy(m, mc.peakStackMap)
	return m
}

// CreatePeakStackMap generates a mapping of the peaks carried over from previous
// mmrs. This makes how the Get method accesses the peak stack be compatible
// with how GetRoot accesses the store. The default configuration works only for
// how leaf addition accesses the stack.
func (mc *MassifContext2) CreatePeakStackMap() error {
	mc.peakStackMap = PeakStackMap(mc.Start.MassifHeight, mc.Start.FirstIndex)
	if mc.peakStackMap == nil {
		return fmt.Errorf("invalid massif height or first index in start record")
	}
	return nil
}

func (mc *MassifContext2) StartNextMassif() error {
	// re-create Start for the new blob

	var err error

	// From here, mc.Start is logically the *previous* massif blob. And we start
	// the next massif based on the header of the previous.
	nextPeakStack, err := mc.NextPeakStack()
	if err != nil {
		return err
	}

	nextStart := NewMassifStart(
		// last id from *previous* blob is the initial value for this new blob.
		mc.Start.LastID,
		mc.Start.CommitmentEpoch, mc.Start.MassifHeight,
		// Note: at this point mc.Start and mc.Data refer to the *previous*
		// massif blob, so we can use it to compute the first index of the new
		// blob we are about to create.
		mc.Start.MassifIndex+1, mc.RangeCount())

	nextData, err := nextStart.MarshalBinary()
	if err != nil {
		return err
	}
	// NOTICE: At this point, provider implementations would read the new tag from the start header.

	// We pre-allocate zero filled data for the index. When the blob is
	// complete, the index will be fully populated. We store a trie key in it,
	// which provides for data recovery & additional proof types, and also the
	// minimal information we need to retain in order to update confirmation
	// status. The fixed increase on read size is expected to *improve*
	// performance: It turns out, according to the azure guidance, this should
	// actually make the blobs perform better.  If this causes the blob to be
	// greater than 256k, it will get placed in higher throughput storage from
	// the start.  See
	// https://learn.microsoft.com/en-us/azure/storage/blobs/storage-performance-checklist#partitioning
	nextData = append(nextData, mc.InitIndexData()...)

	// PeakStackLen is _not_ marshaled into the header, we can always compute it when needed
	nextStart.PeakStackLen = uint64(len(nextPeakStack) / ValueBytes)
	nextData = append(nextData, nextPeakStack...)

	// store the updated data and update the start configuration for the new stack
	mc.Start = nextStart
	mc.Data = nextData

	return nil
}

func (mc MassifContext2) InitIndexData() []byte {
	return make([]byte, IndexHeaderBytes+mc.IndexSize())
}

// NextPeakStack accepts the peak stack from the previous massif and returns the
// start data and stack for the current massif start details.
func (mc MassifContext2) NextPeakStack() ([]byte, error) {

	var err error

	// Remembering that the 'push' to the stack is always the last log entry so
	// we just leave it where it is naturally and gather it into the stack only
	// when we propagate the stack to the next massif here. And we need to do
	// that before we pop.
	peakStack, err := mc.GetAncestorPeakStack()
	if err != nil {
		return nil, err
	}
	stackLen := uint64(len(peakStack) / ValueBytes)
	if false {
		// Note: we don't need to compute the stack length here, but it serves as a
		// good early detector for data corruption issues.
		if stackLen != mmr.LeafMinusSpurSum(uint64(mc.Start.MassifIndex)) {
			return nil, fmt.Errorf("%w: computed stack length doesn't match accumulated stack length", ErrAncestorStackInvalid)
		}
	}

	pop := mmr.SpurHeightLeaf(uint64(mc.Start.MassifIndex))

	// do the stack pop, the append happens naturally when the last leaf is added
	// due to our always collecting it from the end of the log (via GetPeakStack
	// above)
	peakStack = peakStack[:(stackLen-pop)*ValueBytes]

	// Now we have popped the ancestors we are done with, we can push the last
	// value from the previous massif.
	peakStack = append(peakStack, mc.GetLastValue()...)
	return peakStack, nil
}

// GetPeakStack returns the ancestor peak stack plus the last value of the
// current massif. This method should only be called on a complete massif. The
// caller is responsible for ensuring this condition is met.
func (mc MassifContext2) GetPeakStack() ([]byte, error) {
	ancestors, err := mc.GetAncestorPeakStack()
	if err != nil {
		return nil, err
	}
	return append(ancestors, mc.GetLastValue()...), nil
}

// Get returns the value associated with the node at MMR index i
//
// Note that due to the structure of the MMR we are guaranteed that adding a
// node will only reference other nodes in the *current* massif, OR it will
// reference some subset of the roots of the previous massifs. The ancestor
// roots we need periodically reset due to the structure of the mmr. The are
// perfectly determined by the current mmr size. We maintain them in a stack and
// always carry the stack forward from blob to blob. The size of the stack we
// need is <= mmr height - massif height
//
// Similarly *proving* or *verifying* a node in the current massif benefits from
// the same property.
//
//	3        \   15   massif 1 \ . massif 2
//	          \/    \           \
//	 massif 0 /\     \           |
//	         /   \    \          |
//	2 ..... 7.....|....14........|...... 22 .....
//	      /   \   |   /   \      |      /
//	1    3     6  | 10     13    |    18     21
//	    / \  /  \ | / \    /  \  |   /  \
//	   1   2 4   5| 8   9 11   12| 16   17 19 20
//	   0   1 3   4| 7   8 10   11| 15   16 18 19
//	   | massif 0 |  massif 1 .  | massif 2 ....>
//
// This method satisfies the Get method of the MMR NodeAdder interface
func (mc *MassifContext2) Get(i uint64) ([]byte, error) {
	value, err := mc.get(i)
	// this would produce way too much logging in services, but it is very handy for integration tests
	if false && err == nil {
		logger.Sugar.Debugf("mc.get: i=%d, mi=%d, v=%x", i, mc.Start.MassifIndex, value)
	}
	return value, err
}

// GetTrieEntry gets the trie entry given the mmrIndex of its corresponding leaf node.
func (mc MassifContext2) GetTrieEntry(mmrIndex uint64) ([]byte, error) {

	// Note: mmrIndex identifies an arbitrary node, so LeafIndex is necessary
	trieIndex := mmr.LeafIndex(mmrIndex)

	massifTrieIndex, err := mc.GetMassifTrieIndex(trieIndex)
	if err != nil {
		return nil, err
	}

	return GetTrieEntry(mc.Data, mc.IndexStart(), massifTrieIndex), nil
}

// GetTrieKey gets the trie key given the mmrIndex of the trie entries corresponding leaf node.
func (mc MassifContext2) GetTrieKey(mmrIndex uint64) ([]byte, error) {

	// Note: mmrIndex identifies an arbitrary node, so LeafIndex is necessary
	trieIndex := mmr.LeafIndex(mmrIndex)

	massifTrieIndex, err := mc.GetMassifTrieIndex(trieIndex)
	if err != nil {
		return nil, err
	}

	return GetTrieKey(mc.Data, mc.IndexStart(), massifTrieIndex), nil
}

func (mc *MassifContext2) get(i uint64) ([]byte, error) {
	// Normal case, reference to a node included in the current massif
	if i >= mc.Start.FirstIndex {
		return IndexedLogValue(mc.Data[mc.LogStart():], i-mc.Start.FirstIndex), nil
	}

	// Ok, its a reference to a peak carried over from a previous massif or this is an error case

	if mc.Start.FirstIndex == 0 {
		return nil, fmt.Errorf("%w: the first massif has no ancestors", ErrGetIndexUnavailable)
	}

	peakStackIndex, err := mc.peakStackIndex(i)
	if err != nil {
		return nil, err
	}
	value, err := mc.GetStackedPeak(peakStackIndex)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid context, requesting %d", err, i)
	}
	if false {
		logger.Sugar.Debugf("mc.get(peak): i=%d, mi=%d, v=%x", i, mc.Start.MassifIndex, value)
	}

	return value, nil
}

func (mc *MassifContext2) GetStackedPeak(peakStackIndex int) ([]byte, error) {
	stackTop := mc.LogStart()
	stackStart := mc.PeakStackStart()
	if stackStart > stackTop {
		return nil, ErrAncestorStackInvalid
	}

	valueStart := stackStart + uint64(peakStackIndex)*ValueBytes
	valueEnd := valueStart + ValueBytes
	if valueEnd > stackTop {
		return nil, fmt.Errorf("%w: exceeded the data range of the ancestor peak stack", ErrAncestorStackInvalid)
	}

	return mc.Data[valueStart:valueEnd], nil
}

func (mc *MassifContext2) peakStackIndex(i uint64) (int, error) {
	if mc.peakStackMap != nil {
		peakIndex, ok := mc.peakStackMap[i]
		if !ok {
			return 0, fmt.Errorf("%w: %d is not in the peak map", ErrAncestorStackInvalid, i)
		}
		return peakIndex, nil
	}

	// Because the peakStackMap is relatively expensive to create, we only use
	// it for the confirmer. When adding nodes, we rely on the known structure
	// of the stack and the known order nodes will be asked for.  The ancestor
	// stack is maintained so that the nodes we need, when adding leaves, are
	// listed in the order they will be asked for. And we initialize
	// nextAncestor in AddLeafHash to the top of the stack
	if mc.nextAncestor < 0 {
		return 0, fmt.Errorf("%w: exceeded the data range of the ancestor peak stack, requesting %d", ErrAncestorStackInvalid, i)
	}
	next := mc.nextAncestor
	mc.nextAncestor--
	return next, nil
}

// Append adds the leaf value to the log and returns the MMR index of the _next_ node
// This method satisfies the Append method of the MMR NodeAdder interface
func (mc *MassifContext2) Append(value []byte) (uint64, error) {

	if len(value) != ValueBytes {
		return 0, ErrLogValueBadSize
	}

	fmt.Printf("mc.Append: node=%x, i=%d, mi=%d\n", value, mc.RangeCount()-1, mc.Start.MassifIndex)

	// XXX: TODO: ideally we would check for over flow here. But it is awkward
	// and log base 2 n to work out the actual limit of this context. If we want
	// that, we would capture it in GetCurrentContext The add leaf method
	// pre-flight checks on the highest leaf index which can be computed
	// directly at any time. Over flow after that check is only possible if our
	// basic mmr add is bust and that is extensively covered by unit tests.

	mc.Data = append(mc.Data, value...)
	return mc.RangeCount(), nil
}

// AddHashedLeaf adds the leaf value and corresponding trie data to the log and
// trie. On error, the current data buffer should be discarded entirely (not
// written back to storage)
//
// Params:
//   - extraBytes - extra bytes that are added to the trie value before idtimestamp. maximum 24 bytes.
//     any extra bytes above 24 bytes will be truncated.
//
// Returns the resulting size of the mmr if the leaf is adds successfully.
func (mc *MassifContext2) AddHashedLeaf(
	hasher hash.Hash,
	idTimestamp uint64,
	extraBytes []byte,
	logId []byte,
	appId []byte,
	value []byte,
) (uint64, error) {

	if len(value) != ValueBytes {
		return 0, ErrLogValueBadSize
	}

	trieKey := NewTrieKey(KeyTypeApplicationContent, logId, appId)
	if len(trieKey) != TrieKeyBytes {
		return 0, ErrIndexEntryBadSize
	}

	count := mc.Count()
	iLast := mc.LastLeafMMRIndex()

	if mc.Start.FirstIndex+count > iLast {
		return 0, ErrMassifFull
	}

	// If we are about to add the last leaf, initialize the index into the peak
	// stack. Each interior node added for the last leaf takes the 'next' item
	// from the stack.
	if mc.Start.FirstIndex+count == iLast {
		mc.nextAncestor = int(mc.Start.PeakStackLen) - 1
	}

	// Get the trie leaf index. The count prior to addition of the leaf is the
	// index of the leaf we are adding.
	nextLeafIndex := mc.MassifLeafCount()

	// Overwrite the pre-allocated index entry with the index data.
	SetTrieEntry(mc.Data, mc.IndexStart(), nextLeafIndex, idTimestamp, extraBytes, trieKey)

	// Save the last id added so that we can guarantee monotonicity (and hence uniqueness for the tenant)
	mc.setLastIdTimestamp(idTimestamp)

	// provider implementations based on object storage may, and typically
	// *should* set a tag on the storage object to make the lastid indexed.
	// And make appropriate optimistic concurrency arrangements.

	// Note: assume that the whole update is discarded on error, including the index update above.

	// Returns the new MMR size if the new leaf is added successfully
	return mmr.AddHashedLeaf(mc, hasher, value)
}

// CheckConsistency checks that the data in the massif is consistent with the provided state.
//
// This generates a consistency proof from the mmr index identified by the state
// size to the last mmr index present in the context. That proof is then
// verified as consistent with the accumulator provided in the base state.
//
// Returns:
//   - the latest accumulator on success
//   - an error otherwise (the returned accumulator is nil)
func (mc *MassifContext2) CheckConsistency(
	baseState MMRState) ([][]byte, error) {

	if baseState.Peaks == nil {
		return nil, ErrStateRootMissing
	}

	// Note: this can never be 0, because we always create a new massif with at least one node
	mmrSizeCurrent := mc.RangeCount()

	if mmrSizeCurrent < baseState.MMRSize {
		return nil, ErrStateSizeBeforeMassifStart
	}

	// If the size has not advanced return the previously signed state.
	if mmrSizeCurrent == baseState.MMRSize {
		// There are two cases of note, but we can treat them equivalently here
		// 1. The massif is complete
		// 2. There have been no further entries on an incomplete massif
		return nil, nil
	}

	ok, peaksB, err := mmr.CheckConsistency(
		mc, sha256.New(), baseState.MMRSize, mmrSizeCurrent, baseState.Peaks)
	if err != nil {
		return nil,
			fmt.Errorf("%w: proof verification error: err=%s, massif=%d",
				ErrConsistencyProofCheck,
				err.Error(), mc.Start.MassifIndex)
	}
	if !ok {
		return nil,
			fmt.Errorf("%w: proof verification check, massif=%d",
				ErrInconsistentState,
				mc.Start.MassifIndex)
	}

	return peaksB, nil
}

// setLastIdTimestamp must be called after A
func (mc *MassifContext2) setLastIdTimestamp(idTimestamp uint64) {
	mc.Start.LastID = idTimestamp
	// Note: must 'write through' to the data, so commit only has to put the
	// bytes and doesn't care about the details of the format and its maintenance
	binary.BigEndian.PutUint64(mc.Data[MassifStartKeyLastIDFirstByte:MassifStartKeyLastIDEnd], idTimestamp)
}

// GetLastIdTimestamp returns the idTimestamp of the last entry in the log
// Note that this reads directly from the massif start data
func (mc *MassifContext2) GetLastIdTimestamp() uint64 {
	idTimestamp := binary.BigEndian.Uint64(mc.Data[MassifStartKeyLastIDFirstByte:MassifStartKeyLastIDEnd])
	return idTimestamp
}

// GetAncestorPeakStack returns the stack of ancestor peaks accumulated and
// retained from previous massifs. These are all the nodes that will be (or
// were) referenced when adding the last leaf to the current massif. Note that
// when carrying this stack forward to the next massif header, the last leaf is
// considered to have been 'pushed' on the stack and should be copied forward as
// the new accumulated stack head.
func (mc MassifContext2) GetAncestorPeakStack() ([]byte, error) {

	peakStackStart := mc.PeakStackStart()
	logStart := mc.LogStart()
	if peakStackStart == logStart {
		return nil, nil
	}

	// It must be empty or have room for at least one item
	if peakStackStart+ValueBytes > logStart {
		return nil, fmt.Errorf("%w: peakStackEnd + entry size > logStart:  %d > %d", ErrAncestorStackInvalid, peakStackStart+ValueBytes, logStart)
	}

	// Must be properly aligned
	if (logStart-peakStackStart)%ValueBytes != 0 {
		return nil, fmt.Errorf("%w: size %% entry size=%d", ErrAncestorStackInvalid, (logStart-peakStackStart)%ValueBytes)
	}

	if mc.Data == nil {
		return nil, fmt.Errorf("%w: no data available", ErrAncestorStackInvalid)
	}

	return mc.Data[peakStackStart:logStart], nil
}

func (mc MassifContext2) LastCommitUnixMS(idTimestampEpoch uint8) (int64, error) {
	id := mc.GetLastIdTimestamp()
	return snowflakeid.IDUnixMilli(id, idTimestampEpoch)
}

// GetMassifLeafIndex returns the leafIndex into the whole log relative to the start of the massif leaf index.
func (mc MassifContext2) GetMassifLeafIndex(leafIndex uint64) (uint64, error) {

	// Note: FirstIndex is also the MMRSize at the end of the previous massif, so LeafCount is used.
	// similarly RangeCount (below) will always return a valid MMRSize
	firstLeafIndex := mmr.LeafCount(mc.Start.FirstIndex)
	if leafIndex < firstLeafIndex {
		return 0, fmt.Errorf("index %d: %w", leafIndex, ErrBeforeFirstLeaf)
	}
	leafEnd := mmr.LeafCount(mc.RangeCount())
	if leafIndex >= leafEnd {
		return 0, fmt.Errorf("index %d: %w", leafIndex, ErrLeafRange)
	}
	return leafIndex - firstLeafIndex, nil
}

// GetMassifTrieIndex returns the trieIndex into the whole log relative to the start of the massif trie index.
func (mc MassifContext2) GetMassifTrieIndex(trieIndex uint64) (uint64, error) {

	// trie index is equivalent to leaf index, so just get the leaf index
	return mc.GetMassifLeafIndex(trieIndex)
}

// GetTrieIdTimestamp returns the idTimestamp from the trieEntry, for the identified trie index.
func (mc MassifContext2) GetTrieIdTimestamp(trieIndex uint64) ([]byte, error) {
	return GetIdtimestamp(mc.Data, mc.IndexStart(), trieIndex), nil
}

// MassifLeafCount returns the number of leaves in the current blob (If you want
// the number of leaves in the entire mmr call mmr.LeafCount directly)
func (mc MassifContext2) MassifLeafCount() uint64 {

	// Get the count of leaves in the entire mmr, RangeCount always returns a valid MMRSize
	count := mmr.LeafCount(mc.RangeCount())
	// Subtract the number of leaves in the mmr defined by the end of the last
	// blob to get the count of leaves in the current blob. FirstIndex is the
	// valid MMRSize of the end of the preceding massif.
	return count - mmr.LeafCount(mc.Start.FirstIndex)
}

// TODO: deprecate/remove the use of these methods
func (mc MassifContext2) FixedHeaderEnd() uint64 {
	return FixedHeaderEnd()
}

func (mc MassifContext2) IndexHeaderStart() uint64 {
	return TrieHeaderStart()
}

// IndexHeaderEhd returns the end of the bytes reserved for the index header.
// Currently, nothing is stored in this.
// XXX: TODO: Consider removing the field all together
func (mc MassifContext2) IndexHeaderEnd() uint64 {
	return mc.IndexHeaderStart() + IndexHeaderBytes
}

// IndexStart returns the index of the first **byte** of index data.
func (mc MassifContext2) IndexStart() uint64 {
	return mc.IndexHeaderEnd()
}

func (mc MassifContext2) IndexLen() uint64 {
	return (1 << mc.Start.MassifHeight)
}

func (mc MassifContext2) IndexSize() uint64 {
	return mc.IndexLen() * TrieEntryBytes
}

// IndexEnd returns the byte index of the end of index data
func (mc MassifContext2) IndexEnd() uint64 {
	return mc.IndexStart() + TrieEntryBytes*(1<<mc.Start.MassifHeight)
}

func (mc MassifContext2) PeakStackStart() uint64 {
	return mc.IndexEnd()
}

func (mc MassifContext2) LogStart() uint64 {
	// Note that we calculate and store the peak stack length when we establish
	// the context. So we don't need (or want) to use the global helper.
	return mc.IndexEnd() + ValueBytes*mc.Start.PeakStackLen
}

func (mc MassifContext2) GetLastValue() []byte {
	if len(mc.Data) < ValueBytes {
		return nil
	}
	return mc.Data[len(mc.Data)-ValueBytes:]
}

// Count returns the number of log entries in the massif
func (mc MassifContext2) Count() uint64 {
	logStart := mc.LogStart()
	if logStart > uint64(len(mc.Data)) {
		return (uint64(len(mc.Data)) - logStart) / LogEntryBytes
	}
	return (uint64(len(mc.Data)) - logStart) / LogEntryBytes
}

// RangeCount returns the total number of log entries in the MMR up to and including this context
func (mc MassifContext2) RangeCount() uint64 {
	return mc.Start.FirstIndex + mc.Count()
}

// LastLeafMMRIndex returns the *MMR* index for the last leaf entry that can be
// added to the mmr. This is typically used to check if the last entry is being
// added.
func (mc MassifContext2) LastLeafMMRIndex() uint64 {
	return RangeLastLeafIndex(mc.Start.FirstIndex, mc.Start.MassifHeight)
}
