package urkle

import "bytes"

const (
	FrontierMagicV1        = "FNT1"
	FrontierVersionV1      = 1
	FrontierKeyBitsV1      = 64
	FrontierMaxDepth       = 64
	FrontierFrameBytes     = 8
	FrontierStateV1Bytes   = 32 + FrontierMaxDepth*FrontierFrameBytes
	frontierNoRefSentinel  = ^uint32(0)
	frontierHeaderBytesV1  = 32
	frontierFramesOffBytes = frontierHeaderBytesV1
)

type Frame struct {
	Bit  uint8
	Left Ref
}

// FrontierStateV1 is builder-only state required to resume append-only construction without scanning.
type FrontierStateV1 struct {
	LastKey  uint64
	Pending  Ref
	Next     Ref
	NextLeaf uint32
	Depth    uint8
	Frames   [FrontierMaxDepth]Frame
}

// EncodeFrontierV1 encodes a V1 frontier state into dst.
func EncodeFrontierV1(dst []byte, st FrontierStateV1) error {
	if len(dst) < FrontierStateV1Bytes {
		return ErrFrontierBadSize
	}

	copy(dst[0:4], []byte(FrontierMagicV1))
	dst[4] = FrontierVersionV1
	dst[5] = FrontierKeyBitsV1
	dst[6] = 0
	dst[7] = 0

	writeU64BE(dst[8:16], st.LastKey)

	p := uint32(st.Pending)
	if st.Pending == NoRef {
		p = frontierNoRefSentinel
	}
	writeU32BE(dst[16:20], p)
	writeU32BE(dst[20:24], uint32(st.Next))

	dst[24] = st.Depth
	dst[25] = 0
	dst[26] = 0
	dst[27] = 0
	writeU32BE(dst[28:32], st.NextLeaf)

	off := frontierFramesOffBytes
	for i := 0; i < FrontierMaxDepth; i++ {
		dst[off+0] = st.Frames[i].Bit
		dst[off+1] = 0
		dst[off+2] = 0
		dst[off+3] = 0
		writeU32BE(dst[off+4:off+8], uint32(st.Frames[i].Left))
		off += FrontierFrameBytes
	}

	return nil
}

// DecodeFrontierV1 decodes a V1 frontier state from src.
//
// ok=false indicates the frontier block is empty/uninitialized (all zeros).
func DecodeFrontierV1(src []byte) (st FrontierStateV1, ok bool, err error) {
	if len(src) < FrontierStateV1Bytes {
		return FrontierStateV1{}, false, ErrFrontierBadSize
	}
	if bytes.Equal(src[0:4], []byte{0, 0, 0, 0}) {
		return FrontierStateV1{}, false, nil
	}
	if string(src[0:4]) != FrontierMagicV1 {
		return FrontierStateV1{}, false, ErrFrontierBadMagic
	}
	if src[4] != FrontierVersionV1 {
		return FrontierStateV1{}, false, ErrFrontierBadVersion
	}
	// src[5] keybits

	st.LastKey = readU64BE(src[8:16])

	p := readU32BE(src[16:20])
	if p == frontierNoRefSentinel {
		st.Pending = NoRef
	} else {
		st.Pending = Ref(p)
	}
	st.Next = Ref(readU32BE(src[20:24]))

	st.Depth = src[24]
	st.NextLeaf = readU32BE(src[28:32])

	off := frontierFramesOffBytes
	for i := 0; i < FrontierMaxDepth; i++ {
		st.Frames[i].Bit = src[off+0]
		st.Frames[i].Left = Ref(readU32BE(src[off+4 : off+8]))
		off += FrontierFrameBytes
	}

	return st, true, nil
}
