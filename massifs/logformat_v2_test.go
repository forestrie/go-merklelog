package massifs

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMassifLogEntries_V2(t *testing.T) {
	massifHeight := uint8(3)

	base := PeakStackEnd(massifHeight) // header + index + fixed peak stack
	_, err := MassifLogEntries(int(base-1), massifHeight)
	assert.ErrorIs(t, err, ErrMassifDataLengthInvalid)

	for nodes := uint64(0); nodes < 32; nodes++ {
		dataLen := int(base + nodes*ValueBytes)
		got, err := MassifLogEntries(dataLen, massifHeight)
		assert.NoError(t, err)
		assert.Equal(t, nodes, got)
	}
}


