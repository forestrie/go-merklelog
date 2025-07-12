package massifs

import (
	"errors"

	"github.com/datatrails/go-datatrails-common/cose"
)

var ErrLogContextNotRead = errors.New("attempted to use lastContext before it was read")

type Checkpoint struct {
	Sign1Message cose.CoseSign1Message
	MMRState     MMRState
}
