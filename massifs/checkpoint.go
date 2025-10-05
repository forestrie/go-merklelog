package massifs

import (
	"errors"

	"github.com/forestrie/go-merklelog/massifs/cose"
)

var ErrLogContextNotRead = errors.New("attempted to use lastContext before it was read")

type Checkpoint struct {
	Sign1Message cose.CoseSign1Message
	MMRState     MMRState
}
