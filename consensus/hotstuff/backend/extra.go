// extra.go is responsible for manipulation of the extradata field.

package backend

import (
	"bytes"

	// "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
)

// prepareExtra returns a extra-data of the given header and validators
func (h *backend) prepareExtra(header *types.Header) ([]byte, error) {
	var buf bytes.Buffer

	// compensate the lack bytes if header.Extra is not enough HotStuffExtraVanity bytes.
	if len(header.Extra) < types.HotStuffExtraVanity {
		header.Extra = append(header.Extra, bytes.Repeat([]byte{0x00}, types.HotStuffExtraVanity-len(header.Extra))...)
	}
	buf.Write(header.Extra[:types.HotStuffExtraVanity])

	// Mask and AggregatedSig will be filled in afterwards
	hs := &types.HotStuffExtra{
		SpeakerAddr: h.Address(),
		Seal:        make([]byte, types.HotStuffExtraSeal),
	}

	payload, err := rlp.EncodeToBytes(&hs)
	if err != nil {
		return nil, err
	}

	return append(buf.Bytes(), payload...), nil
}
