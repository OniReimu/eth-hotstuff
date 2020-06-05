// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package types

import (
	"errors"
	"io"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	// "go.dedis.ch/kyber/v3/sign"
)

var (
	// HotStuffDigest represents a hash of "The scalable HotStuff"
	// to identify whether the block is from HotStuff consensus engine
	HotStuffDigest = common.HexToHash("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")

	// (Genesis): 32B+initialSigners+65B
	// (Non-genesis): 32B+SpeakerAddr+Mask+AggregatedKey+AggregatedSig+65B
	HotStuffExtraVanity = crypto.DigestLength    // Fixed number of extra-data bytes reserved for validator vanity
	HotStuffExtraSeal   = crypto.SignatureLength // Fixed number of extra-data bytes reserved for validator seal
	HotStuffExtraAggSig = 1024 * 10              // TODO, need to adjust --saber

	// ErrInvalidHotStuffHeaderExtra is returned if the length of extra-data is less than 32 bytes
	ErrInvalidHotStuffHeaderExtra = errors.New("invalid hotstuff header extra-data")
)

type HotStuffExtra struct {
	SpeakerAddr common.Address

	Validators []common.Address // This only exists in Genesis as it can be too long for every block

	Mask          []byte
	AggregatedKey []byte
	AggregatedSig []byte

	Seal []byte
}

// EncodeRLP serializes h into the Ethereum RLP format.
func (h *HotStuffExtra) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, []interface{}{
		h.SpeakerAddr,
		h.Validators,
		h.Mask,
		h.AggregatedKey,
		h.AggregatedSig,
		h.Seal,
	})
}

// DecodeRLP implements rlp.Decoder, and load the hotstuff fields from a RLP stream.
func (h *HotStuffExtra) DecodeRLP(s *rlp.Stream) error {
	var hotStuffExtra struct {
		SpeakerAddr   common.Address
		Validators    []common.Address
		Mask          []byte
		AggregatedKey []byte
		AggregatedSig []byte
		Seal          []byte
	}
	if err := s.Decode(&hotStuffExtra); err != nil {
		return err
	}
	h.SpeakerAddr, h.Validators, h.Mask, h.AggregatedKey, h.AggregatedSig, h.Seal = hotStuffExtra.SpeakerAddr, hotStuffExtra.Validators, hotStuffExtra.Mask, hotStuffExtra.AggregatedKey, hotStuffExtra.AggregatedSig, hotStuffExtra.Seal
	return nil
}

// ExtractIstanbulExtra extracts all values of the HotStuffExtra from the header. It returns an
// error if the length of the given extra-data is less than 32 bytes or the extra-data can not
// be decoded.
func ExtractHotStuffExtra(h *Header) (*HotStuffExtra, error) {
	if len(h.Extra) < HotStuffExtraVanity {
		return nil, ErrInvalidHotStuffHeaderExtra
	}

	var hotStuffExtra *HotStuffExtra
	err := rlp.DecodeBytes(h.Extra[HotStuffExtraVanity:], &hotStuffExtra)
	if err != nil {
		return nil, err
	}
	return hotStuffExtra, nil
}

// HotStuffFilteredHeader returns a filtered header which some information (like seal, validators set)
// are clean to fulfill the HotStuff hash rules. It returns nil if the extra-data cannot be
// decoded/encoded by rlp.
func HotStuffFilteredHeader(h *Header, keepSeal bool) *Header {
	newHeader := CopyHeader(h)
	hotStuffExtra, err := ExtractHotStuffExtra(newHeader)
	if err != nil {
		return nil
	}

	if !keepSeal {
		hotStuffExtra.Seal = []byte{}
	}

	payload, err := rlp.EncodeToBytes(&hotStuffExtra)
	if err != nil {
		return nil
	}

	newHeader.Extra = append(newHeader.Extra[:HotStuffExtraVanity], payload...)

	return newHeader
}
