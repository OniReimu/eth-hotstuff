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

package core

import (
	"bytes"
	"fmt"
	"io"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

type CoreEngine interface {
	Start() error
	Stop() error

	IsSpeaker() bool

	// verify if a hash is the same as the proposed block in the current pending request
	//
	// this is useful when the engine is currently the speaker
	//
	// pending request is populated right at the first pre-request stage so this would give us the earliest verification
	// to avoid any race condition of coming propagated blocks
	IsCurrentProposal(blockHash common.Hash) bool

	SetAddressAndLogger(addr common.Address)

	CurrentRoundstate() *roundState
}

type State uint64

const (
	StateSendPub State = iota
	StateAcceptRequest
	StateAnnounced
	StateResponsed
	// StateCommitted
)

func (s State) String() string {
	if s == StateSendPub {
		return "Broadcasting Pub"
	} else if s == StateAcceptRequest {
		return "Accept request"
	} else if s == StateAnnounced {
		return "Announced"
	} else if s == StateResponsed {
		return "Responsed"
	} else {
		return "Unknown"
	}
}

// Cmp compares s and y and returns:
//   -1 if s is the previous state of y
//    0 if s and y are the same state
//   +1 if s is the next state of y
func (s State) Cmp(y State) int {
	if uint64(s) < uint64(y) {
		return -1
	}
	if uint64(s) > uint64(y) {
		return 1
	}
	return 0
}

const (
	msgSendPub uint64 = iota
	msgAnnounce
	msgResponse
	msgRoundChange
)

type message struct {
	Code      uint64
	Msg       []byte
	Address   common.Address
	Signature []byte
	// Pub of the aggregated signature
	AggPub  []byte
	AggSign []byte
}

// ==============================================
//
// define the functions that needs to be provided for rlp Encoder/Decoder.

// EncodeRLP serializes m into the Ethereum RLP format.
func (m *message) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, []interface{}{m.Code, m.Msg, m.Address, m.Signature, m.AggPub, m.AggSign})
}

// DecodeRLP implements rlp.Decoder, and load the consensus fields from a RLP stream.
func (m *message) DecodeRLP(s *rlp.Stream) error {
	var msg struct {
		Code      uint64
		Msg       []byte
		Address   common.Address
		Signature []byte
		AggPub    []byte
		AggSign   []byte
	}

	if err := s.Decode(&msg); err != nil {
		return err
	}
	m.Code, m.Msg, m.Address, m.Signature, m.AggPub, m.AggSign = msg.Code, msg.Msg, msg.Address, msg.Signature, msg.AggPub, msg.AggSign
	return nil
}

// ==============================================
//
// define the functions that needs to be provided for core.

func (m *message) FromPayload(b []byte, validateFn func([]byte, []byte) (common.Address, error)) error {
	// Decode message
	err := rlp.DecodeBytes(b, &m)
	if err != nil {
		return err
	}

	// Validate message (on a message without Signature)
	if validateFn != nil {
		var payload []byte
		payload, err = m.PayloadNoSig()
		if err != nil {
			return err
		}

		signerAdd, err := validateFn(payload, m.Signature)
		if err != nil {
			return err
		}
		if !bytes.Equal(signerAdd.Bytes(), m.Address.Bytes()) {
			return errInvalidSigner
		}
	}
	return nil
}

func (m *message) Payload() ([]byte, error) {
	return rlp.EncodeToBytes(m)
}

func (m *message) PayloadNoAddrNoAggNoSig() ([]byte, error) {
	return rlp.EncodeToBytes(&message{
		Code:      m.Code,
		Msg:       m.Msg,
		Address:   common.Address{},
		Signature: []byte{},
		AggPub:    []byte{},
		AggSign:   []byte{},
	})
}

func (m *message) PayloadNoSig() ([]byte, error) {
	return rlp.EncodeToBytes(&message{
		Code:      m.Code,
		Msg:       m.Msg,
		Address:   m.Address,
		Signature: []byte{},
		AggPub:    m.AggPub,
		AggSign:   m.AggSign,
	})
}

func (m *message) Decode(val interface{}) error {
	return rlp.DecodeBytes(m.Msg, val)
}

func (m *message) String() string {
	return fmt.Sprintf("{Code: %v, Address: %v}", m.Code, m.Address.String())
}

// ==============================================
//
// helper functions

func Encode(val interface{}) ([]byte, error) {
	return rlp.EncodeToBytes(val)
}
