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
	"io"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/hotstuff"
	"github.com/ethereum/go-ethereum/rlp"
)

// newRoundState creates a new roundState instance with the given view and validatorSet
func newRoundState(view *hotstuff.View, validatorSet hotstuff.ValidatorSet, announce *hotstuff.Announce, pendingRequest *hotstuff.Request, hasBadProposal func(hash common.Hash) bool) *roundState {
	return &roundState{
		round:          view.Round,
		height:         view.Height,
		Announce:       announce,
		Responses:      newMessageSet(validatorSet),
		mu:             new(sync.RWMutex),
		pendingRequest: pendingRequest,
		hasBadProposal: hasBadProposal,
	}
}

// roundState stores the consensus state
type roundState struct {
	round          *big.Int
	height         *big.Int
	Announce       *hotstuff.Announce
	Responses      *messageSet
	pendingRequest *hotstuff.Request

	mu             *sync.RWMutex
	hasBadProposal func(hash common.Hash) bool
}

func (s *roundState) Message(roundChange bool) *message {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !roundChange {
		if s.Announce == nil || s.Responses == nil {
			return nil
		}
		sub := s.Subject()
		encodedSubject, err := Encode(sub)
		if err != nil {
			return nil
		}

		return &message{
			Code: msgResponse,
			Msg:  encodedSubject,
		}
	} else {
		sub := s.Subject()
		sub.Digest = common.Hash{}
		encodedSubject, err := Encode(sub)
		if err != nil {
			return nil
		}
		// TODO: Do we need more verification here? --saber
		return &message{
			Code: msgRoundChange,
			Msg:  encodedSubject,
		}
	}
}

func (s *roundState) Subject() *hotstuff.Subject {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.Announce == nil {
		return nil
	}

	return &hotstuff.Subject{
		View: &hotstuff.View{
			Round:  new(big.Int).Set(s.round),
			Height: new(big.Int).Set(s.height),
		},
		Digest: s.Announce.Proposal.Hash(),
	}
}

func (s *roundState) SetAnnounce(announce *hotstuff.Announce) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Announce = announce
}

func (s *roundState) Proposal() hotstuff.Proposal {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.Announce != nil {
		return s.Announce.Proposal
	}

	return nil
}

func (s *roundState) SetRound(r *big.Int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.round = new(big.Int).Set(r)
}

func (s *roundState) Round() *big.Int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.round
}

func (s *roundState) SetHeight(height *big.Int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.height = height
}

func (s *roundState) Height() *big.Int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.height
}

// The DecodeRLP method should read one value from the given
// Stream. It is not forbidden to read less or more, but it might
// be confusing.
func (s *roundState) DecodeRLP(stream *rlp.Stream) error {
	var ss struct {
		Round          *big.Int
		Height         *big.Int
		Announce       *hotstuff.Announce
		Responses      *messageSet
		pendingRequest *hotstuff.Request
	}

	if err := stream.Decode(&ss); err != nil {
		return err
	}
	s.round = ss.Round
	s.height = ss.Height
	s.Announce = ss.Announce
	s.Responses = ss.Responses
	s.pendingRequest = ss.pendingRequest
	s.mu = new(sync.RWMutex)

	return nil
}

// EncodeRLP should write the RLP encoding of its receiver to w.
// If the implementation is a pointer method, it may also be
// called for nil pointers.
//
// Implementations should generate valid RLP. The data written is
// not verified at the moment, but a future version might. It is
// recommended to write only a single value but writing multiple
// values or no value at all is also permitted.
func (s *roundState) EncodeRLP(w io.Writer) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return rlp.Encode(w, []interface{}{
		s.round,
		s.height,
		s.Announce,
		s.Responses,
		s.pendingRequest,
	})
}
