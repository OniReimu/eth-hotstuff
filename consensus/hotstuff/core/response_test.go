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
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/hotstuff"
	"github.com/ethereum/go-ethereum/consensus/hotstuff/validator"
	"github.com/ethereum/go-ethereum/crypto"

	"go.dedis.ch/kyber/v3/pairing/bn256"
)

func TestHandleCommit(t *testing.T) {
	N := uint64(4)
	F := uint64(1)

	proposal := newTestProposal()
	expectedSubject := &hotstuff.Subject{
		View: &hotstuff.View{
			Round:  big.NewInt(0),
			Height: proposal.Number(),
		},
		Digest: proposal.Hash(),
	}

	testCases := []struct {
		system      *testSystem
		expectedErr error
	}{
		{
			// normal case
			func() *testSystem {
				sys := NewTestSystemWithBackend(N, F)

				for i, backend := range sys.backends {
					c := backend.engine.(*core)
					c.valSet = backend.peers
					c.current = newTestRoundState(
						&hotstuff.View{
							Round:  big.NewInt(0),
							Height: big.NewInt(1),
						},
						c.valSet,
					)

					if i == 0 {
						// replica 0 is the speaker
						c.state = StateAnnounced
					}
				}
				return sys
			}(),
			nil,
		},
		{
			// future message
			func() *testSystem {
				sys := NewTestSystemWithBackend(N, F)

				for i, backend := range sys.backends {
					c := backend.engine.(*core)
					c.valSet = backend.peers
					if i == 0 {
						// replica 0 is the speaker
						c.current = newTestRoundState(
							expectedSubject.View,
							c.valSet,
						)
						c.state = StateAnnounced
					} else {
						c.current = newTestRoundState(
							&hotstuff.View{
								Round:  big.NewInt(2),
								Height: big.NewInt(3),
							},
							c.valSet,
						)
					}
				}
				return sys
			}(),
			errFutureMessage,
		},
		{
			// subject not match
			func() *testSystem {
				sys := NewTestSystemWithBackend(N, F)

				for i, backend := range sys.backends {
					c := backend.engine.(*core)
					c.valSet = backend.peers
					if i == 0 {
						// replica 0 is the speaker
						c.current = newTestRoundState(
							expectedSubject.View,
							c.valSet,
						)
						c.state = StateAnnounced
					} else {
						c.current = newTestRoundState(
							&hotstuff.View{
								Round:  big.NewInt(0),
								Height: big.NewInt(0),
							},
							c.valSet,
						)
					}
				}
				return sys
			}(),
			errOldMessage,
		},
		// TODO: double send message
	}

OUTER:
	for _, test := range testCases {
		test.system.Run(false)

		v0 := test.system.backends[0]
		r0 := v0.engine.(*core)

		suite := bn256.NewSuite()
		msgSet := make([]*message, 0, N)

		for i, v := range test.system.backends {

			v.SetAggInfo(true, suite)

			if i != 0 {
				msg, err := v.engine.(*core).getResponseMessage()
				if err != nil {
					t.Errorf("error mismatch: have %v, want nil", err)
				}
				msgSet = append(msgSet, msg)
			}

			validator := r0.valSet.GetByIndex(uint64(i))
			m, _ := Encode(v.engine.(*core).current.Subject())
			if err := r0.handleResponse(&message{
				Code:      msgResponse,
				Msg:       m,
				Address:   validator.Address(),
				Signature: []byte{},
				AggPub:    []byte{},
				AggSign:   []byte{},
			}, validator); err != nil {
				if err != test.expectedErr {
					t.Errorf("error mismatch: have %v, want %v", err, test.expectedErr)
				}
				continue OUTER
			}
		}

		for i, msg := range msgSet {
			if err := r0.handleResponse(msg, r0.valSet.GetByIndex(uint64(i))); err != nil {
				if err != test.expectedErr {
					t.Errorf("error mismatch: have %v, want %v", err, test.expectedErr)
				}
				continue OUTER
			}
		}

		if r0.state != StateResponsed {
			// There are not enough commit messages in core
			if r0.state != StateAnnounced {
				t.Errorf("state mismatch: have %v, want %v", r0.state, StateAnnounced)
			}
			if r0.current.Responses.Size() >= r0.HotStuffSize() {
				t.Errorf("the size of response messages should be less than %v", r0.HotStuffSize())
			}
			continue
		}

		// core should have N-(N-1)/3 honest members
		if r0.current.Responses.Size() < r0.HotStuffSize() {
			t.Errorf("the size of response messages should be larger than N-(N-1)/3 honest members: size %v", r0.HotStuffSize())
		}

		// There would only be one element in committedMsgs because only collecting >= HotStuffSize of Response will trigger Commit and append
		// mask := v0.committedMsgs[0].mask
		aggSig := v0.committedMsgs[0].aggSig
		aggKey := v0.committedMsgs[0].aggKey

		if err := v0.verifySig(false, aggKey, aggSig); err != nil {
			t.Errorf("error mismatch: have %v, want nil", err)
		}
	}
}

// round is not checked for now
func TestVerifyCommit(t *testing.T) {
	// for log purpose
	privateKey, _ := crypto.GenerateKey()
	peer := validator.New(getPublicKeyAddress(privateKey))
	valSet := validator.NewSet([]common.Address{peer.Address()}, hotstuff.RoundRobin)

	sys := NewTestSystemWithBackend(uint64(1), uint64(0))

	testCases := []struct {
		expected   error
		commit     *hotstuff.Subject
		roundState *roundState
	}{
		{
			// normal case
			expected: nil,
			commit: &hotstuff.Subject{
				View:   &hotstuff.View{Round: big.NewInt(0), Height: big.NewInt(0)},
				Digest: newTestProposal().Hash(),
			},
			roundState: newTestRoundState(
				&hotstuff.View{Round: big.NewInt(0), Height: big.NewInt(0)},
				valSet,
			),
		},
		{
			// old message
			expected: errInconsistentSubject,
			commit: &hotstuff.Subject{
				View:   &hotstuff.View{Round: big.NewInt(0), Height: big.NewInt(0)},
				Digest: newTestProposal().Hash(),
			},
			roundState: newTestRoundState(
				&hotstuff.View{Round: big.NewInt(1), Height: big.NewInt(1)},
				valSet,
			),
		},
		{
			// different digest
			expected: errInconsistentSubject,
			commit: &hotstuff.Subject{
				View:   &hotstuff.View{Round: big.NewInt(0), Height: big.NewInt(0)},
				Digest: common.StringToHash("1234567890"),
			},
			roundState: newTestRoundState(
				&hotstuff.View{Round: big.NewInt(1), Height: big.NewInt(1)},
				valSet,
			),
		},
		{
			// malicious package(lack of height)
			expected: errInconsistentSubject,
			commit: &hotstuff.Subject{
				View:   &hotstuff.View{Round: big.NewInt(0), Height: nil},
				Digest: newTestProposal().Hash(),
			},
			roundState: newTestRoundState(
				&hotstuff.View{Round: big.NewInt(1), Height: big.NewInt(1)},
				valSet,
			),
		},
		{
			// wrong announce message with same height but different round
			expected: errInconsistentSubject,
			commit: &hotstuff.Subject{
				View:   &hotstuff.View{Round: big.NewInt(1), Height: big.NewInt(0)},
				Digest: newTestProposal().Hash(),
			},
			roundState: newTestRoundState(
				&hotstuff.View{Round: big.NewInt(0), Height: big.NewInt(0)},
				valSet,
			),
		},
		{
			// wrong announce message with same round but different height
			expected: errInconsistentSubject,
			commit: &hotstuff.Subject{
				View:   &hotstuff.View{Round: big.NewInt(0), Height: big.NewInt(1)},
				Digest: newTestProposal().Hash(),
			},
			roundState: newTestRoundState(
				&hotstuff.View{Round: big.NewInt(0), Height: big.NewInt(0)},
				valSet,
			),
		},
	}
	for i, test := range testCases {
		c := sys.backends[0].engine.(*core)
		c.current = test.roundState

		if err := c.verifyResponse(test.commit, peer); err != nil {
			if err != test.expected {
				t.Errorf("result %d: error mismatch: have %v, want %v", i, err, test.expected)
			}
		}
	}
}
