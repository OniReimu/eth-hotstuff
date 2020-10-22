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
	"testing"

	"go.dedis.ch/kyber/v3/pairing/bn256"
)

func TestHandleSendPub(t *testing.T) {
	N := uint64(4)
	F := uint64(1)

	testCases := []struct {
		system      *testSystem
		expectedErr error
	}{
		{
			// normal case
			func() *testSystem {
				sys := NewTestSystemWithBackend(N, F)

				for _, backend := range sys.backends {
					c := backend.engine.(*core)
					c.valSet = backend.peers
				}
				return sys
			}(),
			nil,
		},
	}

OUTER:
	for _, test := range testCases {
		test.system.Run(false)
		v0 := test.system.backends[0]
		r0 := v0.engine.(*core)

		suite := bn256.NewSuite()

		for i, v := range test.system.backends {
			v.SetAggInfo(true, suite)
			validator := r0.valSet.GetByIndex(uint64(i))
			pubByte, err := v.aggregatedPub.MarshalBinary()
			if err != nil {
				t.Errorf("error mismatch: have %v, want nil", err)
			}
			if err := r0.handleSendPub(&message{
				Code:    msgSendPub,
				Msg:     pubByte,
				Address: validator.Address(),
			}, validator); err != nil {
				if err != test.expectedErr {
					t.Errorf("error mismatch: have %v, want %v", err, test.expectedErr)
				}
				continue OUTER
			}
		}

		// prepared is normal case
		if r0.state != StateSendPub {
			// There are not enough PREPARE messages in core
			if r0.state != StateAcceptRequest {
				t.Errorf("state mismatch: have %v, want %v", r0.state, StateAcceptRequest)
			}
			continue
		}
	}
}
