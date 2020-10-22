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
)

// notice: the normal case have been tested in integration tests.
func TestHandleMsg(t *testing.T) {
	N := uint64(4)
	F := uint64(1)
	sys := NewTestSystemWithBackend(N, F)

	closer := sys.Run(true)
	defer closer()

	v0 := sys.backends[0]
	r0 := v0.engine.(*core)

	m, _ := Encode(&hotstuff.Subject{
		View: &hotstuff.View{
			Height: big.NewInt(0),
			Round:  big.NewInt(0),
		},
		Digest: common.StringToHash("1234567890"),
	})
	// with a matched payload. msgAnnounce should match with *hotstuff.Announce in normal case.
	msg := &message{
		Code:      msgAnnounce,
		Msg:       m,
		Address:   v0.Address(),
		Signature: []byte{},
		AggPub:    []byte{},
		AggSign:   []byte{},
	}

	_, val := v0.Validators(nil).GetByAddress(v0.Address())
	if err := r0.handleCheckedMsg(msg, val); err != errFailedDecodeAnnounce {
		t.Errorf("error mismatch: have %v, want %v", err, errFailedDecodeAnnounce)
	}

	m, _ = Encode(&hotstuff.Announce{
		View: &hotstuff.View{
			Height: big.NewInt(0),
			Round:  big.NewInt(0),
		},
		Proposal: makeBlock(1),
	})
	// with a unmatched payload. msgPrepare should match with *hotstuff.Subject in normal case.
	msg = &message{
		Code:      msgResponse,
		Msg:       m,
		Address:   v0.Address(),
		Signature: []byte{},
		AggPub:    []byte{},
		AggSign:   []byte{},
	}

	_, val = v0.Validators(nil).GetByAddress(v0.Address())
	if err := r0.handleCheckedMsg(msg, val); err != errFailedDecodeResponse {
		t.Errorf("error mismatch: have %v, want %v", err, errFailedDecodeResponse)
	}

	m, _ = Encode(&hotstuff.Announce{
		View: &hotstuff.View{
			Height: big.NewInt(0),
			Round:  big.NewInt(0),
		},
		Proposal: makeBlock(2),
	})
	// with a unmatched payload. istanbul.MsgCommit should match with *istanbul.Subject in normal case.
	msg = &message{
		Code:      msgSendPub,
		Msg:       m,
		Address:   v0.Address(),
		Signature: []byte{},
		AggPub:    []byte{},
		AggSign:   []byte{},
	}

	_, val = v0.Validators(nil).GetByAddress(v0.Address())
	if err := r0.handleCheckedMsg(msg, val); err != errFailedDecodeSendPub {
		t.Errorf("error mismatch: have %v, want %v", err, errFailedDecodeSendPub)
	}

	m, _ = Encode(&hotstuff.Announce{
		View: &hotstuff.View{
			Height: big.NewInt(0),
			Round:  big.NewInt(0),
		},
		Proposal: makeBlock(3),
	})
	// invalid message code. message code is not exists in list
	msg = &message{
		Code:      uint64(99),
		Msg:       m,
		Address:   v0.Address(),
		Signature: []byte{},
		AggPub:    []byte{},
		AggSign:   []byte{},
	}

	_, val = v0.Validators(nil).GetByAddress(v0.Address())
	if err := r0.handleCheckedMsg(msg, val); err == nil {
		t.Errorf("error mismatch: have %v, want nil", err)
	}

	// with malicious payload
	if err := r0.handleMsg([]byte{1}); err == nil {
		t.Errorf("error mismatch: have %v, want nil", err)
	}
}
