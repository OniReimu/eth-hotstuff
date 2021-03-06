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
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/hotstuff"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"gopkg.in/karalabe/cookiejar.v2/collections/prque"
)

func TestCheckMessage(t *testing.T) {
	c := &core{
		state: StateAcceptRequest,
		current: newRoundState(&hotstuff.View{
			Height: big.NewInt(2),
			Round:  big.NewInt(0),
		}, newTestValidatorSet(4), nil, nil, nil),
	}

	// invalid view format
	err := c.checkMessage(msgAnnounce, nil)
	if err != errInvalidMessage {
		t.Errorf("error mismatch: have %v, want %v", err, errInvalidMessage)
	}

	testStates := []State{StateSendPub, StateAcceptRequest, StateAnnounced, StateResponsed}
	testCode := []uint64{msgSendPub, msgAnnounce, msgResponse, msgRoundChange}

	// future height with the current height
	v := &hotstuff.View{
		Height: big.NewInt(2),
		Round:  big.NewInt(0),
	}
	for i := 0; i < len(testStates); i++ {
		c.state = testStates[i]
		for j := 0; j < len(testCode); j++ {
			err := c.checkMessage(testCode[j], v)
			if err != errFutureMessage {
				t.Errorf("error mismatch: have %v, want %v", err, errFutureMessage)
			}
		}
	}
	// future height with the higher height
	v = &hotstuff.View{
		Height: big.NewInt(3),
		Round:  big.NewInt(0),
	}
	for i := 0; i < len(testStates); i++ {
		c.state = testStates[i]
		for j := 0; j < len(testCode); j++ {
			err := c.checkMessage(testCode[j], v)
			if err != errFutureMessage {
				t.Errorf("error mismatch: have %v, want %v", err, errFutureMessage)
			}
		}
	}

	// future round
	v = &hotstuff.View{
		Height: big.NewInt(2),
		Round:  big.NewInt(1),
	}
	for i := 0; i < len(testStates); i++ {
		c.state = testStates[i]
		for j := 0; j < len(testCode); j++ {
			err := c.checkMessage(testCode[j], v)
			if testCode[j] == msgRoundChange {
				if err != nil {
					t.Errorf("error mismatch: have %v, want nil", err)
				}
			} else if err != errFutureMessage {
				t.Errorf("error mismatch: have %v, want %v", err, errFutureMessage)
			}
		}
	}

	// current view but waiting for round change
	v = &hotstuff.View{
		Height: big.NewInt(1),
		Round:  big.NewInt(0),
	}
	c.waitingForRoundChange = true
	for i := 0; i < len(testStates); i++ {
		c.state = testStates[i]
		for j := 0; j < len(testCode); j++ {
			err := c.checkMessage(testCode[j], v)
			if testCode[j] == msgRoundChange {
				if err != nil {
					t.Errorf("error mismatch: have %v, want nil", err)
				}
			} else if err != errFutureMessage {
				t.Errorf("error mismatch: have %v, want %v", err, errFutureMessage)
			}
		}
	}
	c.waitingForRoundChange = false

	v = c.currentView()
	// current view, state = StateSendPub
	c.state = StateSendPub
	for i := 0; i < len(testCode); i++ {
		err = c.checkMessage(testCode[i], v)
		if testCode[i] > msgSendPub {
			if err != errInsufficientPub {
				t.Errorf("error mismatch: have %v, want %v", err, errInsufficientPub)
			}
		}
	}
	// current view, state = StateAcceptRequest
	c.state = StateAcceptRequest
	for i := 0; i < len(testCode); i++ {
		err = c.checkMessage(testCode[i], v)
		if testCode[i] == msgRoundChange {
			if err != nil {
				t.Errorf("error mismatch: have %v, want nil", err)
			}
		} else if testCode[i] == msgAnnounce {
			if err != nil {
				t.Errorf("error mismatch: have %v, want nil", err)
			}
		} else {
			if err != errFutureMessage {
				t.Errorf("error mismatch: have %v, want %v", err, errFutureMessage)
			}
		}
	}

	// current view, state = StateAnnounced
	c.state = StateAnnounced
	for i := 0; i < len(testCode); i++ {
		err = c.checkMessage(testCode[i], v)
		if testCode[i] == msgRoundChange {
			if err != nil {
				t.Errorf("error mismatch: have %v, want nil", err)
			}
		} else if err != nil {
			t.Errorf("error mismatch: have %v, want nil", err)
		}
	}

	// current view, state = StateResponsed
	c.state = StateResponsed
	for i := 0; i < len(testCode); i++ {
		err = c.checkMessage(testCode[i], v)
		if testCode[i] == msgRoundChange {
			if err != nil {
				t.Errorf("error mismatch: have %v, want nil", err)
			}
		} else if err != nil {
			t.Errorf("error mismatch: have %v, want nil", err)
		}
	}

}

func TestStoreBacklog(t *testing.T) {
	c := &core{
		logger:     log.New("backend", "test", "id", 0),
		valSet:     newTestValidatorSet(1),
		backlogs:   make(map[common.Address]*prque.Prque),
		backlogsMu: new(sync.Mutex),
	}
	v := &hotstuff.View{
		Round:  big.NewInt(10),
		Height: big.NewInt(10),
	}
	p := c.valSet.GetByIndex(0)
	// push announce msg
	announce := &hotstuff.Announce{
		View:     v,
		Proposal: makeBlock(1),
	}
	announcePayload, _ := Encode(announce)
	m := &message{
		Code: msgAnnounce,
		Msg:  announcePayload,
	}
	c.storeBacklog(m, p)
	msg := c.backlogs[p.Address()].PopItem()
	if !reflect.DeepEqual(msg, m) {
		t.Errorf("message mismatch: have %v, want %v", msg, m)
	}

	// push response msg
	subject := &hotstuff.Subject{
		View:   v,
		Digest: common.StringToHash("1234567890"),
	}
	subjectPayload, _ := Encode(subject)

	// push response msg
	m = &message{
		Code: msgResponse,
		Msg:  subjectPayload,
	}
	c.storeBacklog(m, p)
	msg = c.backlogs[p.Address()].PopItem()
	if !reflect.DeepEqual(msg, m) {
		t.Errorf("message mismatch: have %v, want %v", msg, m)
	}

	// push roundChange msg
	m = &message{
		Code: msgRoundChange,
		Msg:  subjectPayload,
	}
	c.storeBacklog(m, p)
	msg = c.backlogs[p.Address()].PopItem()
	if !reflect.DeepEqual(msg, m) {
		t.Errorf("message mismatch: have %v, want %v", msg, m)
	}
}

func TestProcessFutureBacklog(t *testing.T) {
	backend := &testSystemBackend{
		events: new(event.TypeMux),
	}
	c := &core{
		logger:     log.New("backend", "test", "id", 0),
		valSet:     newTestValidatorSet(1),
		backlogs:   make(map[common.Address]*prque.Prque),
		backlogsMu: new(sync.Mutex),
		backend:    backend,
		current: newRoundState(&hotstuff.View{
			Height: big.NewInt(1),
			Round:  big.NewInt(0),
		}, newTestValidatorSet(4), nil, nil, nil),
		state: StateAcceptRequest,
	}
	c.subscribeEvents()
	defer c.unsubscribeEvents()

	v := &hotstuff.View{
		Round:  big.NewInt(10),
		Height: big.NewInt(10),
	}
	p := c.valSet.GetByIndex(0)
	// push a future msg
	subject := &hotstuff.Subject{
		View:   v,
		Digest: common.StringToHash("1234567890"),
	}
	subjectPayload, _ := Encode(subject)
	m := &message{
		Code: msgResponse,
		Msg:  subjectPayload,
	}
	c.storeBacklog(m, p)
	c.processBacklog()

	const timeoutDura = 2 * time.Second
	timeout := time.NewTimer(timeoutDura)
	select {
	case e, ok := <-c.events.Chan():
		if !ok {
			return
		}
		t.Errorf("unexpected events comes: %v", e)
	case <-timeout.C:
		// success
	}
}

func TestProcessBacklog(t *testing.T) {
	v := &hotstuff.View{
		Round:  big.NewInt(0),
		Height: big.NewInt(1),
	}
	announce := &hotstuff.Announce{
		View:     v,
		Proposal: makeBlock(1),
	}
	announcePayload, _ := Encode(announce)

	subject := &hotstuff.Subject{
		View:   v,
		Digest: common.StringToHash("1234567890"),
	}
	subjectPayload, _ := Encode(subject)

	msgs := []*message{
		{
			Code: msgAnnounce,
			Msg:  announcePayload,
		},
		{
			Code: msgResponse,
			Msg:  subjectPayload,
		},
		{
			Code: msgRoundChange,
			Msg:  subjectPayload,
		},
	}
	for i := 0; i < len(msgs); i++ {
		testProcessBacklog(t, msgs[i])
	}
}

func testProcessBacklog(t *testing.T, msg *message) {
	vset := newTestValidatorSet(1)
	backend := &testSystemBackend{
		events: new(event.TypeMux),
		peers:  vset,
	}
	c := &core{
		logger:     log.New("backend", "test", "id", 0),
		backlogs:   make(map[common.Address]*prque.Prque),
		backlogsMu: new(sync.Mutex),
		valSet:     vset,
		backend:    backend,
		state:      State(msg.Code),
		current: newRoundState(&hotstuff.View{
			Height: big.NewInt(1),
			Round:  big.NewInt(0),
		}, newTestValidatorSet(4), nil, nil, nil),
	}
	c.subscribeEvents()
	defer c.unsubscribeEvents()

	c.storeBacklog(msg, vset.GetByIndex(0))
	c.processBacklog()

	const timeoutDura = 2 * time.Second
	timeout := time.NewTimer(timeoutDura)
	select {
	case ev := <-c.events.Chan():
		e, ok := ev.Data.(backlogEvent)
		if !ok {
			t.Errorf("unexpected event comes: %v", reflect.TypeOf(ev.Data))
		}
		if e.msg.Code != msg.Code {
			t.Errorf("message code mismatch: have %v, want %v", e.msg.Code, msg.Code)
		}
		// success
	case <-timeout.C:
		t.Error("unexpected timeout occurs")
	}
}
