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

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/hotstuff"
)

func (c *core) sendResponse() {
	sub := c.current.Subject()
	c.broadcastResponse(sub)
}

func (c *core) sendResponseForOldBlock(view *hotstuff.View, digest common.Hash) {
	sub := &hotstuff.Subject{
		View:   view,
		Digest: digest,
	}
	c.broadcastResponse(sub)
}

func (c *core) broadcastResponse(sub *hotstuff.Subject) {
	logger := c.logger.New("state", c.state)

	encodedSubject, err := Encode(sub)
	if err != nil {
		logger.Error("Failed to encode", "subject", sub)
		return
	}
	// Only unicast to the current speaker
	c.broadcast(&message{
		Code: msgResponse,
		Msg:  encodedSubject,
	}, new(big.Int))
}

func (c *core) handleResponse(msg *message, src hotstuff.Validator) error {
	// Decode RESPONSE message
	var response *hotstuff.Subject
	err := msg.Decode(&response) // Only decode the msg.Msg
	if err != nil {
		return errFailedDecodeResponse
	}

	if err := c.checkMessage(msgResponse, response.View); err != nil {
		return err
	}

	if err := c.verifyResponse(response, src); err != nil {
		return err
	}

	c.acceptResponse(msg, src)

	// Commit the proposal once we have enough COMMIT messages and we are not in the Committed state.
	if c.current.Responses.Size() >= c.HotStuffSize() && c.state.Cmp(StateResponsed) < 0 {
		c.commit(false, new(big.Int))
	}

	return nil
}

// verifyResponse verifies if the received RESPONSE message is equivalent to our subject
func (c *core) verifyResponse(response *hotstuff.Subject, src hotstuff.Validator) error {
	logger := c.logger.New("from", src, "state", c.state)

	sub := c.current.Subject()
	if !reflect.DeepEqual(response, sub) {
		logger.Warn("Inconsistent subjects between RESPONSE and proposal", "expected", sub, "got", response)
		return errInconsistentSubject
	}

	return nil
}

func (c *core) acceptResponse(msg *message, src hotstuff.Validator) error {
	logger := c.logger.New("from", src, "state", c.state)

	// Add the RESPONSE message to current round state
	if err := c.current.Responses.Add(msg); err != nil {
		logger.Error("Failed to add RESPONSE message to round state", "msg", msg, "err", err)
		return err
	}

	return nil
}
