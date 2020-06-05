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

	"github.com/ethereum/go-ethereum/consensus/hotstuff"
)

func (c *core) sendPub(payload []byte) {
	logger := c.logger.New("state", c.state)
	logger.Trace("Send AggPub")
	c.broadcast(&message{
		Code: msgSendPub,
		Msg:  payload,
	}, new(big.Int))
}

func (c *core) handleSendPub(msg *message, src hotstuff.Validator) error {
	result, err := c.acceptPub(msg, src)
	if err != nil {
		return err
	}
	if result >= c.valSet.Size() {
		c.setState(StateAcceptRequest)
		c.hasAggPub = true
		c.backend.AggPubCh() <- struct{}{}
	}
	return nil
}

func (c *core) acceptPub(msg *message, src hotstuff.Validator) (int, error) {
	logger := c.logger.New("from", src, "state", c.state)
	logger.Trace("Accept AggPub")
	count, err := c.addAggPub(msg.Address, msg.Msg)
	if err != nil {
		return -1, err
	}

	return count, nil
}
