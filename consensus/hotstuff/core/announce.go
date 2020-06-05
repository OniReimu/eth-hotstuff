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
	"time"

	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/hotstuff"
)

func (c *core) sendAnnounce(announce *hotstuff.Request) {
	logger := c.logger.New("state", c.state)
	// If I'm the speaker and on the same block height with the proposal
	if c.current.Height().Cmp(announce.Proposal.Number()) == 0 && c.IsSpeaker() {
		curView := c.currentView()
		announce, err := Encode(&hotstuff.Announce{
			View:     curView,
			Proposal: announce.Proposal,
		})
		if err != nil {
			logger.Error("Failed to encode", "view", curView)
			return
		}
		c.broadcast(&message{
			Code: msgAnnounce,
			Msg:  announce,
		}, new(big.Int))
	}
}

func (c *core) handleAnnounce(msg *message, src hotstuff.Validator) error {
	logger := c.logger.New("from", src, "state", c.state)

	// Decode ANNOUNCE
	var announce *hotstuff.Announce
	err := msg.Decode(&announce)
	if err != nil {
		return errFailedDecodeAnnounce
	}

	if err := c.checkMessage(msgAnnounce, announce.View); err != nil {
		if err == errOldMessage {
			// Get validator set for the given proposal
			valSet := c.backend.ParentValidators(announce.Proposal).Copy()
			previousSpeaker := c.backend.GetSpeaker(announce.Proposal.Number().Uint64() - 1)
			valSet.CalcSpeaker(previousSpeaker, announce.View.Round.Uint64())
			// Send RESPONSE it if it is an existing block (mainly for receiving announce after view change)
			// 1. The speaker needs to be a speaker matches the given (Height + Round)
			// 2. The given block must exist
			if valSet.IsSpeaker(src.Address()) && c.backend.HasPropsal(announce.Proposal.Hash(), announce.Proposal.Number()) {
				c.sendResponseForOldBlock(announce.View, announce.Proposal.Hash())
				return nil
			}
		}
		return err
	}

	// Check if the message comes from current speaker
	if !c.valSet.IsSpeaker(src.Address()) {
		logger.Warn("Ignore announce messages from non-speaker")
		return errNotFromSpeaker
	}

	// Verify the proposal we received
	if duration, err := c.backend.Verify(announce.Proposal); err != nil {
		// if it's a future block, we will handle it again after the duration
		if err == consensus.ErrFutureBlock {
			logger.Info("Proposed block will be handled in the future", "err", err, "duration", duration)
			c.stopFutureAnnounceTimer()
			c.futureAnnounceTimer = time.AfterFunc(duration, func() {
				c.sendEvent(backlogEvent{
					src: src,
					msg: msg,
				})
			})
		} else {
			logger.Warn("Failed to verify proposal", "err", err, "duration", duration)
			c.sendNextRoundChange()
		}
		return err
	}

	// Here is about to accept the ANNOUNCE and send RESPONSE
	if c.state == StateAcceptRequest {
		c.acceptAnnounce(announce)
		c.setState(StateAnnounced)
		c.sendResponse()
	}

	return nil
}

func (c *core) acceptAnnounce(announce *hotstuff.Announce) {
	c.consensusTimestamp = time.Now()
	c.current.SetAnnounce(announce)
}
