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
	"github.com/ethereum/go-ethereum/consensus/hotstuff"
	"gopkg.in/karalabe/cookiejar.v2/collections/prque"
)

var (
	// msgPriority is defined for calculating processing priority to speedup consensus
	// msgAnnounce > msgCommit > msgResponse
	msgPriority = map[uint64]int{
		msgAnnounce: 1,
		// msgCommit:   2,
		msgResponse: 2,
	}
)

// checkMessage checks the message state
// return errInvalidMessage if the message is invalid
// return errFutureMessage if the message view is larger than current view
// return errOldMessage if the message view is smaller than current view
func (c *core) checkMessage(msgCode uint64, view *hotstuff.View) error {
	if view == nil || view.Height == nil || view.Round == nil {
		return errInvalidMessage
	}

	if !c.hasAggPub && msgCode > msgSendPub {
		return errInsufficientPub
	}

	if msgCode == msgRoundChange {
		// Three-phase view change -> reorg
		if view.Height.Uint64()+1 == c.currentView().Height.Uint64() && view.Round.Uint64() > 0 {
			return nil
		}
		// other cases
		if view.Height.Cmp(c.currentView().Height) >= 0 { // Round change in hotstuff should only propose the (current-1) block
			return errFutureMessage
		} else if view.Cmp(c.currentView()) < 0 {
			return errOldMessage
		}
		return nil
	}

	if view.Cmp(c.currentView()) > 0 {
		return errFutureMessage
	}

	if view.Cmp(c.currentView()) < 0 {
		return errOldMessage
	}

	if c.waitingForRoundChange {
		return errFutureMessage
	}

	// StateAcceptRequest only accepts msgAnnounce
	// other messages are future messages
	if c.state == StateAcceptRequest {
		if msgCode > msgAnnounce {
			return errFutureMessage
		}
		return nil
	}

	// For states(StateAnnounce, StateResponsed, StateCommitted),
	// can accept all message types if processing with same view
	return nil
}

func (c *core) storeBacklog(msg *message, src hotstuff.Validator) {
	logger := c.logger.New("from", src, "state", c.state)

	if src.Address() == c.Address() {
		logger.Warn("Backlog from self")
		return
	}

	logger.Trace("Store future message")

	c.backlogsMu.Lock()
	defer c.backlogsMu.Unlock()

	logger.Debug("Retrieving backlog queue", "for", src.Address(), "backlogs_size", len(c.backlogs))
	backlog := c.backlogs[src.Address()]
	if backlog == nil {
		backlog = prque.New()
	}
	switch msg.Code {
	case msgAnnounce:
		var p *hotstuff.Announce
		err := msg.Decode(&p)
		if err == nil {
			backlog.Push(msg, toPriority(msg.Code, p.View))
		}
		// for msgRoundChange, msgPrepare and msgCommit cases
	default:
		var p *hotstuff.Subject
		err := msg.Decode(&p)
		if err == nil {
			backlog.Push(msg, toPriority(msg.Code, p.View))
		}
	}
	c.backlogs[src.Address()] = backlog
}

func (c *core) processBacklog() {
	c.backlogsMu.Lock()
	defer c.backlogsMu.Unlock()

	for srcAddress, backlog := range c.backlogs {
		if backlog == nil {
			continue
		}
		_, src := c.valSet.GetByAddress(srcAddress)
		if src == nil {
			// validator is not available
			delete(c.backlogs, srcAddress)
			continue
		}
		logger := c.logger.New("from", src, "state", c.state)
		isFuture := false

		// We stop processing if
		//   1. backlog is empty
		//   2. The first message in queue is a future message
		for !(backlog.Empty() || isFuture) {
			m, prio := backlog.Pop()
			msg := m.(*message)
			var view *hotstuff.View
			switch msg.Code {
			case msgAnnounce:
				var m *hotstuff.Announce
				err := msg.Decode(&m)
				if err == nil {
					view = m.View
				}
				// for msgRoundChange, msgPrepare and msgCommit cases
			default:
				var sub *hotstuff.Subject
				err := msg.Decode(&sub)
				if err == nil {
					view = sub.View
				}
			}
			if view == nil {
				logger.Debug("Nil view", "msg", msg)
				continue
			}
			// Push back if it's a future message
			err := c.checkMessage(msg.Code, view)
			if err != nil {
				if err == errFutureMessage {
					logger.Trace("Stop processing backlog", "msg", msg)
					backlog.Push(msg, prio)
					isFuture = true
					break
				}
				logger.Trace("Skip the backlog event", "msg", msg, "err", err)
				continue
			}
			logger.Trace("Post backlog event", "msg", msg)

			go c.sendEvent(backlogEvent{
				src: src,
				msg: msg,
			})
		}
	}
}

func toPriority(msgCode uint64, view *hotstuff.View) float32 {
	if msgCode == msgRoundChange {
		// For msgRoundChange, set the message priority based on its height
		return -float32(view.Height.Uint64() * 1000)
	}
	// FIXME: round will be reset as 0 while new height
	// 10 * Round limits the range of message code is from 0 to 9
	// 1000 * Height limits the range of round is from 0 to 99
	return -float32(view.Height.Uint64()*1000 + view.Round.Uint64()*10 + uint64(msgPriority[msgCode]))
}
