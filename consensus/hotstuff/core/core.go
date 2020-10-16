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
	// "bytes"
	"math"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/hotstuff"
	"github.com/ethereum/go-ethereum/params"
	// "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	metrics "github.com/ethereum/go-ethereum/metrics"
	"gopkg.in/karalabe/cookiejar.v2/collections/prque"
)

// New creates an HotStuff consensus core
func New(backend hotstuff.Backend, config *hotstuff.Config) CoreEngine {
	r := metrics.NewRegistry()
	c := &core{
		config: config,
		// state:              StateAcceptRequest,
		state:                           StateSendPub,
		address:                         backend.Address(),
		handlerWg:                       new(sync.WaitGroup),
		logger:                          log.New("address", backend.Address()),
		backend:                         backend,
		backlogs:                        make(map[common.Address]*prque.Prque),
		backlogsMu:                      new(sync.Mutex),
		pendingRequests:                 prque.New(),
		pendingRequestsMu:               new(sync.Mutex),
		pendingRequestsUnconfirmedQueue: hotstuff.NewQueue(int(params.MinimumUnconfirmed)),
		consensusTimestamp:              time.Time{},
		roundMeter:                      metrics.NewMeter(),
		blockheightMeter:                metrics.NewMeter(),
		consensusTimer:                  metrics.NewTimer(),
	}

	r.Register("consensus/hotstuff/core/round", c.roundMeter)
	r.Register("consensus/hotstuff/core/blockheight", c.blockheightMeter)
	r.Register("consensus/hotstuff/core/consensus", c.consensusTimer)

	c.validateFn = c.checkValidatorSignature
	return c
}

// ----------------------------------------------------------------------------

type core struct {
	config  *hotstuff.Config
	address common.Address
	state   State
	logger  log.Logger

	backend             hotstuff.Backend
	events              *event.TypeMuxSubscription
	finalCommittedSub   *event.TypeMuxSubscription
	timeoutSub          *event.TypeMuxSubscription
	futureAnnounceTimer *time.Timer

	valSet                hotstuff.ValidatorSet
	waitingForRoundChange bool
	validateFn            func([]byte, []byte) (common.Address, error)

	hasAggPub bool

	backlogs   map[common.Address]*prque.Prque
	backlogsMu *sync.Mutex

	current   *roundState
	handlerWg *sync.WaitGroup

	roundChangeSet   *roundChangeSet
	roundChangeTimer *time.Timer

	pendingRequests                 *prque.Prque
	pendingRequestsMu               *sync.Mutex
	pendingRequestsUnconfirmedQueue *hotstuff.Queue

	consensusTimestamp time.Time
	// the meter to record the round change rate
	roundMeter metrics.Meter
	// the meter to record the block height update rate
	blockheightMeter metrics.Meter
	// the timer to record consensus duration (from accepting a preprepare to final committed stage)
	consensusTimer metrics.Timer
}

func (c *core) finalizeMessage(msg *message) ([]byte, error) {
	var err error

	// Add local address and aggregated-oriented pub and sign
	msg.Address = common.Address{}
	msg.AggPub = []byte{}
	msg.AggSign = []byte{}

	// Assign the AggPub, AggSign, and Mask if it's a RESPONSE message and proposal is not nil
	if (msg.Code == msgResponse || msg.Code == msgRoundChange) && c.current.Proposal() != nil {
		signedData, err := msg.PayloadNoAddrNoAggNoSig()
		if err != nil {
			return nil, err
		}
		msg.AggPub, msg.AggSign, err = c.backend.AggregatedSignedFromSingle(signedData)
		if err != nil {
			return nil, err
		}
	}
	// Add sender address
	msg.Address = c.Address()

	// Sign message
	data, err := msg.PayloadNoSig()
	if err != nil {
		return nil, err
	}
	msg.Signature, err = c.backend.Sign(data)
	if err != nil {
		return nil, err
	}

	// Convert to payload
	payload, err := msg.Payload()
	if err != nil {
		return nil, err
	}

	return payload, nil
}

func (c *core) broadcast(msg *message, round *big.Int) {
	logger := c.logger.New("state", c.state)

	payload, err := c.finalizeMessage(msg)
	if err != nil {
		logger.Error("Failed to finalize message", "msg", msg, "err", err)
		return
	}

	if msg.Code == msgResponse && c.current.Proposal() != nil {
		// Unicast payload to the current speaker
		if err = c.backend.Unicast(c.valSet, payload); err != nil {
			logger.Error("Failed to unicast message", "msg", msg, "err", err)
			return
		}
	} else if msg.Code == msgRoundChange && c.current.Proposal() != nil {
		// Calculate the new speaker
		_, lastSpeaker := c.backend.LastProposal()
		proposedNewSet := c.valSet.Copy()
		proposedNewSet.CalcSpeaker(lastSpeaker, round.Uint64())
		if !proposedNewSet.IsSpeaker(c.Address()) {
			// Unicast payload to the proposed speaker
			if err = c.backend.Unicast(proposedNewSet, payload); err != nil {
				logger.Error("Failed to unicast message", "msg", msg, "err", err)
				return
			}
		} else {
			logger.Trace("Local is the next speaker", "msg", msg)
			return
		}
	} else {
		// Broadcast payload
		if err = c.backend.Broadcast(c.valSet, payload); err != nil {
			logger.Error("Failed to broadcast message", "msg", msg, "err", err)
			return
		}
	}

}

func (c *core) currentView() *hotstuff.View {
	return &hotstuff.View{
		Height: new(big.Int).Set(c.current.Height()),
		Round:  new(big.Int).Set(c.current.Round()),
	}
}

func (c *core) IsSpeaker() bool {
	v := c.valSet
	if v == nil {
		return false
	}
	return v.IsSpeaker(c.backend.Address())
}

func (c *core) IsCurrentProposal(blockHash common.Hash) bool {
	return c.current != nil && c.current.pendingRequest != nil && c.current.pendingRequest.Proposal.Hash() == blockHash
}

func (c *core) Address() common.Address {
	return c.address
}

// func (c *core) SetAddressAndLogger(addr common.Address) {
// 	c.address = addr
// 	c.logger = log.New("address", c.backend.GetAddress())
// }

func (c *core) commit(roundChange bool, round *big.Int) {
	c.setState(StateResponsed)

	collectionPub := make(map[common.Address][]byte)
	collectionSig := make(map[common.Address][]byte)

	if !roundChange {
		proposal := c.current.Proposal()
		if proposal != nil {
			for _, msg := range c.current.Responses.Values() {
				if msg.Code == msgResponse {
					collectionPub[msg.Address], collectionSig[msg.Address] = msg.AggPub, msg.AggSign
				}
			}
			if err := c.backend.Commit(proposal, c.valSet, collectionPub, collectionSig); err != nil {
				c.sendNextRoundChange()
				return
			}
		}
	} else {
		// Round Change
		if !c.pendingRequestsUnconfirmedQueue.Empty() {
			proposal, err := c.pendingRequestsUnconfirmedQueue.GetFirst()
			if err != nil {
				c.sendNextRoundChange()
				return
			}
			for _, msg := range c.roundChangeSet.roundChanges[round.Uint64()].Values() {
				if msg.Code == msgRoundChange {
					collectionPub[msg.Address], collectionSig[msg.Address] = msg.AggPub, msg.AggSign
				}
			}
			if err := c.backend.Commit(proposal.(hotstuff.Proposal), c.valSet, collectionPub, collectionSig); err != nil {
				c.sendNextRoundChange()
				return
			}

		}

	}

}

// startNewRound starts a new round. if round equals to 0, it means to starts a new block height
func (c *core) startNewRound(round *big.Int) {
	var logger log.Logger
	if c.current == nil {
		logger = c.logger.New("old_round", -1, "old_height", 0)
	} else {
		logger = c.logger.New("old_round", c.current.Round(), "old_height", c.current.Height())
	}

	roundChange := false
	// Try to get last proposal
	lastProposal, lastSpeaker := c.backend.LastProposal()
	if c.current == nil {
		logger.Trace("Start to the initial round")
	} else if lastProposal.Number().Cmp(c.current.Height()) >= 0 {
		diff := new(big.Int).Sub(lastProposal.Number(), c.current.Height())
		c.blockheightMeter.Mark(new(big.Int).Add(diff, common.Big1).Int64())

		if !c.consensusTimestamp.IsZero() {
			c.consensusTimer.UpdateSince(c.consensusTimestamp)
			c.consensusTimestamp = time.Time{}
		}
		logger.Trace("Catch up latest proposal", "number", lastProposal.Number().Uint64(), "hash", lastProposal.Hash())
	} else if lastProposal.Number().Cmp(big.NewInt(c.current.Height().Int64()-1)) == 0 {
		if round.Cmp(common.Big0) == 0 {
			// same height and round, don't need to start new round
			return
		} else if round.Cmp(c.current.Round()) < 0 {
			logger.Warn("New round should not be smaller than current round", "height", lastProposal.Number().Int64(), "new_round", round, "old_round", c.current.Round())
			return
		}
		roundChange = true
	} else {
		logger.Warn("New height should be larger than current height", "new_height", lastProposal.Number().Int64())
		return
	}

	var newView *hotstuff.View
	if roundChange {
		newView = &hotstuff.View{
			Height: new(big.Int).Set(c.current.Height()),
			Round:  new(big.Int).Set(round),
		}
	} else {
		newView = &hotstuff.View{
			Height: new(big.Int).Add(lastProposal.Number(), common.Big1),
			Round:  new(big.Int),
		}
		c.valSet = c.backend.Validators(lastProposal)
	}

	// Update logger
	logger = logger.New("old_speaker", c.valSet.GetSpeaker())
	// Clear invalid ROUND CHANGE messages
	c.roundChangeSet = newRoundChangeSet(c.valSet)
	// New snapshot for new round
	c.updateRoundState(newView, c.valSet, roundChange)
	// Calculate new proposer
	c.valSet.CalcSpeaker(lastSpeaker, newView.Round.Uint64())
	c.waitingForRoundChange = false

	if !c.hasAggPub {
		c.setState(StateSendPub)
	} else {
		c.setState(StateAcceptRequest)
	}

	if roundChange && c.IsSpeaker() && c.current != nil && c.hasAggPub && c.state == StateAcceptRequest {
		if c.current.pendingRequest != nil && !c.pendingRequestsUnconfirmedQueue.Empty() {
			// TODO - hotstuff changeview replacing pendingRequest, commit directly with aggsig of roundchange
			c.commit(true, round)
		}
	}
	c.newRoundChangeTimer()

	logger.Debug("New round", "new_round", newView.Round, "new_height", newView.Height, "old_speaker", c.valSet.GetSpeaker(), "valSet", c.valSet.List(), "size", c.valSet.Size(), "IsSpeaker", c.IsSpeaker())
}

func (c *core) catchUpRound(view *hotstuff.View) {
	logger := c.logger.New("old_round", c.current.Round(), "old_height", c.current.Height(), "old_speaker", c.valSet.GetSpeaker())

	if view.Round.Cmp(c.current.Round()) > 0 {
		c.roundMeter.Mark(new(big.Int).Sub(view.Round, c.current.Round()).Int64())
	}
	c.waitingForRoundChange = true

	c.updateRoundState(view, c.valSet, true)
	c.roundChangeSet.Clear(view.Round)
	c.newRoundChangeTimer()

	logger.Trace("Catch up round", "new_round", view.Round, "new_height", view.Height, "new_speaker", c.valSet)
}

// updateRoundState updates round state
func (c *core) updateRoundState(view *hotstuff.View, validatorSet hotstuff.ValidatorSet, roundChange bool) {
	if roundChange && c.current != nil {
		// TODO - hotstuff changeview replacing pendingRequest
		c.current = newRoundState(view, validatorSet, nil, c.current.pendingRequest, c.backend.HasBadProposal)
	} else {
		c.current = newRoundState(view, validatorSet, nil, nil, c.backend.HasBadProposal)
	}
}

func (c *core) setState(state State) {
	if c.state != state {
		c.state = state
	}
	if state == StateAcceptRequest {
		c.processPendingRequests()
	}
	c.processBacklog()
}

func (c *core) stopFutureAnnounceTimer() {
	if c.futureAnnounceTimer != nil {
		c.futureAnnounceTimer.Stop()
	}
}

func (c *core) stopTimer() {
	c.stopFutureAnnounceTimer()
	if c.roundChangeTimer != nil {
		c.roundChangeTimer.Stop()
	}
}

func (c *core) newRoundChangeTimer() {
	c.stopTimer()

	// set timeout based on the round number
	timeout := time.Duration(c.config.RequestTimeout) * time.Millisecond
	round := c.current.Round().Uint64()
	if round > 0 {
		timeout += time.Duration(math.Pow(2, float64(round))) * time.Second
	}
	c.roundChangeTimer = time.AfterFunc(timeout, func() {
		c.sendEvent(timeoutEvent{})
	})
}

func (c *core) checkValidatorSignature(data []byte, sig []byte) (common.Address, error) {
	return hotstuff.CheckValidatorSignature(c.valSet, data, sig)
}

func (c *core) addAggPub(address common.Address, pubByte []byte) (int, error) {
	return c.backend.AddAggPub(c.valSet, address, pubByte)
}

func (c *core) HotStuffSize() int {
	c.logger.Trace("Confirmation Formula used (N-(N-1))/3")
	return int((c.valSet.Size() - (c.valSet.Size()-1)/3))
}

// PrepareCommittedSeal returns a committed seal for the given hash
func (c *core) CurrentRoundstate() *roundState {
	if c.current != nil {
		return c.current
	}
	return nil
}
