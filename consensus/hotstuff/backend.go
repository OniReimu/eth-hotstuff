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

package hotstuff

import (
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/event"
	// "go.dedis.ch/kyber/v3"
)

// Backend provides application specific functions for HotStuff core (consensus/hotstuff/backend/backend.go)
type Backend interface {
	// GetAddress returns the owner's address
	GetAddress() common.Address

	// SetAddress sets the owner's address to core
	SetAddress()

	// Validators returns the validator set
	Validators(proposal Proposal) ValidatorSet

	// EventMux returns the event mux in backend
	EventMux() *event.TypeMux

	// Broadcast sends a message to all validators (include self)
	Broadcast(valSet ValidatorSet, payload []byte) error

	// Gossip sends a message to all validators (exclude self)
	Gossip(valSet ValidatorSet, payload []byte) error

	// Unicast sends a message to the current speaker
	Unicast(valSet ValidatorSet, payload []byte) error

	// Commit delivers an approved proposal to backend.
	// The delivered proposal will be put into blockchain.
	Commit(proposal Proposal, valSet ValidatorSet, collectionPub, collectionSig map[common.Address][]byte) error

	// Verify verifies the proposal. If a consensus.ErrFutureBlock error is returned,
	// the time difference of the proposal and current time is also returned.
	Verify(Proposal) (time.Duration, error)

	// Sign signs input data with the backend's private key
	Sign([]byte) ([]byte, error)

	// CheckSignature verifies the signature by checking if it's signed by
	// the given validator
	CheckSignature(data []byte, addr common.Address, sig []byte) error

	// LastProposal retrieves latest committed proposal and the address of speaker
	LastProposal() (Proposal, common.Address)

	// HasPropsal checks if the combination of the given hash and height matches any existing blocks
	HasPropsal(hash common.Hash, number *big.Int) bool

	// GetSpeaker returns the speaker of the given block height
	GetSpeaker(number uint64) common.Address

	// ParentValidators returns the validator set of the given proposal's parent block
	ParentValidators(proposal Proposal) ValidatorSet

	// HasBadBlock returns whether the block with the hash is a bad block
	HasBadProposal(hash common.Hash) bool

	Close() error

	// Aggregated-signature-related

	// AggPubCh returns the aggPub channel to coreEngine
	AggPubCh() chan struct{}

	// AddAggPub adds new aggPub to local recording everytime the valset gets updated
	AddAggPub(valSet ValidatorSet, address common.Address, pubByte []byte) (int, error)

	// AggregatedSignedFromSingle assigns value to msg.AggPub and msg.AggSign
	AggregatedSignedFromSingle(msg []byte) ([]byte, []byte, error)

	// AggregateSignature aggregates the signatures
	AggregateSignature(valSet ValidatorSet, collectionPub, collectionSig map[common.Address][]byte) ([]byte, []byte, []byte, error)

	// UpdateMask updates the state of the current mask
	UpdateMask(valSet ValidatorSet) error

	// RemoveParticipants removes arbitrary pubs from the current mask
	RemoveParticipants(valSet ValidatorSet, addresses ...common.Address)
}
