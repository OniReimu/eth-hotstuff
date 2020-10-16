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

// Package hotstuff implements the scalable hotstuff consensus algorithm.

package backend

import (
	// "bytes"
	// "errors"
	// "io"
	"math/big"
	// "runtime"
	// "strconv"
	"crypto/ecdsa"
	// "fmt"
	// "reflect"
	"sync"
	"time"

	// "github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	// "github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/hotstuff"
	hotStuffCore "github.com/ethereum/go-ethereum/consensus/hotstuff/core"
	"github.com/ethereum/go-ethereum/consensus/hotstuff/validator"
	"github.com/ethereum/go-ethereum/core"
	// "github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	// "github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	// "github.com/ethereum/go-ethereum/rpc"

	lru "github.com/hashicorp/golang-lru"
	// "gopkg.in/karalabe/cookiejar.v2/collections/prque"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/sign"
	"go.dedis.ch/kyber/v3/sign/bdn"
	"go.dedis.ch/kyber/v3/util/random"
)

const (
	// fetcherID is the ID indicates the block is from HotStuff engine
	fetcherID = "hotstuff"
)

// // SignerFn is a signer callback function to request a header to be signed by a
// // backing account. (Avoid import circle...)
// type SignerFn func(accounts.Account, string, []byte) ([]byte, error)

// HotStuff is the scalable hotstuff consensus engine
type backend struct {
	config       *hotstuff.Config
	db           ethdb.Database // Database to store and retrieve necessary information
	core         hotStuffCore.CoreEngine
	chain        consensus.ChainReader
	currentBlock func() *types.Block
	hasBadBlock  func(hash common.Hash) bool
	logger       log.Logger

	recents        *lru.ARCCache // Snapshots for recent block to speed up reorgs
	signatures     *lru.ARCCache // Signatures of recent blocks to speed up mining
	recentMessages *lru.ARCCache // the cache of peer's messages
	knownMessages  *lru.ARCCache // the cache of self messages

	privateKey *ecdsa.PrivateKey
	signer     common.Address // Ethereum address of the signing key
	// signFn func(accounts.Account, string, []byte) ([]byte, error) // Signer function to authorize hashes with

	// The channels for hotstuff engine notifications
	commitCh          chan *types.Block
	proposedBlockHash common.Hash
	coreStarted       bool
	sigMu             sync.RWMutex // Protects the signer fields
	consenMu          sync.Mutex   // Ensure a round can only start after the last one has finished
	coreMu            sync.RWMutex

	// event subscription for ChainHeadEvent event
	broadcaster consensus.Broadcaster

	hotStuffEventMux *event.TypeMux

	proposals map[common.Address]bool // Current list of proposals we are pushing

	// aggregated signature
	aggregatedKeyPair map[common.Address]kyber.Point // map[address] -> pub
	participants      int
	aggPubCh          chan struct{}
	aggregatedPub     kyber.Point
	aggregatedPrv     kyber.Scalar
	mask              *sign.Mask // update whenever the size of aggregatedKeyPair increases
}

func New(config *hotstuff.Config, privateKey *ecdsa.PrivateKey, db ethdb.Database) consensus.HotStuff {
	recents, _ := lru.NewARC(inmemorySnapshots)
	signatures, _ := lru.NewARC(inmemorySignatures)
	recentMessages, _ := lru.NewARC(inmemoryPeers)
	knownMessages, _ := lru.NewARC(inmemoryMessages)

	backend := &backend{
		config:            config,
		db:                db,
		logger:            log.New(),
		commitCh:          make(chan *types.Block, 1),
		coreStarted:       false,
		hotStuffEventMux:  new(event.TypeMux),
		privateKey:        privateKey,
		signatures:        signatures,
		recentMessages:    recentMessages,
		knownMessages:     knownMessages,
		recents:           recents,
		proposals:         make(map[common.Address]bool),
		aggregatedKeyPair: make(map[common.Address]kyber.Point),
		aggPubCh:          make(chan struct{}),
	}
	backend.aggregatedPrv, backend.aggregatedPub = bdn.NewKeyPair(config.Suite, random.New())
	backend.core = hotStuffCore.New(backend, backend.config)
	return backend
}

// EventMux implements hotstuff.Backend.EventMux
func (h *backend) EventMux() *event.TypeMux {
	return h.hotStuffEventMux
}

// // SetAddress implements hotstuff.Backend.SetAddress
// func (h *backend) SetAddress() {
// 	h.core.SetAddressAndLogger(h.signer)
// }

// // GetAddress implements hotstuff.Backend.GetAddress
// func (h *backend) GetAddress() common.Address {
// 	return h.signer // This is initialized in eth/backend.go - StartMining()
// }

// Address implements hotstuff.Backend.Address
func (h *backend) Address() common.Address {
	return h.signer
}

// Validators implements hotstuff.Backend.Validators
func (h *backend) Validators(proposal hotstuff.Proposal) hotstuff.ValidatorSet {
	return h.getValidators(proposal.Number().Uint64(), proposal.Hash())
}

// Broadcast implements hotstuff.Backend.Broadcast
func (h *backend) Broadcast(valSet hotstuff.ValidatorSet, payload []byte) error {
	// send to others
	h.Gossip(valSet, payload)
	// send to self
	msg := hotstuff.MessageEvent{
		Payload: payload,
	}
	go h.EventMux().Post(msg)
	return nil
}

// Broadcast implements hotstuff.Backend.Gossip
func (h *backend) Gossip(valSet hotstuff.ValidatorSet, payload []byte) error {
	hash := hotstuff.RLPHash(payload)
	h.knownMessages.Add(hash, true)

	targets := make(map[common.Address]bool)
	for _, val := range valSet.List() { // hotstuff/validator/default.go - defaultValidator
		if val.Address() != h.Address() {
			targets[val.Address()] = true
		}
	}
	if h.broadcaster != nil && len(targets) > 0 {
		ps := h.broadcaster.FindPeers(targets)
		for addr, p := range ps {
			ms, ok := h.recentMessages.Get(addr)
			var m *lru.ARCCache
			if ok {
				m, _ = ms.(*lru.ARCCache)
				if _, k := m.Get(hash); k {
					// This peer had this event, skip it
					continue
				}
			} else {
				m, _ = lru.NewARC(inmemoryMessages)
			}

			m.Add(hash, true)
			h.recentMessages.Add(addr, m)
			go p.Send(hotstuffMsg, payload)
		}
	}
	return nil
}

// Broadcast implements hotstuff.Backend.Unicast
func (h *backend) Unicast(valSet hotstuff.ValidatorSet, payload []byte) error {
	if valSet.IsSpeaker(h.Address()) {
		return errInvalidProposal
	}

	hash := hotstuff.RLPHash(payload)
	h.knownMessages.Add(hash, true)

	targets := make(map[common.Address]bool)
	for _, val := range valSet.List() {
		if val.Address() != h.Address() {
			targets[val.Address()] = true
		}
	}
	if h.broadcaster != nil && len(targets) > 0 {
		ps := h.broadcaster.FindPeers(targets)
		if p, exist := ps[valSet.GetSpeaker().Address()]; !exist {
			return errInvalidProposal
		} else {
			go p.Send(hotstuffMsg, payload)
		}
	}
	return nil
}

// Commit implements hotstuff.Backend.Commit
func (h *backend) Commit(proposal hotstuff.Proposal, valSet hotstuff.ValidatorSet, collectionPub, collectionSig map[common.Address][]byte) error {
	// Check if the proposal is a valid block
	block := &types.Block{}
	block, ok := proposal.(*types.Block)
	if !ok {
		h.logger.Error("Invalid proposal, %v", proposal)
		return errInvalidProposal
	}

	header := block.Header()

	// Aggregate the signature
	mask, aggSig, aggKey, err := h.AggregateSignature(valSet, collectionPub, collectionSig)
	if err != nil {
		return err
	}
	hotStuffExtra, err := types.ExtractHotStuffExtra(header)
	if err != nil {
		return err
	}
	copy(hotStuffExtra.Mask, mask)
	copy(hotStuffExtra.AggregatedKey, aggKey)
	copy(hotStuffExtra.AggregatedSig, aggSig)

	payload, err := rlp.EncodeToBytes(&hotStuffExtra)
	if err != nil {
		return nil
	}

	header.Extra = append(header.Extra[:types.HotStuffExtraVanity], payload...)

	// Sign all the things (the last 65B Seal)!
	sighash, err := h.Sign(HotStuffRLP(header))
	if err != nil {
		return err
	}
	// sighash, err := h.signFn(accounts.Account{Address: h.GetAddress()}, "", HotStuffRLP(header)) // Need to check if the empty string works
	// if err != nil {
	// 	return err
	// }

	copy(header.Extra[len(header.Extra)-extraSeal:], sighash)

	// update block's header
	newBlock := block.WithSeal(header)

	h.logger.Info("Committed", "address", h.Address(), "hash", proposal.Hash(), "number", proposal.Number().Uint64())
	// - if the proposed and committed blocks are the same, send the proposed hash
	//   to commit channel, which is being watched inside the engine.Seal() function.
	// - otherwise, we try to insert the block.
	// -- if success, the ChainHeadEvent event will be broadcasted, try to build
	//    the next block and the previous Seal() will be stopped (need to check this --- saber).
	// -- otherwise, an error will be returned and a round change event will be fired.
	if h.proposedBlockHash == newBlock.Hash() {
		// feed block hash to Seal() and wait the Seal() result
		h.commitCh <- newBlock
		return nil
	}

	if h.broadcaster != nil {
		h.broadcaster.Enqueue(fetcherID, newBlock)
	}

	return nil
}

// Verify implements hotstuff.Backend.Verify
func (h *backend) Verify(proposal hotstuff.Proposal) (time.Duration, error) {
	// Check if the proposal is a valid block
	block := &types.Block{}
	block, ok := proposal.(*types.Block)
	if !ok {
		h.logger.Error("Invalid proposal, %v", proposal)
		return 0, errInvalidProposal
	}

	// check bad block
	if h.HasBadProposal(block.Hash()) {
		return 0, core.ErrBlacklistedHash
	}

	// check block body
	txnHash := types.DeriveSha(block.Transactions())
	uncleHash := types.CalcUncleHash(block.Uncles())
	if txnHash != block.Header().TxHash {
		return 0, errMismatchTxhashes
	}
	if uncleHash != nilUncleHash {
		return 0, errInvalidUncleHash
	}

	// verify the header of proposed block
	err := h.VerifyHeader(h.chain, block.Header(), false)
	// ignore errEmptyAggregatedSig error because we don't have the bls-signature yet
	if err == nil || err == errEmptyAggregatedSig {
		return 0, nil
	} else if err == consensus.ErrFutureBlock {
		return time.Unix(int64(block.Header().Time), 0).Sub(now()), consensus.ErrFutureBlock
	}
	return 0, err
}

// Sign implements hotstuff.Backend.Sign
func (h *backend) Sign(data []byte) ([]byte, error) {
	hashData := crypto.Keccak256(data)
	// return h.signFn(accounts.Account{Address: h.GetAddress()}, "", hashData)
	return crypto.Sign(hashData, h.privateKey)
}

// CheckSignature implements hotstuff.Backend.CheckSignature
func (h *backend) CheckSignature(data []byte, address common.Address, sig []byte) error {
	signer, err := hotstuff.GetSignatureAddress(data, sig)
	if err != nil {
		log.Error("Failed to get signer address", "err", err)
		return err
	}
	// Compare derived addresses
	if signer != address {
		return errInvalidSignature
	}
	return nil
}

// HasPropsal implements hotstuff.Backend.HashBlock
func (h *backend) HasPropsal(hash common.Hash, number *big.Int) bool {
	return h.chain.GetHeader(hash, number.Uint64()) != nil
}

// GetSpeaker implements hotstuff.Backend.GetSpeaker
func (h *backend) GetSpeaker(number uint64) common.Address {
	if header := h.chain.GetHeaderByNumber(number); header != nil {
		a, _ := h.Author(header)
		return a
	}
	return common.Address{}
}

// ParentValidators implements hotstuff.Backend.GetParentValidators
func (h *backend) ParentValidators(proposal hotstuff.Proposal) hotstuff.ValidatorSet {
	if block, ok := proposal.(*types.Block); ok {
		return h.getValidators(block.Number().Uint64()-1, block.ParentHash())
	}
	return validator.NewSet(nil, h.config.SpeakerPolicy)
}

func (h *backend) getValidators(number uint64, hash common.Hash) hotstuff.ValidatorSet {
	snap, err := h.snapshot(h.chain, number, hash, nil)
	if err != nil {
		return validator.NewSet(nil, h.config.SpeakerPolicy)
	}
	return snap.ValSet
}

func (h *backend) LastProposal() (hotstuff.Proposal, common.Address) {
	block := h.currentBlock()

	var speaker common.Address
	if block.Number().Cmp(common.Big0) > 0 {
		var err error
		speaker, err = h.Author(block.Header())
		if err != nil {
			h.logger.Error("Failed to get block speaker", "err", err)
			return nil, common.Address{}
		}
	}

	// Return header only block here since we don't need block body
	return block, speaker
}

func (h *backend) HasBadProposal(hash common.Hash) bool {
	if h.hasBadBlock == nil {
		return false
	}
	return h.hasBadBlock(hash)
}
