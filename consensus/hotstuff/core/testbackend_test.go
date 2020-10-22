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
	"crypto/ecdsa"
	"errors"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/hotstuff"
	"github.com/ethereum/go-ethereum/consensus/hotstuff/validator"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	elog "github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/sign"
	"go.dedis.ch/kyber/v3/sign/bdn"
	"go.dedis.ch/kyber/v3/util/random"
)

var testLogger = elog.New()

type testSystemBackend struct {
	id  uint64
	sys *testSystem

	engine CoreEngine
	peers  hotstuff.ValidatorSet
	events *event.TypeMux

	committedMsgs []testCommittedMsgs
	sentMsgs      [][]byte // store the message when Send is called by core

	address common.Address
	db      ethdb.Database

	// aggregated signature
	suite             *bn256.Suite
	aggregatedKeyPair map[common.Address]kyber.Point // map[address] -> pub
	participants      int
	aggPubCh          chan struct{}
	aggregatedPub     kyber.Point
	aggregatedPrv     kyber.Scalar
	mask              *sign.Mask // update whenever the size of aggregatedKeyPair increases
}

type testCommittedMsgs struct {
	commitProposal hotstuff.Proposal
	// committedSeals [][]byte
	mask   []byte
	aggSig []byte
	aggKey []byte
}

// ==============================================
//
// define the functions that needs to be provided for Istanbul.

func (self *testSystemBackend) Address() common.Address {
	return self.address
}

// Peers returns all connected peers
func (self *testSystemBackend) Validators(proposal hotstuff.Proposal) hotstuff.ValidatorSet {
	return self.peers
}

func (self *testSystemBackend) EventMux() *event.TypeMux {
	return self.events
}

func (self *testSystemBackend) Broadcast(valSet hotstuff.ValidatorSet, message []byte) error {
	testLogger.Info("enqueuing a message...", "address", self.Address())
	self.sentMsgs = append(self.sentMsgs, message)
	self.sys.queuedMessage <- hotstuff.MessageEvent{
		Payload: message,
	}
	return nil
}

func (self *testSystemBackend) Unicast(valSet hotstuff.ValidatorSet, message []byte) error {
	testLogger.Info("enqueuing a message...", "address", self.Address())
	self.sentMsgs = append(self.sentMsgs, message)
	self.sys.queuedMessage <- hotstuff.MessageEvent{
		Payload: message,
	}
	return nil
}

func (self *testSystemBackend) Gossip(valSet hotstuff.ValidatorSet, message []byte) error {
	testLogger.Warn("not sign any data")
	return nil
}

func (self *testSystemBackend) Commit(proposal hotstuff.Proposal, valSet hotstuff.ValidatorSet, collectionPub, collectionSig map[common.Address][]byte) error {
	testLogger.Info("commit message", "address", self.Address())
	// Aggregate the signature
	mask, aggSig, aggKey, err := self.AggregateSignature(valSet, collectionPub, collectionSig)
	if err != nil {
		return err
	}
	self.committedMsgs = append(self.committedMsgs, testCommittedMsgs{
		commitProposal: proposal,
		// committedSeals: seals,
		mask:   mask,
		aggSig: aggSig,
		aggKey: aggKey,
	})

	// fake new head events
	go self.events.Post(hotstuff.FinalCommittedEvent{})
	return nil
}

func (self *testSystemBackend) Verify(proposal hotstuff.Proposal) (time.Duration, error) {
	return 0, nil
}

func (self *testSystemBackend) Sign(data []byte) ([]byte, error) {
	testLogger.Info("returning current backend address so that CheckValidatorSignature returns the same value")
	return self.address.Bytes(), nil
}

func (self *testSystemBackend) CheckSignature([]byte, common.Address, []byte) error {
	return nil
}

func (self *testSystemBackend) CheckValidatorSignature(data []byte, sig []byte) (common.Address, error) {
	return common.BytesToAddress(sig), nil
}

func (self *testSystemBackend) Hash(b interface{}) common.Hash {
	return common.StringToHash("Test")
}

func (self *testSystemBackend) NewRequest(request hotstuff.Proposal) {
	go self.events.Post(hotstuff.RequestEvent{
		Proposal: request,
	})
}

func (self *testSystemBackend) HasBadProposal(hash common.Hash) bool {
	return false
}

func (self *testSystemBackend) LastProposal() (hotstuff.Proposal, common.Address) {
	l := len(self.committedMsgs)
	if l > 0 {
		return self.committedMsgs[l-1].commitProposal, common.Address{}
	}
	return makeBlock(0), common.Address{}
}

// Only block height 5 will return true
func (self *testSystemBackend) HasPropsal(hash common.Hash, number *big.Int) bool {
	return number.Cmp(big.NewInt(5)) == 0
}

func (self *testSystemBackend) GetSpeaker(number uint64) common.Address {
	return common.Address{}
}

func (self *testSystemBackend) ParentValidators(proposal hotstuff.Proposal) hotstuff.ValidatorSet {
	return self.peers
}

func (self *testSystemBackend) Close() error {
	return nil
}

// AggPubCh returns the aggPub channel to coreEngine
func (self *testSystemBackend) AggPubCh() chan struct{} {
	return nil
}

// AddAggPub adds new aggPub to local recording everytime the valset gets updated
func (self *testSystemBackend) AddAggPub(valSet hotstuff.ValidatorSet, address common.Address, pubByte []byte) (int, error) {
	return 0, nil
}

// CountAggPub retrieves the size of current aggregated public key collection
func (self *testSystemBackend) CountAggPub() int {
	return self.participants
}

// AggregatedSignedFromSingle assigns value to msg.AggPub and msg.AggSign
func (self *testSystemBackend) AggregatedSignedFromSingle(msg []byte) ([]byte, []byte, error) {
	if self.aggregatedPub == nil || self.aggregatedPrv == nil {
		return nil, nil, errors.New("incorrect agg information")
	}
	pubByte, err := self.aggregatedPub.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	sig, err := bdn.Sign(self.suite, self.aggregatedPrv, msg)
	if err != nil {
		return nil, nil, err
	}
	return pubByte, sig, nil
}

// AggregateSignature aggregates the signatures
func (self *testSystemBackend) AggregateSignature(valSet hotstuff.ValidatorSet, collectionPub, collectionSig map[common.Address][]byte) ([]byte, []byte, []byte, error) {
	if err := self.collectSignature(valSet, collectionPub); err != nil {
		return nil, nil, nil, err
	}
	if err := self.setBitForMask(collectionPub); err != nil {
		return nil, nil, nil, err
	}
	aggSig, err := self.aggregateSignatures(collectionSig)
	if err != nil {
		return nil, nil, nil, err
	}
	aggKey, err := self.aggregateKeys()
	if err != nil {
		return nil, nil, nil, err
	}
	if len(self.mask.Mask()) != (valSet.Size()+7)/8 {
		// This shouldn't happen because the process stops due to the state not set to StateAcceptRequest yet
		return nil, nil, nil, errors.New("insufficient aggPub")
	}
	return self.mask.Mask(), aggSig, aggKey, nil
}

// UpdateMask updates the state of the current mask
func (self *testSystemBackend) UpdateMask(valSet hotstuff.ValidatorSet) error {
	convert := func(keyPair map[common.Address]kyber.Point) []kyber.Point {
		keyPairSlice := make([]kyber.Point, 0, params.MaximumMiner)
		for addr, pub := range keyPair {
			if _, val := valSet.GetByAddress(addr); val != nil {
				keyPairSlice = append(keyPairSlice, pub)
			}
		}
		return keyPairSlice
	}

	var err error
	filteredList := convert(self.aggregatedKeyPair)
	if len(filteredList) != valSet.Size() {
		// This shouldn't happen because the process stops due to the state not set to StateAcceptRequest yet
		return errors.New("insufficient aggPub")
	}
	self.mask, err = sign.NewMask(self.suite, filteredList, nil)
	if err != nil {
		return err
	}

	return nil
}

// RemoveParticipants removes arbitrary pubs from the current mask
func (self *testSystemBackend) RemoveParticipants(valSet hotstuff.ValidatorSet, addresses ...common.Address) {
}

// SetAggInfo assigns new keypair for unit testing
func (self *testSystemBackend) SetAggInfo(unitTest bool, suite *bn256.Suite) {
	if unitTest {
		self.suite = bn256.NewSuite()
		self.aggregatedPrv, self.aggregatedPub = bdn.NewKeyPair(self.suite, random.New())
	}
}

// ==============================================
//
// TODO: This should not be a copy-paste
func (self *testSystemBackend) collectSignature(valSet hotstuff.ValidatorSet, collection map[common.Address][]byte) error {
	for addr, pubByte := range collection {
		if addr == self.Address() {
			return errors.New("invalid proposal")
		}
		pub := self.suite.G2().Point()
		if err := pub.UnmarshalBinary(pubByte); err != nil {
			return err
		}
		if _, exist := self.aggregatedKeyPair[addr]; !exist {
			self.aggregatedKeyPair[addr] = pub
			self.participants += 1
		}
	}
	// Update the mask anyway, reset the bit
	if err := self.UpdateMask(valSet); err != nil {
		return err
	}
	return nil
}

func (self *testSystemBackend) setBitForMask(collection map[common.Address][]byte) error {
	for _, pubByte := range collection {
		pub := self.suite.G2().Point()
		if err := pub.UnmarshalBinary(pubByte); err != nil {
			return err
		}
		for i, key := range self.mask.Publics() {
			if key.Equal(pub) {
				self.mask.SetBit(i, true)
			}
		}
	}
	return nil
}

func (self *testSystemBackend) aggregateSignatures(collection map[common.Address][]byte) ([]byte, error) {
	sigs := make([][]byte, len(collection))
	i := 0
	for _, sig := range collection {
		sigs[i] = make([]byte, types.HotStuffExtraAggSig)
		copy(sigs[i][:], sig)
		i += 1
	}
	if len(sigs) != len(collection) {
		return nil, errors.New("incorrect conversion")
	}

	aggregatedSig, err := bdn.AggregateSignatures(self.suite, sigs, self.mask)
	if err != nil {
		return nil, err
	}
	aggregatedSigByte, err := aggregatedSig.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return aggregatedSigByte, nil
}

func (self *testSystemBackend) aggregateKeys() ([]byte, error) {
	aggKey, err := bdn.AggregatePublicKeys(self.suite, self.mask)
	if err != nil {
		return nil, err
	}
	aggKeyByte, err := aggKey.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return aggKeyByte, nil
}

func (self *testSystemBackend) verifySig(roundChange bool, aggKeyByte, aggSigByte []byte) error {
	// UnmarshalBinary aggKeyByte to kyber.Point
	aggKey := self.suite.G2().Point()
	if err := aggKey.UnmarshalBinary(aggKeyByte); err != nil {
		return err
	}

	// Regenerate the *message
	msg := self.engine.(*core).CurrentRoundstate().Message(roundChange)
	signedData, err := msg.PayloadNoAddrNoAggNoSig()
	if err != nil {
		return err
	}
	if err := bdn.Verify(self.suite, aggKey, signedData, aggSigByte); err != nil {
		return err
	}
	return nil
}

func (self *testSystemBackend) verifyMask(valSet hotstuff.ValidatorSet, mask []byte) error {
	if len(mask) != (valSet.Size()+7)/8 {
		return errors.New("insufficient aggPub")
	}

	count := 0
	for i := range valSet.List() {
		byteIndex := i / 8
		m := byte(1) << uint(i&7)
		if (mask[byteIndex] & m) != 0 {
			count++
		}
	}
	// This excludes the speaker
	if count < valSet.F() {
		return errors.New("invalid aggregated signature")
	}
	return nil
}

//
// ==============================================

// ==============================================
//
// define the struct that need to be provided for integration tests.

type testSystem struct {
	backends []*testSystemBackend

	queuedMessage chan hotstuff.MessageEvent
	quit          chan struct{}
}

func newTestSystem(n uint64) *testSystem {
	testLogger.SetHandler(elog.StdoutHandler)
	return &testSystem{
		backends: make([]*testSystemBackend, n),

		queuedMessage: make(chan hotstuff.MessageEvent),
		quit:          make(chan struct{}),
	}
}

func generateValidators(n int) []common.Address {
	vals := make([]common.Address, 0)
	for i := 0; i < n; i++ {
		privateKey, _ := crypto.GenerateKey()
		vals = append(vals, crypto.PubkeyToAddress(privateKey.PublicKey))
	}
	return vals
}

func newTestValidatorSet(n int) hotstuff.ValidatorSet {
	return validator.NewSet(generateValidators(n), hotstuff.RoundRobin)
}

// FIXME: int64 is needed for N and F
func NewTestSystemWithBackend(n, f uint64) *testSystem {
	testLogger.SetHandler(elog.StdoutHandler)

	addrs := generateValidators(int(n))
	sys := newTestSystem(n)
	config := hotstuff.DefaultConfig

	for i := uint64(0); i < n; i++ {
		vset := validator.NewSet(addrs, hotstuff.RoundRobin)
		backend := sys.NewBackend(i)
		backend.peers = vset
		backend.address = vset.GetByIndex(i).Address()

		core := New(backend, config).(*core)
		core.state = StateAcceptRequest
		core.current = newRoundState(&hotstuff.View{
			Round:  big.NewInt(0),
			Height: big.NewInt(1),
		}, vset, nil, nil, func(hash common.Hash) bool {
			return false
		})
		core.valSet = vset
		core.logger = testLogger
		core.validateFn = backend.CheckValidatorSignature

		backend.engine = core
	}

	return sys
}

// listen will consume messages from queue and deliver a message to core
func (t *testSystem) listen() {
	for {
		select {
		case <-t.quit:
			return
		case queuedMessage := <-t.queuedMessage:
			testLogger.Info("consuming a queue message...")
			for _, backend := range t.backends {
				go backend.EventMux().Post(queuedMessage)
			}
		}
	}
}

// Run will start system components based on given flag, and returns a closer
// function that caller can control lifecycle
//
// Given a true for core if you want to initialize core engine.
func (t *testSystem) Run(core bool) func() {
	for _, b := range t.backends {
		if core {
			b.engine.Start() // start Istanbul core
		}
	}

	go t.listen()
	closer := func() { t.stop(core) }
	return closer
}

func (t *testSystem) stop(core bool) {
	close(t.quit)

	for _, b := range t.backends {
		if core {
			b.engine.Stop()
		}
	}
}

func (t *testSystem) NewBackend(id uint64) *testSystemBackend {
	// assume always success
	ethDB := rawdb.NewMemoryDatabase()
	backend := &testSystemBackend{
		id:     id,
		sys:    t,
		events: new(event.TypeMux),
		db:     ethDB,
	}

	t.backends[id] = backend
	return backend
}

// ==============================================
//
// helper functions.

func getPublicKeyAddress(privateKey *ecdsa.PrivateKey) common.Address {
	return crypto.PubkeyToAddress(privateKey.PublicKey)
}
