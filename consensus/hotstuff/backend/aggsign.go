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
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/hotstuff"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"

	// "go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/sign"
	"go.dedis.ch/kyber/v3/sign/bdn"
	// "go.dedis.ch/kyber/v3/util/random"
)

func (h *backend) AggPubCh() chan struct{} {
	return h.aggPubCh
}

// AddAggPub implements hotstuff.Backend.AddAggPub
func (h *backend) AddAggPub(valSet hotstuff.ValidatorSet, address common.Address, pubByte []byte) (int, error) {
	pub := h.config.Suite.G2().Point()
	if err := pub.UnmarshalBinary(pubByte); err != nil {
		return -1, err
	}
	if _, exist := h.aggregatedKeyPair[address]; !exist {
		h.aggregatedKeyPair[address] = pub
		_, ok := valSet.GetByAddress(address)
		if ok == nil {
			h.logger.Trace("Address not in validators set, backing up", "address", address)
		} else {
			h.logger.Trace("Address in validators set", "address", address)
			h.participants += 1
		}
	}

	return h.participants, nil
}

// AggregatedSignedFromSingle implements hotstuff.Backend.AggregatedSignedFromSingle
func (h *backend) AggregatedSignedFromSingle(msg []byte) ([]byte, []byte, error) {
	if h.aggregatedPub == nil || h.aggregatedPrv == nil {
		return nil, nil, errIncorrectAggInfo
	}
	pubByte, err := h.aggregatedPub.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	sig, err := bdn.Sign(h.config.Suite, h.aggregatedPrv, msg)
	if err != nil {
		return nil, nil, err
	}
	return pubByte, sig, nil
}

// AggregateSignature implements hotstuff.Backend.AggregateSignature
func (h *backend) AggregateSignature(valSet hotstuff.ValidatorSet, collectionPub, collectionSig map[common.Address][]byte) ([]byte, []byte, []byte, error) {
	if err := h.collectSignature(valSet, collectionPub); err != nil {
		return nil, nil, nil, err
	}
	if err := h.setBitForMask(collectionPub); err != nil {
		return nil, nil, nil, err
	}
	aggSig, err := h.aggregateSignatures(collectionSig)
	if err != nil {
		return nil, nil, nil, err
	}
	aggKey, err := h.aggregateKeys()
	if err != nil {
		return nil, nil, nil, err
	}
	if len(h.mask.Mask()) != (valSet.Size()+7)/8 {
		// This shouldn't happen because the process stops due to the state not set to StateAcceptRequest yet
		return nil, nil, nil, errInsufficientAggPub
	}
	return h.mask.Mask(), aggSig, aggKey, nil
}

// UpdateMask implements hotstuff.Backend.UpdateMask
func (h *backend) UpdateMask(valSet hotstuff.ValidatorSet) error {
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
	filteredList := convert(h.aggregatedKeyPair)
	if len(filteredList) != valSet.Size() {
		// This shouldn't happen because the process stops due to the state not set to StateAcceptRequest yet
		return errInsufficientAggPub
	}
	h.mask, err = sign.NewMask(h.config.Suite, filteredList, nil)
	if err != nil {
		return err
	}

	return nil
}

// RemoveMask implements hotstuff.Backend.RemoveMask
func (h *backend) RemoveParticipants(valSet hotstuff.ValidatorSet, addresses ...common.Address) {
	for _, addr := range addresses {
		if _, exist := h.aggregatedKeyPair[addr]; exist {
			delete(h.aggregatedKeyPair, addr)
			h.participants -= 1
		}
	}
	if err := h.UpdateMask(valSet); err != nil {
		return
	}
}

func (h *backend) collectSignature(valSet hotstuff.ValidatorSet, collection map[common.Address][]byte) error {
	for addr, pubByte := range collection {
		if addr == h.Address() {
			return errInvalidProposal
		}
		pub := h.config.Suite.G2().Point()
		if err := pub.UnmarshalBinary(pubByte); err != nil {
			return err
		}
		if _, exist := h.aggregatedKeyPair[addr]; !exist {
			h.aggregatedKeyPair[addr] = pub
			h.participants += 1
		}
	}
	// Update the mask anyway, reset the bit
	if err := h.UpdateMask(valSet); err != nil {
		return err
	}
	return nil
}

func (h *backend) setBitForMask(collection map[common.Address][]byte) error {
	for _, pubByte := range collection {
		pub := h.config.Suite.G2().Point()
		if err := pub.UnmarshalBinary(pubByte); err != nil {
			return err
		}
		for i, key := range h.mask.Publics() {
			if key.Equal(pub) {
				h.mask.SetBit(i, true)
			}
		}
	}
	return nil
}

func (h *backend) aggregateSignatures(collection map[common.Address][]byte) ([]byte, error) {
	sigs := make([][]byte, len(collection))
	i := 0
	for _, sig := range collection {
		sigs[i] = make([]byte, types.HotStuffExtraAggSig)
		copy(sigs[i][:], sig)
		i += 1
	}
	if len(sigs) != len(collection) {
		return nil, errTestIncorrectConversion
	}

	aggregatedSig, err := bdn.AggregateSignatures(h.config.Suite, sigs, h.mask)
	if err != nil {
		return nil, err
	}
	aggregatedSigByte, err := aggregatedSig.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return aggregatedSigByte, nil
}

func (h *backend) aggregateKeys() ([]byte, error) {
	aggKey, err := bdn.AggregatePublicKeys(h.config.Suite, h.mask)
	if err != nil {
		return nil, err
	}
	aggKeyByte, err := aggKey.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return aggKeyByte, nil
}

func (h *backend) verifySig(roundChange bool, aggKeyByte, aggSigByte []byte) error {
	// UnmarshalBinary aggKeyByte to kyber.Point
	aggKey := h.config.Suite.G2().Point()
	if err := aggKey.UnmarshalBinary(aggKeyByte); err != nil {
		return err
	}

	// Regenerate the *message
	msg := h.core.CurrentRoundstate().Message(roundChange)
	signedData, err := msg.PayloadNoAddrNoAggNoSig()
	if err != nil {
		return err
	}
	if err := bdn.Verify(h.config.Suite, aggKey, signedData, aggSigByte); err != nil {
		return err
	}
	return nil
}

func (h *backend) verifyMask(valSet hotstuff.ValidatorSet, mask []byte) error {
	if len(mask) != (valSet.Size()+7)/8 {
		return errInsufficientAggPub
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
		return errInvalidAggregatedSig
	}
	return nil
}
