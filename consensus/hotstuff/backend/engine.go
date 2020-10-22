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
	"bytes"
	"errors"

	// "io"
	"math/big"
	"math/rand"

	// "strconv"
	// "sync"
	"time"

	// "github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/hotstuff"

	// hotStuffCore "github.com/ethereum/go-ethereum/consensus/hotstuff/core"
	"github.com/ethereum/go-ethereum/consensus/hotstuff/validator"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	// "github.com/ethereum/go-ethereum/ethdb"
	// "github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"

	// lru "github.com/hashicorp/golang-lru"
	"golang.org/x/crypto/sha3"
)

const (
	checkpointInterval = 1024 // Number of blocks after which to save the vote snapshot to the database
	inmemorySnapshots  = 128  // Number of recent vote snapshots to keep in memory
	inmemorySignatures = 4096 // Number of recent block signatures to keep in memory
	inmemoryPeers      = 1000
	inmemoryMessages   = 1024
)

// HotStuff protocol constants.
var (
	extraVanity = crypto.DigestLength    // Fixed number of extra-data prefix bytes reserved for signer vanity
	extraSeal   = crypto.SignatureLength // Fixed number of extra-data suffix bytes reserved for signer seal

	defaultDifficulty = big.NewInt(1)
	nilUncleHash      = types.CalcUncleHash(nil) // Always Keccak256(RLP([])) as uncles are meaningless outside of PoW.
	emptyNonce        = types.BlockNonce{}
	uncleHash         = types.CalcUncleHash(nil) // Always Keccak256(RLP([])) as uncles are meaningless outside of PoW.
	now               = time.Now

	nonceAuthVote = hexutil.MustDecode("0xffffffffffffffff") // Magic nonce number to vote on adding a new validator
	nonceDropVote = hexutil.MustDecode("0x0000000000000000") // Magic nonce number to vote on removing a validator.
)

// Various error messages to mark blocks invalid. These should be private to
// prevent engine specific errors from being referenced in the remainder of the
// codebase, inherently breaking if the engine is swapped out. Please put common
// error types into the consensus package.
var (
	// errUnknownBlock is returned when the list of signers is requested for a block
	// that is not part of the local blockchain.
	errUnknownBlock = errors.New("unknown block")

	// errInvalidCheckpointBeneficiary is returned if a checkpoint/epoch transition
	// block has a beneficiary set to non-zeroes.
	errInvalidCheckpointBeneficiary = errors.New("beneficiary in checkpoint block non-zero")

	// errInvalidVote is returned if a nonce value is something else that the two
	// allowed constants of 0x00..0 or 0xff..f.
	errInvalidVote = errors.New("vote nonce not 0x00..0 or 0xff..f")

	// errInvalidCheckpointVote is returned if a checkpoint/epoch transition block
	// has a vote nonce set to non-zeroes.
	errInvalidCheckpointVote = errors.New("vote nonce in checkpoint block non-zero")

	// errMissingVanity is returned if a block's extra-data section is shorter than
	// 32 bytes, which is required to store the signer vanity.
	errMissingVanity = errors.New("extra-data 32 byte vanity prefix missing")

	// errMissingSignature is returned if a block's extra-data section doesn't seem
	// to contain a 65 byte secp256k1 signature.
	errMissingSignature = errors.New("extra-data 65 byte signature suffix missing")

	// errExtraSigners is returned if non-checkpoint block contain signer data in
	// their extra-data fields.
	errExtraSigners = errors.New("non-checkpoint block contains extra signer list")

	// errInvalidCheckpointSigners is returned if a checkpoint block contains an
	// invalid list of signers (i.e. non divisible by 20 bytes).
	errInvalidCheckpointSigners = errors.New("invalid signer list on checkpoint block")

	// errMismatchingCheckpointSigners is returned if a checkpoint block contains a
	// list of signers different than the one the local node calculated.
	errMismatchingCheckpointSigners = errors.New("mismatching signer list on checkpoint block")

	// errInvalidMixDigest is returned if a block's mix digest is non-zero.
	errInvalidMixDigest = errors.New("non-zero mix digest")

	// errInvalidUncleHash is returned if a block contains an non-empty uncle list.
	errInvalidUncleHash = errors.New("non empty uncle hash")

	// errInvalidDifficulty is returned if the difficulty of a block neither 1 or 2.
	errInvalidDifficulty = errors.New("invalid difficulty")

	// errWrongDifficulty is returned if the difficulty of a block doesn't match the
	// turn of the signer.
	errWrongDifficulty = errors.New("wrong difficulty")

	// ErrInvalidTimestamp is returned if the timestamp of a block is lower than
	// the previous block's timestamp + the minimum block period.
	ErrInvalidTimestamp = errors.New("invalid timestamp")

	// errInvalidVotingChain is returned if an authorization list is attempted to
	// be modified via out-of-range or non-contiguous headers.
	errInvalidVotingChain = errors.New("invalid voting chain")

	// errUnauthorizedSigner is returned if a header is signed by a non-authorized entity.
	errUnauthorizedSigner = errors.New("unauthorized signer")

	// errRecentlySigned is returned if a header is signed by an authorized entity
	// that already signed a header recently, thus is temporarily not allowed to.
	errRecentlySigned = errors.New("recently signed")

	// HotStuff - new error types
	// errInvalidProposal is returned when a prposal is malformed.
	errInvalidProposal = errors.New("invalid proposal")

	// errMismatchTxhashes is returned if the TxHash in header is mismatch.
	errMismatchTxhashes = errors.New("mismatch transactions hashes")

	// errInsufficientAggPub is returned if there is no enough aggPub being recorded locally
	errInsufficientAggPub = errors.New("insufficient aggPub")

	// errInvalidAggregatedSign is returned if the aggregated signature is not signed by any of parent validators.
	errInvalidAggregatedSig = errors.New("invalid aggregated signature")

	// errEmptyAggregatedSign is returned if the field of aggregated signature is zero.
	errEmptyAggregatedSig = errors.New("zero aggregated signature")

	// errInvalidSignature is returned when given signature is not signed by given
	// address.
	errInvalidSignature = errors.New("invalid signature")

	// errInvalidExtraDataFormat is returned when the extra data format is incorrect
	errInvalidExtraDataFormat = errors.New("invalid extra data format")

	// errInvalidNonce is returned if a block's nonce is invalid
	errInvalidNonce = errors.New("invalid nonce")

	// errInvalidTimestamp is returned if the timestamp of a block is lower than the previous block's timestamp + the minimum block period.
	errInvalidTimestamp = errors.New("invalid timestamp")

	// errIncorrectAggInfo is returned if the local agg information is empty
	errIncorrectAggInfo = errors.New("incorrect agg information")

	// errTestIncorrectConversion is returned if the any conversion is incorrect for tests
	errTestIncorrectConversion = errors.New("incorrect conversion")
)

// Author implements consensus.Engine, returning the Ethereum address recovered
// from the signature in the header's extra-data section.
func (h *backend) Author(header *types.Header) (common.Address, error) {
	return ecrecover(header, h.signatures)
}

func (h *backend) VerifyHeader(chain consensus.ChainReader, header *types.Header, seal bool) error {
	return h.verifyHeader(chain, header, nil)
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers. The
// method returns a quit channel to abort the operations and a results channel to
// retrieve the async verifications (the order is that of the input slice).
func (h *backend) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))

	go func() {
		for i, header := range headers {
			err := h.verifyHeader(chain, header, headers[:i])

			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

// verifyHeader checks whether a header conforms to the consensus rules.The
// caller may optionally pass in a batch of parents (ascending order) to avoid
// looking those up from the database. This is useful for concurrently verifying
// a batch of new headers.
func (h *backend) verifyHeader(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {
	if header.Number == nil {
		return errUnknownBlock
	}

	// Don't waste time checking blocks from the future
	if header.Time > uint64(time.Now().Unix()) {
		return consensus.ErrFutureBlock
	}

	// Ensure that the extra data format is satisfied
	if _, err := types.ExtractHotStuffExtra(header); err != nil {
		return errInvalidExtraDataFormat
	}

	// Ensure that the coinbase is valid
	if header.Nonce != (emptyNonce) && !bytes.Equal(header.Nonce[:], nonceAuthVote) && !bytes.Equal(header.Nonce[:], nonceDropVote) {
		return errInvalidNonce
	}

	// Ensure that the mix digest is zero as we don't have fork protection currently
	if header.MixDigest != types.HotStuffDigest {
		return errInvalidMixDigest
	}
	// Ensure that the block doesn't contain any uncles which are meaningless in Istanbul
	if header.UncleHash != nilUncleHash {
		return errInvalidUncleHash
	}
	// Ensure that the block's difficulty is meaningful (may not be correct at this point)
	if header.Difficulty == nil || header.Difficulty.Cmp(defaultDifficulty) != 0 {
		return errInvalidDifficulty
	}

	// All basic checks passed, verify cascading fields
	return h.verifyCascadingFields(chain, header, parents)
}

// verifyCascadingFields verifies all the header fields that are not standalone,
// rather depend on a batch of previous headers. The caller may optionally pass
// in a batch of parents (ascending order) to avoid looking those up from the
// database. This is useful for concurrently verifying a batch of new headers.
func (h *backend) verifyCascadingFields(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {
	// The genesis block is the always valid dead-end
	number := header.Number.Uint64()
	if number == 0 {
		return nil
	}
	// Ensure that the block's timestamp isn't too close to it's parent
	var parent *types.Header
	if len(parents) > 0 {
		parent = parents[len(parents)-1]
	} else {
		parent = chain.GetHeader(header.ParentHash, number-1)
	}
	if parent == nil || parent.Number.Uint64() != number-1 || parent.Hash() != header.ParentHash {
		return consensus.ErrUnknownAncestor
	}
	if parent.Time+h.config.BlockPeriod > header.Time {
		return errInvalidTimestamp
	}
	// Verify validators in extraData. Validators in snapshot and extraData should be the same.
	snap, err := h.snapshot(chain, number-1, header.ParentHash, parents)
	if err != nil {
		return err
	}
	validators := make([]byte, len(snap.validators())*common.AddressLength)
	for i, validator := range snap.validators() {
		copy(validators[i*common.AddressLength:], validator[:])
	}
	if err := h.verifySigner(chain, header, parents); err != nil {
		return err
	}

	// All basic checks passed, verify the bls-signature
	return h.verifyAggregatedSig(chain, header, parents)
}

// verifySigner checks whether the signer is in parent's validator set
func (h *backend) verifySigner(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {
	// Verifying the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}

	// Retrieve the snapshot needed to verify this header and cache it
	snap, err := h.snapshot(chain, number-1, header.ParentHash, parents)
	if err != nil {
		return err
	}

	// resolve the authorization key and check against signers
	signer, err := ecrecover(header, h.signatures)
	if err != nil {
		return err
	}

	// Signer should be in the validator set of previous block's extraData.
	if _, v := snap.ValSet.GetByAddress(signer); v == nil {
		return errUnauthorizedSigner
	}
	return nil
}

// VerifySeal implements consensus.Engine, checking whether the signature contained
// in the header satisfies the consensus protocol requirements.
func (h *backend) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	// get parent header and ensure the signer is in parent's validator set
	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}

	// ensure that the difficulty equals to defaultDifficulty
	if header.Difficulty.Cmp(defaultDifficulty) != 0 {
		return errInvalidDifficulty
	}
	return h.verifySigner(chain, header, nil)
}

// verifyAggregatedSig checks whether the aggregated-signature contained in the header satisfies the
// consensus protocol requirements.
func (h *backend) verifyAggregatedSig(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {
	number := header.Number.Uint64()
	// We don't need to verify aggregated signature in the genesis block
	if number == 0 {
		return nil
	}

	// Retrieve the snapshot needed to verify this header and cache it
	snap, err := h.snapshot(chain, number-1, header.ParentHash, parents)
	if err != nil {
		return err
	}

	extra, err := types.ExtractHotStuffExtra(header)
	if err != nil {
		return err
	}
	// The length of aggregated info should be larger than 0
	if len(extra.Mask) == 0 || len(extra.AggregatedKey) == 0 || len(extra.AggregatedSig) == 0 {
		return errEmptyAggregatedSig
	}

	// Verify the aggregated signature
	currentHeight, _ := h.LastProposal()
	if number-1 == currentHeight.Number().Uint64() {
		// Roundchange-block -> roundchange == true
		if err := h.verifySig(true, extra.AggregatedKey, extra.AggregatedSig); err != nil {
			return err
		}
	} else if number+1 == currentHeight.Number().Uint64() {
		// Normal-block -> roundchange == false
		if err := h.verifySig(false, extra.AggregatedKey, extra.AggregatedSig); err != nil {
			return err
		}
	} else {
		return errUnknownBlock
	}

	validators := snap.ValSet.Copy()
	if err := h.verifyMask(validators, extra.Mask); err != nil {
		return err
	}

	return nil
}

// VerifyUncles implements consensus.Engine, always returning an error for any
// uncles as this consensus mechanism doesn't permit uncles.
func (h *backend) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	if len(block.Uncles()) > 0 {
		return errInvalidUncleHash
	}
	return nil
}

// Prepare implements consensus.Engine, preparing all the consensus fields of the
// header for running the transactions on top.
func (h *backend) Prepare(chain consensus.ChainReader, header *types.Header) error {
	h.logger.Trace("Prepare starts running")

	// unused fields, force to set to empty
	header.Coinbase = common.Address{} // overwrite the local address in miner/worker.go - commitNewWork
	header.Nonce = emptyNonce
	header.MixDigest = types.HotStuffDigest

	number := header.Number.Uint64()
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}

	// use the same difficulty for all blocks
	header.Difficulty = defaultDifficulty

	// Assemble the voting snapshot
	snap, err := h.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return err
	}

	h.sigMu.RLock()

	// Gather all the proposals that make sense voting on
	addresses := make([]common.Address, 0, len(h.proposals))
	for address, authorize := range h.proposals {
		if snap.checkVote(address, authorize) {
			addresses = append(addresses, address)
		}
	}
	// If there's pending proposals, cast a vote on them
	if len(addresses) > 0 {
		header.Coinbase = addresses[rand.Intn(len(addresses))]
		if h.proposals[header.Coinbase] {
			copy(header.Nonce[:], nonceAuthVote)
		} else {
			copy(header.Nonce[:], nonceDropVote)
		}
	}
	h.sigMu.RUnlock()

	// add validators in snapshot to extraData's validators section
	extra, err := prepareExtra(header, h.Address(), nil)
	if err != nil {
		return err
	}
	header.Extra = extra

	// Ensure the timestamp has the correct delay
	header.Time = parent.Time + h.config.BlockPeriod
	if header.Time < uint64(time.Now().Unix()) {
		header.Time = uint64(time.Now().Unix())
	}
	return nil
}

// Finalize implements consensus.Engine, ensuring no uncles are set, nor block
// rewards given.
func (h *backend) Finalize(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header) {
	// No block rewards in HotStuff, so the state remains as is and uncles are dropped
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
	header.UncleHash = nilUncleHash
}

// FinalizeAndAssemble implements consensus.Engine, ensuring no uncles are set,
// nor block rewards given, and returns the final block.
func (h *backend) FinalizeAndAssemble(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	// No block rewards in PoA, so the state remains as is and uncles are dropped
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
	header.UncleHash = nilUncleHash

	// Assemble and return the final block for sealing
	return types.NewBlock(header, txs, nil, receipts), nil
}

// Seal implements consensus.Engine, attempting to create a sealed block using
// the local signing credentials.
func (h *backend) Seal(chain consensus.ChainReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	h.logger.Trace("Seal starts running")
	calcElapsed := func(start mclock.AbsTime) time.Duration {
		now := mclock.Now()
		elapsed := time.Duration(now) - time.Duration(start)
		return elapsed
	}
	startElapased := mclock.Now()
	defer func() {
		elapsed := calcElapsed(startElapased)
		h.logger.Trace("Seal ends", "elapsed", common.PrettyDuration(elapsed))
	}()

	header := block.Header()

	// Sealing the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}

	h.logger.Info("HotStuff Geth")

	// Broadcast the aggPub first (Everytime updating the valset needs to do this again!)
	// TODO: We consider the change of valset every epoch in the future... --saber
	snap, err := h.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return err
	}
	if len(h.aggregatedKeyPair) < snap.ValSet.Copy().Size() {
		pubByte, err := h.aggregatedPub.MarshalBinary()
		if err != nil {
			return err
		}
		go h.EventMux().Post(hotstuff.SendingPubEvent{
			Payload: pubByte,
		})
	}
	select {
	case <-h.aggPubCh:
	case <-time.After(time.Second * time.Duration(params.SendPubTimeout)):
		// Won't stop here as we expect to receive more later
	}

	// Wait until sealing is terminated or delay timeout.
	delay := time.Unix(int64(block.Header().Time), 0).Sub(now()) // if delay is negative, runs immediately anyway
	h.logger.Trace("Waiting for slot to sign and propagate", "delay", common.PrettyDuration(delay))
	go func() {
		select {
		case <-stop:
			return
		case <-time.After(delay):
		}

		h.consenMu.Lock()
		h.proposedBlockHash = block.Hash()
		defer func() {
			h.proposedBlockHash = common.Hash{}
			h.consenMu.Unlock()
		}()

		// Post Block into Hotstuff engine
		go h.EventMux().Post(hotstuff.RequestEvent{
			Proposal: block,
		})
		for {
			select {
			case result := <-h.commitCh:
				// if the block hash and the hash from channel are the same,
				// return the result. Otherwise, keep waiting the next hash.
				if result != nil && block.Hash() == result.Hash() {
					results <- result
					return
				}
				// This needs to add the chainHeadEvent channel to quit the goroutine --saber
			case <-stop:
				results <- nil
				return
			}
		}
		// Check goroutines to avoid memory leaks (for tests)
		// h.logger.Trace("Number of Goroutines", "number", runtime.NumGoroutine())
		// pprof.Lookup("goroutine").WriteTo(os.Stdout, 1) //Prints out goroutine stack

		// newBlock, err := h.Consensus(chain, block, stop)
		// if err != nil {
		// 	return err
		// }
		// h.closeChannels()

	}()
	return nil
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns the difficulty
// that a new block should have based on the previous blocks in the chain and the
// current signer.
func (h *backend) CalcDifficulty(chain consensus.ChainReader, time uint64, parent *types.Header) *big.Int {
	return big.NewInt(1)
}

// // Authorize injects a private key into the consensus engine to mint new blocks
// // with.
// func (h *backend) Authorize(signer common.Address, signFn func(accounts.Account, string, []byte) ([]byte, error)) {
// 	h.sigMu.Lock()
// 	defer h.sigMu.Unlock()

// 	h.signer = signer
// 	h.signFn = signFn
// 	h.SetAddress()
// }

// Close implements consensus.Engine. It's a noop for hotstuff
func (h *backend) Close() error {
	return nil
}

// APIs implements consensus.Engine, returning the user facing RPC API.
func (h *backend) APIs(chain consensus.ChainReader) []rpc.API {
	return []rpc.API{{
		Namespace: "hotstuff",
		Version:   "1.0",
		Service:   &API{chain: chain, hotstuff: h},
		Public:    false,
	}}
}

// SealHash returns the hash of a block prior to it being sealed.
func SealHash(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()

	rlp.Encode(hasher, types.HotStuffFilteredHeader(header, false))
	// encodeSigHeader(hasher, header)
	hasher.Sum(hash[:0])
	return hash
}

// SealHash returns the hash of a block prior to it being sealed.
func (h *backend) SealHash(header *types.Header) common.Hash {
	return SealHash(header)
}

// HotStuffRLP returns the rlp bytes which needs to be signed for the hotstuff
// sealing. The RLP to sign consists of the entire header apart from the 65 byte signature
// contained at the end of the extra data.
//
// Note, the method requires the extra data to be at least 65 bytes, otherwise it
// panics. This is done to avoid accidentally using both forms (signature present
// or not), which could be abused to produce different hashes for the same header.
func HotStuffRLP(header *types.Header) []byte {
	b := new(bytes.Buffer)
	rlp.Encode(b, types.HotStuffFilteredHeader(header, false))
	// encodeSigHeader(b, header)
	return b.Bytes()
}

// func encodeSigHeader(w io.Writer, header *types.Header) {
// 	err := rlp.Encode(w, []interface{}{
// 		header.ParentHash,
// 		header.UncleHash,
// 		header.Coinbase,
// 		header.Root,
// 		header.TxHash,
// 		header.ReceiptHash,
// 		header.Bloom,
// 		header.Difficulty,
// 		header.Number,
// 		header.GasLimit,
// 		header.GasUsed,
// 		header.Time,
// 		header.Extra[:len(header.Extra)-extraSeal], // Yes, this will panic if extra is too short
// 		header.MixDigest,
// 		header.Nonce,
// 	})
// 	if err != nil {
// 		panic("can't encode: " + err.Error())
// 	}
// }

// Start and Stop invoked in worker.go - start and stop
// Start implements consensus.HotStuff.Start
func (h *backend) Start(chain consensus.ChainReader, currentBlock func() *types.Block, hasBadBlock func(hash common.Hash) bool) error {
	h.coreMu.Lock()
	defer h.coreMu.Unlock()
	if h.coreStarted {
		return hotstuff.ErrStartedEngine
	}

	// clear previous data
	h.proposedBlockHash = common.Hash{}
	if h.commitCh != nil {
		close(h.commitCh)
	}
	h.commitCh = make(chan *types.Block, 1)
	if h.aggPubCh != nil {
		close(h.aggPubCh)
	}
	h.aggPubCh = make(chan struct{})

	h.chain = chain
	h.currentBlock = currentBlock
	h.hasBadBlock = hasBadBlock

	if err := h.core.Start(); err != nil {
		return err
	}

	h.coreStarted = true
	return nil
}

// Stop implements consensus.HotStuff.Stop
func (h *backend) Stop() error {
	h.coreMu.Lock()
	defer h.coreMu.Unlock()
	if !h.coreStarted {
		return hotstuff.ErrStoppedEngine
	}
	if err := h.core.Stop(); err != nil {
		return err
	}
	h.coreStarted = false
	return nil
}

// snapshot retrieves the authorization snapshot at a given point in time.
func (h *backend) snapshot(chain consensus.ChainReader, number uint64, hash common.Hash, parents []*types.Header) (*Snapshot, error) {
	// Search for a snapshot in memory or on disk for checkpoints
	var (
		headers []*types.Header
		snap    *Snapshot
	)
	for snap == nil {
		// If an in-memory snapshot was found, use that
		if s, ok := h.recents.Get(hash); ok {
			snap = s.(*Snapshot)
			break
		}
		// If an on-disk checkpoint snapshot can be found, use that
		if number%checkpointInterval == 0 {
			if s, err := loadSnapshot(h.config.Epoch, h.db, hash); err == nil {
				h.logger.Trace("Loaded voting snapshot form disk", "number", number, "hash", hash)
				snap = s
				break
			}
		}
		// If we're at block zero, make a snapshot
		if number == 0 {
			genesis := chain.GetHeaderByNumber(0)
			if err := h.VerifyHeader(chain, genesis, false); err != nil {
				return nil, err
			}
			hotStuffExtra, err := types.ExtractHotStuffExtra(genesis)
			if err != nil {
				return nil, err
			}
			// hotStuffExtra.Validators only exists in Genesis
			snap = newSnapshot(h.signatures, h.config.Epoch, 0, genesis.Hash(), validator.NewSet(hotStuffExtra.Validators, h.config.SpeakerPolicy))
			if err := snap.store(h.db); err != nil {
				return nil, err
			}
			h.logger.Trace("Stored genesis voting snapshot to disk")
			break
		}
		// No snapshot for this header, gather the header and move backward
		var header *types.Header
		if len(parents) > 0 {
			// If we have explicit parents, pick from there (enforced)
			header = parents[len(parents)-1]
			if header.Hash() != hash || header.Number.Uint64() != number {
				return nil, consensus.ErrUnknownAncestor
			}
			parents = parents[:len(parents)-1]
		} else {
			// No explicit parents (or no more left), reach out to the database
			header = chain.GetHeader(hash, number)
			if header == nil {
				return nil, consensus.ErrUnknownAncestor
			}
		}
		headers = append(headers, header)
		number, hash = number-1, header.ParentHash
	}
	// Previous snapshot found, apply any pending headers on top of it
	for i := 0; i < len(headers)/2; i++ {
		headers[i], headers[len(headers)-1-i] = headers[len(headers)-1-i], headers[i]
	}
	snap, err := snap.apply(headers)
	if err != nil {
		return nil, err
	}
	h.recents.Add(snap.Hash, snap)

	// If we've generated a new checkpoint snapshot, save to disk
	if snap.Number%checkpointInterval == 0 && len(headers) > 0 {
		if err = snap.store(h.db); err != nil {
			return nil, err
		}
		h.logger.Trace("Stored voting snapshot to disk", "number", snap.Number, "hash", snap.Hash)
	}
	return snap, err
}

// update timestamp and signature of the block based on its number of transactions
func (h *backend) updateBlock(parent *types.Header, block *types.Block) (*types.Block, error) {
	header := block.Header()
	// sign the hash
	seal, err := h.Sign(SealHash(header).Bytes())
	if err != nil {
		return nil, err
	}

	err = writeSeal(header, seal)
	if err != nil {
		return nil, err
	}

	return block.WithSeal(header), nil
}

// writeSeal writes the extra-data field of the given header with the given seals.
// suggest to rename to writeSeal.
func writeSeal(h *types.Header, seal []byte) error {
	if len(seal)%types.HotStuffExtraSeal != 0 {
		return errInvalidSignature
	}

	hotstuffExtra, err := types.ExtractHotStuffExtra(h)
	if err != nil {
		return err
	}

	hotstuffExtra.Seal = seal
	payload, err := rlp.EncodeToBytes(&hotstuffExtra)
	if err != nil {
		return err
	}

	h.Extra = append(h.Extra[:types.HotStuffExtraVanity], payload...)
	return nil
}
