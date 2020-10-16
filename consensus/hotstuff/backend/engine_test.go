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

package backend

import (
	"bytes"
	"crypto/ecdsa"
	// "math/big"
	"reflect"
	"testing"
	// "time"

	"github.com/ethereum/go-ethereum/common"
	// "github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/hotstuff"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"

	"go.dedis.ch/kyber/v3/pairing/bn256"
)

// in this test, we can set n to 1, and it means we can process Istanbul and commit a
// block by one node. Otherwise, if n is larger than 1, we have to generate
// other fake events to process Istanbul.
func newBlockChain(n int) (*core.BlockChain, *backend) {
	config, genesis, nodeKeys := getGenesisAndKeys(n)
	memDB := rawdb.NewMemoryDatabase()
	// config := hotstuff.DefaultConfig

	// Use the first key as private key
	b, _ := New(config, nodeKeys[0], memDB).(*backend)
	genesis.MustCommit(memDB)
	blockchain, err := core.NewBlockChain(memDB, nil, genesis.Config, b, vm.Config{}, nil)
	if err != nil {
		panic(err)
	}
	b.Start(blockchain, blockchain.CurrentBlock, blockchain.HasBadBlock)
	snap, err := b.snapshot(blockchain, 0, common.Hash{}, nil)
	if err != nil {
		panic(err)
	}
	if snap == nil {
		panic("failed to get snapshot")
	}
	speakerAddr := snap.ValSet.GetSpeaker().Address()

	// find proposer key
	for _, key := range nodeKeys {
		addr := crypto.PubkeyToAddress(key.PublicKey)
		if addr.String() == speakerAddr.String() {
			b.privateKey = key
			b.signer = addr
		}
	}

	return blockchain, b
}

func getGenesisAndKeys(n int) (*hotstuff.Config, *core.Genesis, []*ecdsa.PrivateKey) {
	// Setup validators
	var nodeKeys = make([]*ecdsa.PrivateKey, n)
	var addrs = make([]common.Address, n)
	for i := 0; i < n; i++ {
		nodeKeys[i], _ = crypto.GenerateKey()
		addrs[i] = crypto.PubkeyToAddress(nodeKeys[i].PublicKey)
	}

	// generate genesis block
	genesis := core.DefaultGenesisBlock()
	genesis.Config = params.TestChainConfig

	// force enable HotStuff engine
	genesis.Config.HotStuff = &params.HotStuffConfig{}
	config := hotstuff.DefaultConfig
	genesis.Config.HotStuff.Test = true
	genesis.Config.HotStuff.Period = config.BlockPeriod
	genesis.Config.HotStuff.Suite = bn256.NewSuite()
	genesis.Config.HotStuff.SpeakerPolicy = uint64(config.SpeakerPolicy)

	config.Suite = genesis.Config.HotStuff.Suite
	config.Test = genesis.Config.HotStuff.Test

	genesis.Config.Ethash = nil
	genesis.Difficulty = defaultDifficulty
	genesis.Nonce = emptyNonce.Uint64()
	genesis.Mixhash = types.HotStuffDigest

	appendValidators(genesis, addrs)
	return config, genesis, nodeKeys
}

func appendValidators(genesis *core.Genesis, addrs []common.Address) {

	if len(genesis.ExtraData) < types.HotStuffExtraVanity {
		genesis.ExtraData = append(genesis.ExtraData, bytes.Repeat([]byte{0x00}, types.HotStuffExtraVanity)...)
	}
	genesis.ExtraData = genesis.ExtraData[:types.HotStuffExtraVanity]

	hst := &types.HotStuffExtra{
		SpeakerAddr:   common.Address{},
		Validators:    addrs,
		Mask:          []byte{},
		AggregatedKey: []byte{},
		AggregatedSig: []byte{},
		Seal:          bytes.Repeat([]byte{0x00}, types.HotStuffExtraSeal),
	}

	hstPayload, err := rlp.EncodeToBytes(&hst)
	if err != nil {
		panic("failed to encode hotstuff extra")
	}
	genesis.ExtraData = append(genesis.ExtraData, hstPayload...)
}

func makeHeader(parent *types.Block, config *hotstuff.Config) *types.Header {
	header := &types.Header{
		ParentHash: parent.Hash(),
		Number:     parent.Number().Add(parent.Number(), common.Big1),
		GasLimit:   core.CalcGasLimit(parent, parent.GasLimit(), parent.GasLimit()),
		GasUsed:    0,
		Extra:      parent.Extra(),
		Time:       parent.Time() + config.BlockPeriod,

		Difficulty: defaultDifficulty,
	}
	return header
}

func makeBlock(chain *core.BlockChain, engine *backend, parent *types.Block) *types.Block {
	block := makeBlockWithoutSeal(chain, engine, parent)
	stopCh := make(chan struct{})
	resultCh := make(chan *types.Block, 10)
	go engine.Seal(chain, block, resultCh, stopCh)
	blk := <-resultCh
	return blk
}

func makeBlockWithoutSeal(chain *core.BlockChain, engine *backend, parent *types.Block) *types.Block {
	header := makeHeader(parent, engine.config)
	engine.Prepare(chain, header)
	state, _ := chain.StateAt(parent.Root())
	block, _ := engine.FinalizeAndAssemble(chain, header, state, nil, nil, nil)
	return block
}

func TestPrepare(t *testing.T) {
	chain, engine := newBlockChain(1)
	header := makeHeader(chain.Genesis(), engine.config)
	err := engine.Prepare(chain, header)
	if err != nil {
		t.Errorf("error mismatch: have %v, want nil", err)
	}
	header.ParentHash = common.StringToHash("1234567890")
	err = engine.Prepare(chain, header)
	if err != consensus.ErrUnknownAncestor {
		t.Errorf("error mismatch: have %v, want %v", err, consensus.ErrUnknownAncestor)
	}
}

func TestSealStopChannel(t *testing.T) {
	chain, engine := newBlockChain(4)
	block := makeBlockWithoutSeal(chain, engine, chain.Genesis())
	stop := make(chan struct{}, 1)
	eventSub := engine.EventMux().Subscribe(hotstuff.RequestEvent{})
	eventLoop := func() {
		ev := <-eventSub.Chan()
		_, ok := ev.Data.(hotstuff.RequestEvent)
		if !ok {
			t.Errorf("unexpected event comes: %v", reflect.TypeOf(ev.Data))
		}
		stop <- struct{}{}
		eventSub.Unsubscribe()
	}
	go eventLoop()
	resultCh := make(chan *types.Block, 10)
	go func() {
		err := engine.Seal(chain, block, resultCh, stop)
		if err != nil {
			t.Errorf("error mismatch: have %v, want nil", err)
		}
	}()

	finalBlock := <-resultCh
	if finalBlock != nil {
		t.Errorf("block mismatch: have %v, want nil", finalBlock)
	}
}
