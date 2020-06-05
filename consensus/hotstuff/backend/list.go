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
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/hotstuff"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/ethdb"
)

func AddressListReader(chain consensus.ChainReader) []common.Address {
	genesis := chain.GetHeaderByNumber(0)
	signerList := genesis.SignerListByte()
	return hotstuff.ByteToAddrSlice(signerList)
}

func AddressListReaderDB(db ethdb.Database) []common.Address {
	hash := rawdb.ReadCanonicalHash(db, 0)
	genesis := rawdb.ReadHeader(db, hash, 0)
	signerList := genesis.SignerListByte()
	return hotstuff.ByteToAddrSlice(signerList)
}
