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
	"bytes"
	"container/list"
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"golang.org/x/crypto/sha3"
)

func RLPHash(v interface{}) (h common.Hash) {
	hw := sha3.NewLegacyKeccak256()
	rlp.Encode(hw, v)
	hw.Sum(h[:0])
	return h
}

// GetSignatureAddress gets the signer address from the signature
func GetSignatureAddress(data []byte, sig []byte) (common.Address, error) {
	// 1. Keccak data
	hashData := crypto.Keccak256(data)
	// 2. Recover public key
	pubkey, err := crypto.SigToPub(hashData, sig)
	if err != nil {
		return common.Address{}, err
	}
	return crypto.PubkeyToAddress(*pubkey), nil
}

func CheckValidatorSignature(valSet ValidatorSet, data []byte, sig []byte) (common.Address, error) {
	// 1. Get signature address
	signer, err := GetSignatureAddress(data, sig)
	if err != nil {
		log.Error("Failed to get signer address", "err", err)
		return common.Address{}, err
	}

	// 2. Check validator
	if _, val := valSet.GetByAddress(signer); val != nil {
		return val.Address(), nil
	}

	return common.Address{}, ErrUnauthorizedAddress
}

// Returns the []byte form of []Address
func AddrToByteSlice(list []common.Address) []byte {
	addr_byte := make([]byte, 0, common.AddressLength*len(list))
	for _, addr := range list {
		addr_byte = append(addr_byte, addr[:]...)
	}
	return addr_byte
}

// Returns the []Address from []byte
func ByteToAddrSlice(addr_byte []byte) []common.Address {
	nums := len(addr_byte) / common.AddressLength
	addrList := make([]common.Address, 0, nums)
	for i := 0; i < nums; i++ {
		addrList = append(addrList, common.BytesToAddress(addr_byte[i*common.AddressLength:(i+1)*common.AddressLength]))
	}
	return addrList
}

//Turns a []byte into a printable hex format
func ByteToHexSlice(list []byte) []string {
	newList := ByteToAddrSlice(list)
	addrList := make([]string, 0, len(newList))
	for _, addr := range newList {
		addrList = append(addrList, addr.Hex())
	}
	return addrList
}

// Turns a []Address into a printable hex format
func AddrToHexSlice(list []common.Address) []string {
	addrList := make([]string, 0, len(list))
	for _, addr := range list {
		addrList = append(addrList, addr.Hex())
	}
	return addrList
}

func AddrSliceEqual(a, b []common.Address) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if !bytes.Equal(a[i][:], b[i][:]) {
			return false
		}
	}
	return true
}

//Sort a list of addresses in ascending order
func SortAddrAsc(addr []common.Address) []common.Address {
	sortedAddr := make([]common.Address, len(addr))
	copy(sortedAddr, addr)
	for i := 0; i < len(sortedAddr); i++ {
		for j := i + 1; j < len(sortedAddr); j++ {
			if bytes.Compare(sortedAddr[i][:], sortedAddr[j][:]) > 0 {
				sortedAddr[i], sortedAddr[j] = sortedAddr[j], sortedAddr[i]
			}
		}
	}
	return sortedAddr
}

func SortAddrDes(addr []common.Address) []common.Address {
	sortedAddr := make([]common.Address, len(addr))
	copy(sortedAddr, addr)
	for i := 0; i < len(sortedAddr); i++ {
		for j := i + 1; j < len(sortedAddr); j++ {
			if bytes.Compare(sortedAddr[i][:], sortedAddr[j][:]) < 0 {
				sortedAddr[i], sortedAddr[j] = sortedAddr[j], sortedAddr[i]
			}
		}
	}
	return sortedAddr
}

func AddrInSlice(addr common.Address, list []common.Address) bool {
	for _, v := range list {
		if v == addr {
			return true
		}
	}
	return false
}

func IndexInSlice(i int, s []uint64) bool {
	for _, v := range s {
		if int(v) == i {
			return true
		}
	}
	return false
}

func AddrIndex(addr common.Address, list []common.Address) int {
	for i, v := range list {
		if v == addr {
			return i
		}
	}
	return -1
}

func StringToUInt(str string) int64 {
	str_byte := []byte(str)
	var prod int64 = 1
	for _, i := range str_byte {
		prod *= int64(i)
	}
	return prod
}

func Max(a uint64, b uint64) uint64 {
	if a > b {
		return a
	} else {
		return b
	}
}

// ----------------------------------------------------------------------------

type Queue struct {
	queue *list.List
	size  int
}

func NewQueue(size int) *Queue {
	return &Queue{
		queue: list.New(),
		size:  size,
	}
}

func (q *Queue) Capacity() int {
	return q.size
}

func (q *Queue) Len() int {
	return q.queue.Len()
}

func (q *Queue) Empty() bool {
	return q.queue.Len() == 0
}

func (q *Queue) Full() bool {
	return q.queue.Len() == q.size
}

func (q *Queue) Enqueue(v interface{}) error {
	if q.Full() {
		return errors.New("Full queue")
	}
	q.queue.PushBack(v)
	return nil
}

func (q *Queue) Dequeue() (interface{}, error) {
	if q.Empty() {
		return nil, errors.New("Empty queue")
	}
	e := q.queue.Front()
	q.queue.Remove(e)
	return e.Value, nil
}

func (q *Queue) FullEnqueue(v interface{}) (interface{}, interface{}, error) {
	if !q.Full() {
		if err := q.Enqueue(v); err != nil {
			return nil, nil, err
		} else {
			first, err := q.GetFirst()
			if err != nil {
				return nil, nil, err
			}
			last, err := q.GetLast()
			if err != nil {
				return nil, nil, err
			}
			return first, last, nil
		}
	} else {
		q.Dequeue()
		if err := q.Enqueue(v); err != nil {
			return nil, nil, err
		} else {
			first, err := q.GetFirst()
			if err != nil {
				return nil, nil, err
			}
			last, err := q.GetLast()
			if err != nil {
				return nil, nil, err
			}
			return first, last, nil
		}
	}
}

func (q *Queue) GetFirst() (interface{}, error) {
	if q.Empty() {
		return nil, errors.New("Empty queue")
	}
	return q.queue.Front().Value, nil
}

func (q *Queue) GetLast() (interface{}, error) {
	if q.Empty() {
		return nil, errors.New("Empty queue")
	}
	return q.queue.Back().Value, nil
}
