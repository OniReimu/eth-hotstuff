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

package types

import (
	"bytes"
	// "encoding/json"
	// "fmt"
	"reflect"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	// "github.com/ethereum/go-ethereum/rlp"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/sign"
	"go.dedis.ch/kyber/v3/sign/bdn"
	"go.dedis.ch/kyber/v3/util/random"
)

func TestHeaderHash(t *testing.T) {
	// 0x9e3ef2ec1e5d66c5d47018e08d1c1cca2990621d1fdc56596825a140d74b24ff
	expectedExtra := common.FromHex("0x0000000000000000000000000000000000000000000000000000000000000000f89af8549444add0ec310f115a0e603b2d7db9f067778eaf8a94294fc7e8f22b3bcdcf955dd7ff3ba2ed833f8212946beaaed781d2d2ab6350f5c4566a2c6eaac407a6948be76812f765c24641ec63dc2852b378aba2b440b8410000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0")
	expectedHash := common.HexToHash("0x9e3ef2ec1e5d66c5d47018e08d1c1cca2990621d1fdc56596825a140d74b24ff")

	// for hotstuff consensus
	header := &Header{MixDigest: HotStuffDigest, Extra: expectedExtra}
	if !reflect.DeepEqual(header.Hash(), expectedHash) {
		t.Errorf("expected: %v, but got: %v", expectedHash.Hex(), header.Hash().Hex())
	}

	// append useless information to extra-data
	unexpectedExtra := append(expectedExtra, []byte{1, 2, 3}...)
	header.Extra = unexpectedExtra
	if !reflect.DeepEqual(header.Hash(), rlpHash(header)) {
		t.Errorf("expected: %v, but got: %v", rlpHash(header).Hex(), header.Hash().Hex())
	}
}

func TestEncodeAndDecode(t *testing.T) {
	suite := bn256.NewSuite()
	_, public1 := bdn.NewKeyPair(suite, random.New())
	_, public2 := bdn.NewKeyPair(suite, random.New())

	mask, _ := sign.NewMask(suite, []kyber.Point{public1, public2}, nil)
	mask.SetBit(0, true)

	aggregatedKey, err := bdn.AggregatePublicKeys(suite, mask)
	if err != nil {
		t.Errorf("got: %v", err)
	}
	aggregatedKeyByte, err := aggregatedKey.MarshalBinary()
	if err != nil {
		t.Errorf("got: %v", err)
	}

	hst := &HotStuffExtra{
		SpeakerAddr: common.BytesToAddress(hexutil.MustDecode("0x44add0ec310f115a0e603b2d7db9f067778eaf8a")),
		Validators: []common.Address{
			common.BytesToAddress(hexutil.MustDecode("0x44add0ec310f115a0e603b2d7db9f067778eaf8a")),
			common.BytesToAddress(hexutil.MustDecode("0x294fc7e8f22b3bcdcf955dd7ff3ba2ed833f8212")),
			common.BytesToAddress(hexutil.MustDecode("0x6beaaed781d2d2ab6350f5c4566a2c6eaac407a6")),
			common.BytesToAddress(hexutil.MustDecode("0x8be76812f765c24641ec63dc2852b378aba2b440")),
		},
		Mask:          []byte{},
		AggregatedKey: aggregatedKeyByte,
		AggregatedSig: []byte{},
		Seal:          []byte{},
	}

	b := new(bytes.Buffer)
	if err = hst.EncodeRLP(b); err != nil {
		t.Errorf("got: %v", err)
	}

	// expectedKeyByte := common.FromHex("1234567890")
	// if !bytes.Equal(expectedKeyByte, b.Bytes()) {
	// 	t.Errorf("expected: %v, but got: %v, and the aggbytes: %v", expectedKeyByte, common.ToHex(b.Bytes()), common.ToHex(aggregatedKeyByte))
	// }

	vanity := bytes.Repeat([]byte{0x00}, HotStuffExtraVanity)
	h := &Header{Extra: append(vanity, b.Bytes()...)}
	HotStuffExtra, err := ExtractHotStuffExtra(h)
	if !reflect.DeepEqual(HotStuffExtra, hst) {
		t.Errorf("expected: %v, but got: %v", hst, HotStuffExtra)
	}
}

func TestExtractToHotStuff(t *testing.T) {
	testCases := []struct {
		vanity         []byte
		istRawData     []byte
		expectedResult *HotStuffExtra
		expectedErr    error
	}{
		{
			// normal case
			bytes.Repeat([]byte{0x00}, HotStuffExtraVanity),
			hexutil.MustDecode("0xf8f09444add0ec310f115a0e603b2d7db9f067778eaf8af8549444add0ec310f115a0e603b2d7db9f067778eaf8a94294fc7e8f22b3bcdcf955dd7ff3ba2ed833f8212946beaaed781d2d2ab6350f5c4566a2c6eaac407a6948be76812f765c24641ec63dc2852b378aba2b44080b8801b4f47e0a57dcb7452cb6821391981f88ffad22ddce62ff1dbfee08175129cfb3b6418f8a5e87be3d2cdf35ecf37447f1109705f7e07c798fabc34de43965e5f5c1f34317329a22c4bc3472163ab97af56642292797c71124e368956cd7c81f57b8e898252dd2aadf9a30dfe1d39888ae26608ba2cf88c97b9f5515c11fa2af68080"),
			&HotStuffExtra{
				SpeakerAddr: common.BytesToAddress(hexutil.MustDecode("0x44add0ec310f115a0e603b2d7db9f067778eaf8a")),
				Validators: []common.Address{
					common.BytesToAddress(hexutil.MustDecode("0x44add0ec310f115a0e603b2d7db9f067778eaf8a")),
					common.BytesToAddress(hexutil.MustDecode("0x294fc7e8f22b3bcdcf955dd7ff3ba2ed833f8212")),
					common.BytesToAddress(hexutil.MustDecode("0x6beaaed781d2d2ab6350f5c4566a2c6eaac407a6")),
					common.BytesToAddress(hexutil.MustDecode("0x8be76812f765c24641ec63dc2852b378aba2b440")),
				},
				Mask:          []byte{},
				AggregatedKey: common.FromHex("0x1b4f47e0a57dcb7452cb6821391981f88ffad22ddce62ff1dbfee08175129cfb3b6418f8a5e87be3d2cdf35ecf37447f1109705f7e07c798fabc34de43965e5f5c1f34317329a22c4bc3472163ab97af56642292797c71124e368956cd7c81f57b8e898252dd2aadf9a30dfe1d39888ae26608ba2cf88c97b9f5515c11fa2af6"),
				AggregatedSig: []byte{},
				Seal:          []byte{},
			},
			nil,
		},
		{
			// insufficient vanity
			bytes.Repeat([]byte{0x00}, HotStuffExtraVanity-1),
			nil,
			nil,
			ErrInvalidHotStuffHeaderExtra,
		},
	}
	for _, test := range testCases {
		h := &Header{Extra: append(test.vanity, test.istRawData...)}
		HotStuffExtra, err := ExtractHotStuffExtra(h)
		if err != test.expectedErr {
			t.Errorf("expected: %v, but got: %v", test.expectedErr, err)
		}
		if !reflect.DeepEqual(HotStuffExtra, test.expectedResult) {
			t.Errorf("expected: %v, but got: %v", test.expectedResult, HotStuffExtra)
		}
	}
}
