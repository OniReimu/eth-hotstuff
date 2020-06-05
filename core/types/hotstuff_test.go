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

// func ExampleEncode() {
// 	suite := bn256.NewSuite()
// 	_, public1 := bdn.NewKeyPair(suite, random.New())
// 	pubd1, _ := public1.MarshalBinary()
// 	_, public2 := bdn.NewKeyPair(suite, random.New())
// 	pubd2, _ := public2.MarshalBinary()

// 	mask, _ := sign.NewMask(suite, []kyber.Point{public1, public2}, nil)
// 	mask.SetBit(0, true)
// 	mask.SetBit(1, true)

// 	hst := &HotStuffExtra{
// 		SpeakerAddr: common.BytesToAddress(hexutil.MustDecode("0x44add0ec310f115a0e603b2d7db9f067778eaf8a")),
// 		Validators: []common.Address{
// 			common.BytesToAddress(hexutil.MustDecode("0x44add0ec310f115a0e603b2d7db9f067778eaf8a")),
// 			common.BytesToAddress(hexutil.MustDecode("0x294fc7e8f22b3bcdcf955dd7ff3ba2ed833f8212")),
// 			common.BytesToAddress(hexutil.MustDecode("0x6beaaed781d2d2ab6350f5c4566a2c6eaac407a6")),
// 			common.BytesToAddress(hexutil.MustDecode("0x8be76812f765c24641ec63dc2852b378aba2b440")),
// 		},
// 		Mask: MaskMarshaling{
// 			Mask: mask.Mask(),
// 			Pubs: [][]byte{
// 				pubd1,
// 				pubd2,
// 			},
// 		},
// 		AggregatedSig: []byte{},
// 		Seal:          []byte{},
// 	}

// 	payload, _ := rlp.EncodeToBytes(&hst)
// 	fmt.Println(common.ToHex(payload))
// 	// Output: 0xf86e9444add0ec310f115a0e603b2d7db9f067778eaf8af8549444add0ec310f115a0e603b2d7db9f067778eaf8a94294fc7e8f22b3bcdcf955dd7ff3ba2ed833f8212946beaaed781d2d2ab6350f5c4566a2c6eaac407a6948be76812f765c24641ec63dc2852b378aba2b440c08080
// }

func TestMarshalBinary(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	private1, public1 := bdn.NewKeyPair(suite, random.New())
	sig1, err := bdn.Sign(suite, private1, msg)
	if err != nil {
		t.Errorf("got: %v", err)
	}
	mask, err := sign.NewMask(suite, []kyber.Point{public1}, nil)
	if err != nil {
		t.Errorf("got: %v", err)
	}
	mask.SetBit(0, true)

	// pub
	public1Byte, err := public1.MarshalBinary()
	if err != nil {
		t.Errorf("got: %v", err)
	}
	public1B := suite.G2().Point()
	err = public1B.UnmarshalBinary(public1Byte)
	if err != nil {
		t.Errorf("got: %v", err)
	}

	// aggsig
	aggregatedSig, err := bdn.AggregateSignatures(suite, [][]byte{sig1}, mask)
	if err != nil {
		t.Errorf("got: %v", err)
	}

	sig, err := aggregatedSig.MarshalBinary()
	if err != nil {
		t.Errorf("got: %v", err)
	}
	aggregatedSig2 := suite.G1().Point()
	err = aggregatedSig2.UnmarshalBinary(sig)
	if err != nil {
		t.Errorf("got: %v", err)
	}

	// aggkey
	aggregatedKey, err := bdn.AggregatePublicKeys(suite, mask)
	if err != nil {
		t.Errorf("got: %v", err)
	}
	aggregatedKeyByte, err := aggregatedKey.MarshalBinary()
	if err != nil {
		t.Errorf("got: %v", err)
	}
	aggregatedKey2 := suite.G2().Point()
	err = aggregatedKey2.UnmarshalBinary(aggregatedKeyByte)
	if err != nil {
		t.Errorf("got: %v", err)
	}
}

func TestAggregateSign(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	private1, public1 := bdn.NewKeyPair(suite, random.New())
	private2, public2 := bdn.NewKeyPair(suite, random.New())

	sig1, err := bdn.Sign(suite, private1, msg)
	if err != nil {
		t.Errorf("got: %v", err)
	}
	sig2, err := bdn.Sign(suite, private2, msg)
	if err != nil {
		t.Errorf("got: %v", err)
	}
	mask, _ := sign.NewMask(suite, []kyber.Point{public1, public2}, nil)
	mask.SetBit(0, true)
	mask.SetBit(1, true)

	aggregatedSig, err := bdn.AggregateSignatures(suite, [][]byte{sig1, sig2}, mask)
	if err != nil {
		t.Errorf("got: %v", err)
	}

	aggregatedKey, err := bdn.AggregatePublicKeys(suite, mask)
	if err != nil {
		t.Errorf("got: %v", err)
	}
	aggregatedKeyByte, err := aggregatedKey.MarshalBinary()
	if err != nil {
		t.Errorf("got: %v", err)
	}
	aggregatedKey2 := suite.G2().Point()
	err = aggregatedKey2.UnmarshalBinary(aggregatedKeyByte)
	if err != nil {
		t.Errorf("got: %v", err)
	}

	sig, err := aggregatedSig.MarshalBinary()
	if err != nil {
		t.Errorf("got: %v", err)
	}

	err = bdn.Verify(suite, aggregatedKey2, msg, sig)
	if err != nil {
		t.Errorf("got: %v", err)
	}
}

func TestEncodeAndDecode(t *testing.T) {
	suite := bn256.NewSuite()
	_, public1 := bdn.NewKeyPair(suite, random.New())
	_, public2 := bdn.NewKeyPair(suite, random.New())

	mask, _ := sign.NewMask(suite, []kyber.Point{public1, public2}, nil)
	// pubs := mask.Publics()
	// pub1, _ := pubs[0].MarshalBinary()
	// pub2, _ := pubs[1].MarshalBinary()
	// if len(pubs) != 2 {
	// 	t.Errorf("expected: %v, but got: %v", 2, len(pubs))
	// }
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
			hexutil.MustDecode("0xf858f8549444add0ec310f115a0e603b2d7db9f067778eaf8a94294fc7e8f22b3bcdcf955dd7ff3ba2ed833f8212946beaaed781d2d2ab6350f5c4566a2c6eaac407a6948be76812f765c24641ec63dc2852b378aba2b44080c0"),
			&HotStuffExtra{
				SpeakerAddr: common.BytesToAddress(hexutil.MustDecode("0x44add0ec310f115a0e603b2d7db9f067778eaf8a")),
				Validators: []common.Address{
					common.BytesToAddress(hexutil.MustDecode("0x44add0ec310f115a0e603b2d7db9f067778eaf8a")),
					common.BytesToAddress(hexutil.MustDecode("0x294fc7e8f22b3bcdcf955dd7ff3ba2ed833f8212")),
					common.BytesToAddress(hexutil.MustDecode("0x6beaaed781d2d2ab6350f5c4566a2c6eaac407a6")),
					common.BytesToAddress(hexutil.MustDecode("0x8be76812f765c24641ec63dc2852b378aba2b440")),
				},
				Mask:          []byte{},
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
