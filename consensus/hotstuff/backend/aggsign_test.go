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
	"testing"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/sign"
	"go.dedis.ch/kyber/v3/sign/bdn"
	"go.dedis.ch/kyber/v3/util/random"
)

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
