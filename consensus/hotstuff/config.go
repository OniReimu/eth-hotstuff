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
	"go.dedis.ch/kyber/v3/pairing/bn256"
)

type SpeakerPolicy uint64

const (
	RoundRobin SpeakerPolicy = iota
	Sticky
	VRF
)

type Config struct {
	RequestTimeout uint64        `toml:",omitempty"` // The timeout for each Istanbul round in milliseconds.
	BlockPeriod    uint64        `toml:",omitempty"` // Default minimum difference between two consecutive block's timestamps in second
	SpeakerPolicy  SpeakerPolicy `toml:",omitempty"` // The policy for speaker selection
	Test           bool          `toml:",omitempty"`
	Epoch          uint64        `toml:",omitempty"` // The number of blocks after which to checkpoint and reset the pending votes
	Suite          *bn256.Suite  `json:"suite"`      // A new suite generated for key distribution
	// AllowedFutureBlockTime uint64        `toml:",omitempty"` // Max time (in seconds) from current time allowed for blocks, before they're considered future blocks
}

var DefaultConfig = &Config{
	RequestTimeout: 20000,
	BlockPeriod:    5,
	SpeakerPolicy:  RoundRobin,
	Epoch:          30000,
	Test:           false,
}
