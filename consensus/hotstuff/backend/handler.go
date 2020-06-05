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
	"errors"
	"io/ioutil"
	"math/big"
	"reflect"

	"github.com/ethereum/go-ethereum/core/types"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/hotstuff"
	// "github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/hashicorp/golang-lru"
)

const (
	NewBlockMsg = 0x07

	hotstuffMsg = 0x11
	// PrepareRequestMsg   = 0x12
	// PrepareResponseMsg  = 0x13
	// ChangeViewMsg       = 0x14
	// BroadcastNewViewMsg = 0x15 // This msg type can be deprecated if VRF is used.
)

var (
	// errDecodeFailed is returned when decode message fails
	errDecodeFailed = errors.New("fail to decode hotstuff message")
)

// Protocol implements consensus.Engine.Protocol
func (h *backend) Protocol() consensus.Protocol {
	return consensus.HotStuffProtocol
}

func (h *backend) decode(msg p2p.Msg) ([]byte, common.Hash, error) {
	var data []byte
	if err := msg.Decode(&data); err != nil {
		return nil, common.Hash{}, errDecodeFailed
	}

	return data, hotstuff.RLPHash(data), nil
}

// HandleMsg implements consensus.Handler.HandleMsg
func (h *backend) HandleMsg(addr common.Address, msg p2p.Msg) (bool, error) {
	h.coreMu.Lock()
	defer h.coreMu.Unlock()
	if msg.Code == hotstuffMsg {
		if !h.coreStarted {
			return true, hotstuff.ErrStoppedEngine
		}

		data, hash, err := h.decode(msg)
		if err != nil {
			return true, errDecodeFailed
		}
		// Mark peer's message
		ms, ok := h.recentMessages.Get(addr)
		var m *lru.ARCCache
		if ok {
			m, _ = ms.(*lru.ARCCache)
		} else {
			m, _ = lru.NewARC(inmemoryMessages)
			h.recentMessages.Add(addr, m)
		}
		m.Add(hash, true)

		// Mark self known message
		if _, ok := h.knownMessages.Get(hash); ok {
			return true, nil
		}
		h.knownMessages.Add(hash, true)

		go h.hotStuffEventMux.Post(hotstuff.MessageEvent{
			Payload: data,
		})
		return true, nil
	}
	if msg.Code == NewBlockMsg && h.core.IsSpeaker() { // eth.NewBlockMsg: import cycle
		// this case is to safeguard the race of similar block which gets propagated from other node while this node is proposing
		// as p2p.Msg can only be decoded once (get EOF for any subsequence read), we need to make sure the payload is restored after we decode it
		h.logger.Debug("Speaker received NewBlockMsg", "size", msg.Size, "payload.type", reflect.TypeOf(msg.Payload), "sender", addr)
		if reader, ok := msg.Payload.(*bytes.Reader); ok {
			payload, err := ioutil.ReadAll(reader)
			if err != nil {
				return true, err
			}
			reader.Reset(payload)       // ready to be decoded
			defer reader.Reset(payload) // restore so main eth/handler can decode
			var request struct {        // this has to be same as eth/protocol.go#newBlockData as we are reading NewBlockMsg
				Block *types.Block
				TD    *big.Int
			}
			if err := msg.Decode(&request); err != nil {
				h.logger.Debug("Speaker was unable to decode the NewBlockMsg", "error", err)
				return false, nil
			}
			newRequestedBlock := request.Block
			if newRequestedBlock.Header().MixDigest == types.HotStuffDigest && h.core.IsCurrentProposal(newRequestedBlock.Hash()) {
				h.logger.Debug("Speaker already proposed this block", "hash", newRequestedBlock.Hash(), "sender", addr)
				return true, nil
			}
		}
	}
	return false, nil
}

// SetBroadcaster implements consensus.Handler.SetBroadcaster
func (h *backend) SetBroadcaster(broadcaster consensus.Broadcaster) {
	h.broadcaster = broadcaster
}

func (h *backend) NewChainHead() error {
	return nil
}
