// key.go holds functions related to key recovery from various messages.

package backend

import (
	// "crypto/ecdsa"
	// "errors"
	// "fmt"
	// "io/ioutil"
	// "os"
	// "path/filepath"
	// "time"

	// "github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/hotstuff"
	"github.com/ethereum/go-ethereum/core/types"
	// "github.com/ethereum/go-ethereum/crypto"
	// "github.com/ethereum/go-ethereum/log"
	// "github.com/ethereum/go-ethereum/node"
	// "github.com/ethereum/go-ethereum/p2p/discover"
	lru "github.com/hashicorp/golang-lru"
)

// ecrecover extracts the Ethereum account address from a signed header. If header does not exist, store in the cache
func ecrecover(header *types.Header, sigcache *lru.ARCCache) (common.Address, error) {
	// If the signature's already cached, return that
	hash := header.Hash()
	if address, known := sigcache.Get(hash); known {
		return address.(common.Address), nil
	}
	// Retrieve the signature from the header extra-data
	if len(header.Extra) < extraSeal {
		return common.Address{}, errMissingSignature
	}
	hotstuffExtra, err := types.ExtractHotStuffExtra(header)
	if err != nil {
		return common.Address{}, err
	}
	signer, err := hotstuff.GetSignatureAddress(SealHash(header).Bytes(), hotstuffExtra.Seal)
	if err != nil {
		return signer, err
	}

	// signature := header.Extra[len(header.Extra)-extraSeal:] // getExtraSeal()

	// // Recover the public key and the Ethereum address
	// pubkey, err := crypto.Ecrecover(SealHash(header).Bytes(), signature)
	// if err != nil {
	// 	return common.Address{}, err
	// }
	// var signer common.Address
	// copy(signer[:], crypto.Keccak256(pubkey[1:])[12:])

	sigcache.Add(hash, signer)
	return signer, nil
}
