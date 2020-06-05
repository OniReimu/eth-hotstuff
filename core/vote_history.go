package core

import (
	// "fmt"
	// "bytes"

	avl "github.com/emirpasic/gods/trees/avltree"
	"github.com/emirpasic/gods/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/log"
)

//A max function for uint64
func max(a, b uint64) uint64 {
	if a > b {
		return a
	} else {
		return b
	}
}

// Used to query the past vote history of a blockchain, as well as fast lookup for the most recent
// vote (i.e. The current mining list)
type VoteHistory struct {
	chain       consensus.ChainReader
	tree        *avl.Tree
	last        uint64
	voteListMap map[uint64]([]common.Address)
}

//Initialise a VoteHistory struct
func (vh *VoteHistory) init(chain consensus.ChainReader) {
	vh.chain = chain
	vh.tree = avl.NewWith(utils.UInt64Comparator)

	//Add genesis into the tree
	genesis := chain.GetHeaderByNumber(0)
	genesisList := genesis.SignerList()
	vh.voteListMap = make(map[uint64]([]common.Address))
	vh.voteListMap[uint64(0)] = genesisList

	vh.tree.Put(uint64(1), uint64(1))

	//Add most recent snapshot into the tree
	header := vh.chain.CurrentHeader()
	number := header.Number.Uint64()
	vh.last = vh.GetPastVoteNum(number + 1) //Need this to include the current block as well
	if vh.last != 0 {
		voteHeader := vh.chain.GetHeaderByNumber(uint64(vh.last))
		vh.voteListMap[vh.last] = voteHeader.SignerList()
		vh.tree.Put(vh.last+1, max(vh.last+1, number))
	}
}

//Returns the blockNumber of the most recent votingList BEFORE the current block
//That is, the mining list when the current block was made.
//If the range (l,r) exists in the set, then that means that
//all blocks from a to b inclusive use the votingList from l-1
func (vh *VoteHistory) GetPastVoteNum(num uint64) uint64 {
	//If genesis block, then just return itself
	if num == 0 {
		return 0
	}

	//Get the previous voteRange
	voteRange, ok := vh.tree.Floor(num)
	if !ok {
		log.Error("Could not find previous vote")
		return 0
	}
	rangeLeft := voteRange.Key.(uint64)
	rangeRight := voteRange.Value.(uint64)

	//If inside the range, then just return the range
	if rangeLeft <= num && num <= rangeRight {
		return rangeLeft - 1
	}

	//Loop backwards until a voteBlock is found, or entered the voteRange
	for i := num - 1; i >= rangeRight; i-- {
		header := vh.chain.GetHeaderByNumber(i)
		if header.IsVotingBlock() {
			//Insert new range onto chain, and return location of the voteBlock.
			vh.tree.Put(i+1, num)
			vh.voteListMap[i] = header.SignerList()
			return i
		}
	}

	//Reached end, update the previous range, and return the voteBlock
	vh.tree.Put(rangeLeft, num)
	return rangeLeft - 1
}

//Returns the blockNumber of the most recent votingList BEFORE the current block
//This uses the AVL tree, or its most recent record depending on which is faster
func (vh *VoteHistory) GetLastVote(num uint64) []common.Address {
	//If requesting the most recent one, then just return it
	var pastVote uint64
	if num > vh.last {
		pastVote = vh.last
	} else {
		pastVote = vh.GetPastVoteNum(num)

	}
	// log.Error("GetLastVote", "Query", num, "Returned", common.AddrToHexSlice(vh.voteListMap[pastVote]))
	addrList := vh.voteListMap[pastVote]

	return addrList
}

// Updates the VoteHistory struct whenever a new votingBlock is submitted.
func (vh *VoteHistory) UpdateLast(num uint64, voteList []common.Address) {
	//Update the slice
	vh.last = num
	vh.voteListMap[num] = make([]common.Address, len(voteList))
	copy(vh.voteListMap[num], voteList)

	//Update the tree
	voteRange := vh.tree.Right()
	rangeLeft := voteRange.Key.(uint64)
	vh.tree.Put(rangeLeft, num)
	vh.tree.Put(num+1, num+1)
}
