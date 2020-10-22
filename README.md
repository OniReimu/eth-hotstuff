## Geth-based HotStuff Consensus mechanism

Ethereumized HotStuff consensus mechanism.

Eth-hotstuff is an Ethereum-based distributed ledger protocol with the novel HotStuff consensus mechanism.

Eth-hotstuff is a fork of [go-ethereum](https://github.com/ethereum/go-ethereum) and is updated in line with go-ethereum releases. The current version is geth-1.9.13. 

Eth-hotstuff implements the framework of consensus engine of [Quorum](https://github.com/jpmorganchase/quorum).

Key enhancements over go-ethereum:

* __Higher Performance__ - Eth-hotstuff offers significantly higher performance throughput than public geth.
* [__Scalability__](https://arxiv.org/abs/1803.05069) - Eth-hotstuff offers the most scalable BFT-based consensus mechanism to support hundreds and thousands of validators in a network at the same time while remaining high throughput.
* __Alternative committee-picker__ - Eth-hotstuff offers multiple committee-pickers rather than the simple round-robin scheme.
	* __Round-Robin__
	* __Sticky__
	* __VRF__

## HotStuff - the most scalable BFT-based consensus mechanism ever since

The HotStuff consensus mechanism has been officialy used in [Facebook Libra](https://developers.libra.org/docs/state-machine-replication-paper). To the best of our knowledge, for the first time, HotStuff takes advantage of both the BFT-based and Nakamoto-based consensus mechanisms, extremely simplifies the implementation of the traditional BFT in Blockchains, in turn, achieves the most scalable BFT-based consensus mechanism ever since. 

#### Why most scalable?

* [__BLS-Multiple-Signature__](https://en.wikipedia.org/wiki/Boneh%E2%80%93Lynn%E2%80%93Shacham) - [Kyber](https://github.com/dedis/kyber) offers a comprehensive crypto library implementing BLS signature. By utilizing BLS signature, the (2f+1, N) aggregated signature can be used to replace the traditional communication among 2f+1 different validators with f indicating the number of attackers and N indicating the total number of validators, thus reducing the complexity down to O(n). Specifically, the steps are shown as below (or reading through this [unit test](https://github.com/dedis/kyber/blob/master/sign/bdn/bdn_test.go) will be most likely more friendly for some of you).
	* Each of the N validators generates its own aggregated private key with a (k, n) aggregated signature scheme being used where k = 2f+1. 
	* Only if the speaker (of a turn) has collected at least k signature secured by k private key from different validators, an aggregated signature can be finalized. As such, any messages can be confirmed being validated by k validators.
	* Any non-speaker (delegator) that has received the message attached with the aggregated signature sent back from the speaker has the ability to validate whether the message has been confirmed by at least 2f+1 validators in the network.

* __Chain-based-HotStuff__ - This is a very important property to simplify the BFT communication in Blockchains compared with the traditional BFT-based database. Accepting a new block and appending it to the local canonical chain can be thought as one turn of BFT communication because of the inherent chained structure of Blockchains. It turns out that by using the BLS signature and the chain-based property, the communication complexity can be replaced with an unconfirmation window of blocks (i.e., sacrificing the latency).

* __Three-Turn-Confirmation__ - The complexity can be boosted to O(N^3) for view change in existing BFT-based consensus mechanisms, e.g., PBFT and Zyzzyva, which significantly hinders the use in large-scale networks. Thus, the HotStuff consensus mechanism is thinking of having three consecutive rounds, i.e., Prepare, Pre-confirm, and Confirmed, to replace the high communication complexity of view change, shown as below.
![HotStuff Consensus Flow Chart](https://github.com/OniReimu/eth-hotstuff/blob/master/docs/hotstuff.png)
This implies that an unconfirmation window (used in PoW) will be implemented even though the HotStuff is a BFT-based consensus mechanism. Taking advantage of the BLS signature and the chain-based property, a view change can be done by having the block (view = 1) to reorganize the __second__ latest block.

* __Alternative committee-picker__ - Turns out that the HotStuff is independent to the committee-picker. 

By reducing the communication complexity to O(N), a scalable BFT-based consensus mechanism can be achieved in large-scale networks.

## TODO (updated on 22/10/2020)

- [x] Coding
- [x] Unit test
- ~~[ ] Peer reviewed by Kevin~~
- [ ] Run unit test and pressure test
- [ ] Consensus engine APIs
- [ ] VRF committee-picker
- [ ] Others


## Contribution

Thank you for considering to help out with the source code! We welcome contributions
from anyone on the internet, and are grateful for even the smallest of fixes!


## License

The go-ethereum library (i.e. all code outside of the `cmd` directory) is licensed under the
[GNU Lesser General Public License v3.0](https://www.gnu.org/licenses/lgpl-3.0.en.html), also
included in our repository in the `COPYING.LESSER` file.

The go-ethereum binaries (i.e. all code inside of the `cmd` directory) is licensed under the
[GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.en.html), also included
in our repository in the `COPYING` file.
