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

package core

import (
	"fmt"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/istanbul"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ed25519"
	"github.com/ethereum/go-ethereum/log"
)

func (c *core) sendPreprepare(request *istanbul.Request) {
	logger := c.logger.New("state", c.state)
	// If I'm the proposer and I have the same sequence with the proposal
	if c.current.Sequence().Cmp(request.Proposal.Number()) == 0 {
		// sending polynomial commitment to the leader
		seq := c.current.Sequence().Uint64()
		if seq > c.startSeq-c.forwardSeq {
			c.sendCommitment(c.forwardSeq)
		}
		if c.IsProposer() {
			curView := c.currentView()
			root := common.Hash{}
			// checking whether the node already has the required data or not
			if seq > c.startSeq {
				c.leaderMu.RLock()
				penLen := len(c.penRoots)
				c.leaderMu.RUnlock()
				done := false

				// Noting down number of available commitments at a leader.
				pentime := c.logdir + "pentime"
				pentimef, err := os.OpenFile(pentime, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if err != nil {
					log.Error("Can't open rcmtime  file", "error", err)
				}
				fmt.Fprintln(pentimef, seq, penLen, c.address.Hex(), c.Now())
				pentimef.Close()

				if penLen == 0 {
					log.Debug("Waiting for commitments", "sequenc", seq, "ldeader", c.Address())
					for {
						select {
						// TODO(sourav): double check for its correctness
						case <-c.commitmentCh:
							c.leaderMu.RLock()
							if len(c.penRoots) > 0 {
								done = true
							}
							c.leaderMu.RUnlock()
						}
						if done {
							break
						}
					}
				}
				c.leaderMu.RLock()
				root = c.penRoots[0]
				cData := c.penAggData[root]
				bisets := c.getByteIndexSets(c.penIndexSets[root])
				request.Proposal.UpdateDRB(bisets, cData)
				c.penRoots = c.penRoots[1:] // deleting pending root
				c.leaderMu.RUnlock()
				go c.sendPrivateData(curView, root)
			}

			preprepare, err := Encode(&istanbul.Preprepare{
				View:     curView,
				Proposal: request.Proposal,
			})
			if err != nil {
				logger.Error("Failed to encode", "view", curView)
				return
			}
			c.broadcast(&message{
				Code: msgPreprepare,
				Msg:  preprepare,
			})
			// logging proposal sending time
			sprptime := c.logdir + "sprptime"
			sprptimef, err := os.OpenFile(sprptime, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				log.Error("Can't open sprptimef  file", "error", err)
			}
			fmt.Fprintln(sprptimef, curView.Sequence.Uint64(), root.Hex(), c.address.Hex(), c.Now())
			sprptimef.Close()
		}
	}
}

// getByteIndexSets returns a bytearray
func (c *core) getByteIndexSets(aisets []common.Address) []byte {
	bsets := make([]byte, len(aisets))
	for i, addr := range aisets {
		bsets[i] = byte(c.addrIDMap[addr])
	}
	return bsets
}

// getIntIndexSets returns an integer array of the indexSets
func (c *core) getIntIndexSets(aisets []common.Address) []int {
	isets := make([]int, len(aisets))
	for i, addr := range aisets {
		isets[i] = c.addrIDMap[addr]
	}
	return isets
}

// sendPrivateData sends private appropriate private data to each node!
func (c *core) sendPrivateData(view *istanbul.View, root common.Hash) {
	c.leaderMu.RLock()
	defer c.leaderMu.RUnlock()
	for raddr, rData := range c.penPrivData[root] {
		go c.sendPrivateDataNode(view, raddr, rData)
	}
}

// sendPrivateDataNode sends private data to a individual node
func (c *core) sendPrivateDataNode(view *istanbul.View, rcvAddr common.Address, rData crypto.RoundData) {
	logger := c.logger.New("state", c.state)
	pData, err := Encode(&istanbul.PrivateData{
		View:  view,
		RData: rData,
	})
	if err != nil {
		logger.Error("Failed to encode pData", "err", err)
	}
	c.sendToNode(rcvAddr, &message{
		Code: msgPrivateData,
		Msg:  pData,
	})
	log.Debug("Send private data", "receiver", rcvAddr, "number", view.Sequence.Uint64())
}

// sendCommitment sends the commitment to the leader of the round
func (c *core) sendCommitment(fwd uint64) {
	logger := c.logger.New("state", c.state)
	_, lastProposer := c.backend.LastProposal()
	leader := c.valSet.GetFutProposer(lastProposer, fwd, c.current.Round().Uint64())
	nData := crypto.ShareRandomSecret(c.getPubKeys(), c.numNodes, c.threshold, ed25519.Random())
	nData.Sender = c.address

	// creating a commitment using a nData
	commitment, err := Encode(&istanbul.Commitment{
		NData: nData,
	})
	if err != nil {
		logger.Error("Failed to encode commitment", "fwd", fwd)
		return
	}
	// send commitment to leader
	self := leader == c.Address()
	c.sendToNode(leader, &message{
		Code: msgCommitment,
		Msg:  commitment,
	})
	scmtime := c.logdir + "scmtime"
	scmtimef, err := os.OpenFile(scmtime, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Error("Can't open scmtime  file", "error", err)
	}
	fmt.Fprintln(scmtimef, c.current.Sequence().Uint64(), leader.Hex(), c.address.Hex(), c.Now())
	scmtimef.Close()
	log.Debug("Sending commitment", "leader", leader, "self", self)
}

// handleCommitment validates a received commitment and stores in a local
// data structure
func (c *core) handleCommitment(msg *message, src istanbul.Validator) error {
	index := c.getIndex(src.Address())
	log.Debug("Handling commitment from", "src", src.Address(), "index", index)

	var cmsg *istanbul.Commitment
	err := msg.Decode(&cmsg)
	if err != nil {
		log.Error("Commitment decoding failed", "from", src.Address(), "index", index, "err", err)
		return errFailedDecodeCommitment
	}

	comm := cmsg.NData
	if err := crypto.ValidateCommit(false, comm, c.getPubKeys(), c.numNodes, c.threshold); err != nil {
		log.Error("Invalid commitment", "from", src.Address(), "index", index, "number", comm.Round, "err", err)
		return errInvalidCommitment
	}

	rcmtime := c.logdir + "rcmtime"
	rcmtimef, err := os.OpenFile(rcmtime, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Error("Can't open rcmtime  file", "error", err)
	}
	fmt.Fprintln(rcmtimef, c.current.Sequence().Uint64(), src.Address().Hex(), c.address.Hex(), c.Now())
	rcmtimef.Close()

	// Notifying send preprepare thread to propose
	if aggregated := c.addCommitment(comm, src.Address()); aggregated {
		select {
		case c.commitmentCh <- struct{}{}:
		default:
		}
	}
	return errHandleCommitment
}

// addCommitment add commitments
func (c *core) addCommitment(com crypto.NodeData, sender common.Address) bool {
	// Locking state variables of leader
	c.leaderMu.Lock()
	defer c.leaderMu.Unlock()

	fidx := -1
	pLen := 0
	for idx, pendings := range c.penData {
		pLen++
		if _, ok := pendings[sender]; !ok {
			pendings[sender] = com
			fidx = idx
			break
		}
	}

	if fidx == -1 {
		fidx = pLen
		c.penData = append(c.penData, map[common.Address]crypto.NodeData{})
		c.penData[fidx][sender] = com
		// Returning false as we know that only one element is present in pending
		if c.threshold > 1 {
			return false
		}
	}

	if len(c.penData[fidx]) == c.threshold {
		c.aggregate(fidx)
		c.penData = append(c.penData[:fidx], c.penData[fidx+1:]...) // deleting from pending
		return true
	}
	return false
}

// aggregate aggregates t+1 polynomial into a single commitment
func (c *core) aggregate(idx int) {
	// This function assumes that leaderMu is alreagy locked
	var (
		isets  = make([]int, c.threshold)
		aisets = make([]common.Address, c.threshold)
		data   = make([]crypto.NodeData, c.threshold)
	)
	// prepare input for the aggregate functions
	pendings := c.penData[idx]
	i := 0
	for addr, nData := range pendings {
		isets[i] = c.addrIDMap[addr]
		aisets[i] = addr
		data[i] = nData
		i++
	}

	// invoke crypto AggregateCommit function
	aggData := crypto.AggregateCommit(c.numNodes, isets, data)
	root := aggData.Root
	c.penRoots = append(c.penRoots, root)
	c.penAggData[root] = aggData
	c.penIndexSets[root] = aisets
	c.penPrivData[root] = make(map[common.Address]crypto.RoundData)

	for raddr, ridx := range c.addrIDMap {
		var (
			commits  = make(crypto.Points, c.threshold)
			encEvals = make(crypto.Points, c.threshold)
			proofs   = make(crypto.NizkProofs, c.threshold)
		)

		// initializing round data for every node
		ii := 0
		for _, nData := range pendings {
			commits[ii] = nData.Points[ridx]
			encEvals[ii] = nData.EncEvals[ridx]
			proofs[ii] = nData.Proofs[ridx]
			ii++
		}
		c.penPrivData[root][raddr] = crypto.RoundData{
			Root:     root,
			IndexSet: aisets,
			Commits:  commits,
			EncEvals: encEvals,
			Proofs:   proofs,
		}
	}

	aggtime := c.logdir + "aggtime"
	aggtimef, err := os.OpenFile(aggtime, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Error("Can't open aggtime  file", "error", err)
	}
	fmt.Fprintln(aggtimef, idx, root.Hex(), c.address.Hex(), c.Now())
	aggtimef.Close()

	log.Debug("Aggregated commitment for", "root", root)
}

// handleAggregate initiates the procedure to handle aggregated message
func (c *core) handleAggregate(sender common.Address, aData crypto.NodeData) error {
	if !c.valSet.IsProposer(sender) {
		log.Error("Aggregate not from leader", "sender", sender, "leader", c.valSet.GetProposer())
		return errNotFromProposer
	}

	if err := crypto.ValidateCommit(true, aData, c.getPubKeys(), c.numNodes, c.threshold); err != nil {
		return err
	}

	// adding aggregated information to the dictionary
	c.nodeMu.Lock()
	c.nodeAggData[aData.Round] = aData
	c.nodeMu.Unlock()
	log.Info("Handled Aggregate", "number", aData.Round, "root", aData.Root)
	return nil
}

func (c *core) handlePrivateData(msg *message, src istanbul.Validator) error {
	logger := c.logger.New("from", src, "state", c.state)
	var pData *istanbul.PrivateData
	err := msg.Decode(&pData)
	if err != nil {
		logger.Error("Private data decoding error", "src", src.Address(), "error", err)
		return errFailedDecodePrivateData
	}

	if !c.valSet.IsProposer(src.Address()) {
		logger.Error("Private data not from proposer", "src", src.Address(), "leader", c.valSet.GetProposer())
		return errNotFromProposer
	}

	// TODO(sourav): validate private data
	seq := pData.View.Sequence.Uint64()
	c.nodePrivData[seq] = pData.RData

	prvtime := c.logdir + "prvtime"
	prvtimef, err := os.OpenFile(prvtime, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Error("Can't open prvtimef  file", "error", err)
	}
	fmt.Fprintln(prvtimef, seq, src.Address().Hex(), c.address.Hex(), pData.RData.Root.Hex(), c.Now())
	prvtimef.Close()

	// sending a signal to privDataCh about availability of data
	select {
	case c.privDataCh <- pData.View:
	default:
	}
	logger.Debug("Private Data added and notified!", "number", seq)
	return errHandlePrivData
}

func (c *core) handlePreprepare(msg *message, src istanbul.Validator) error {
	logger := c.logger.New("from", src, "state", c.state)

	// Decode PRE-PREPARE
	var (
		preprepare *istanbul.Preprepare
		aData      crypto.NodeData
	)

	err := msg.Decode(&preprepare)
	if err != nil {
		return errFailedDecodePreprepare
	}

	seq := preprepare.View.Sequence.Uint64()
	if seq > c.startSeq {
		// Create a NodeData using the Preprepare message
		aData = crypto.NodeData{
			Round:    seq,
			Sender:   src.Address(),
			Root:     preprepare.Proposal.RBRoot(),
			Points:   preprepare.Proposal.Commitments(),
			EncEvals: preprepare.Proposal.EncEvals(),
		}

		if err := c.handleAggregate(src.Address(), aData); err != nil {
			log.Error("Error in HandleAggregate", "src", src.Address(), "rnd", aData.Round, "err", err)
			return err
		}
	}

	// Ensure we have the same view with the PRE-PREPARE message
	// If it is old message, see if we need to broadcast COMMIT
	if err := c.checkMessage(msgPreprepare, preprepare.View); err != nil {
		if err == errOldMessage {
			// Get validator set for the given proposal
			valSet := c.backend.ParentValidators(preprepare.Proposal).Copy()
			previousProposer := c.backend.GetProposer(preprepare.Proposal.Number().Uint64() - 1)
			valSet.CalcProposer(previousProposer, preprepare.View.Round.Uint64())
			// Broadcast COMMIT if it is an existing block
			// 1. The proposer needs to be a proposer matches the given (Sequence + Round)
			// 2. The given block must exist
			if valSet.IsProposer(src.Address()) && c.backend.HasPropsal(preprepare.Proposal.Hash(), preprepare.Proposal.Number()) {
				c.sendCommitForOldBlock(preprepare.View, preprepare.Proposal.Hash())
				return nil
			}
		}
		log.Error("Error in check message", "err", err)
		return err
	}

	// Check if the message comes from current proposer
	if !c.valSet.IsProposer(src.Address()) {
		logger.Warn("Ignore preprepare messages from non-proposer")
		return errNotFromProposer
	}

	// Verify the proposal we received
	if duration, err := c.backend.Verify(preprepare.Proposal); err != nil {
		// if it's a future block, we will handle it again after the duration
		if err == consensus.ErrFutureBlock {
			logger.Info("Proposed block will be handled in the future", "err", err, "duration", duration)
			c.stopFuturePreprepareTimer()
			c.futurePreprepareTimer = time.AfterFunc(duration, func() {
				c.sendEvent(backlogEvent{
					src: src,
					msg: msg,
				})
			})
		} else {
			logger.Warn("Failed to verify proposal", "err", err, "duration", duration)
			c.sendNextRoundChange()
		}
		return err
	}
	// @sourav, Check validity of the recived proposal using the PVSS layer messages!
	// Here is about to accept the PRE-PREPARE
	if c.state == StateAcceptRequest {
		// Send ROUND CHANGE if the locked proposal and the received proposal are different
		if c.current.IsHashLocked() {
			if preprepare.Proposal.Hash() == c.current.GetLockedHash() {
				// Broadcast COMMIT and enters Prepared state directly
				c.acceptPreprepare(preprepare)
				c.setState(StatePrepared)
				c.sendCommit()
			} else {
				// Send round change
				c.sendNextRoundChange()
			}
		} else {

			// Logging handle prepare time
			rprptime := c.logdir + "rprptime"
			rprptimef, err := os.OpenFile(rprptime, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				log.Error("Can't open rprptimef  file", "error", err)
			}
			fmt.Fprintln(rprptimef, seq, src, c.address.Hex(), aData.Root.Hex(), c.Now())
			rprptimef.Close()

			if seq > c.startSeq {
				// handling preprepare message asynchrnously
				go c.handlePreprepareAsync(preprepare, aData.Round)
			} else {
				c.acceptPreprepare(preprepare)
				c.setState(StatePreprepared)
				c.sendPrepare()
			}
		}
	}
	return nil
}

func (c *core) handlePreprepareAsync(preprepare *istanbul.Preprepare, seq uint64) {
	// TODO(sourav): Check whether the private data sent by the leader corresponds
	// to the content of the propsal. Important to handle leader failures after
	// preprepare phase.
	c.nodeMu.RLock()
	_, ok := c.nodePrivData[seq]
	c.nodeMu.RUnlock()
	if !ok {
		done := false
		log.Debug("Waiting for private data from leader!")
		for {
			select {
			// TODO(sourav): We can change this to a bool value indicating
			// whether the leader sent correct data or not.
			case view := <-c.privDataCh:
				if view.Sequence.Uint64() == seq {
					done = true
				}
			}
			if done {
				break
			}
		}
	}
	// Either
	//   1. the locked proposal and the received proposal match
	//   2. we have no locked proposal
	c.acceptPreprepare(preprepare)
	c.setState(StatePreprepared)
	c.sendPrepare()
}

func (c *core) acceptPreprepare(preprepare *istanbul.Preprepare) {
	c.consensusTimestamp = time.Now()
	c.current.SetPreprepare(preprepare)
}
