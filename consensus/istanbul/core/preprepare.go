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
		curView := c.currentView()
		// round := curView.Round.Uint64()
		seq := c.current.Sequence().Uint64()
		if seq > c.startSeq {
			c.sendCommitment(curView, seq)
		}
		if c.IsProposer() {
			// checking whether the node already has the required data or not
			if seq > c.startSeq {
				c.leaderMu.RLock()
				cData, ok := c.leaderAggData[seq]
				aisets, _ := c.indexSets[seq]
				c.leaderMu.RUnlock()
				bisets := c.getByteIndexSets(aisets)
				log.Debug("Waiting for commitments", "sequenc", seq, "ldeader", c.Address())

				done := false
				if !ok {
					for {
						select {
						// TODO(sourav): We can change this to a bool value indicating
						// whether the leader sent correct data or not.
						case view := <-c.commitmentCh:
							if view.Sequence.Uint64() == seq {
								c.leaderMu.RLock()
								cData = c.leaderAggData[seq]
								aisets = c.indexSets[seq]
								c.leaderMu.RUnlock()
								bisets = c.getByteIndexSets(aisets)
								done = true
							}
						}
						if done {
							break
						}
					}
				}
				// to update the blockheader with aggregated commitment
				request.Proposal.UpdateDRB(bisets, cData)
				go c.sendPrivateData(curView, cData.Root)
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
	var (
		round      = view.Sequence.Uint64()
		indexSets  = c.indexSets[round]
		leaderData = c.leaderData[round]
		// intISets   = c.getIntIndexSets(indexSets)
	)
	// For each recipient form a round data message and send it
	// TODO(sourav): Optimize this!
	for rcvAddr, rcvIndex := range c.addrIDMap {
		var (
			commits  crypto.Points
			encEvals crypto.Points
			proofs   crypto.NizkProofs
		)

		for _, addr := range indexSets {
			nData := leaderData[addr]
			commits = append(commits, nData.Points[rcvIndex])
			encEvals = append(encEvals, nData.EncEvals[rcvIndex])
			proofs = append(proofs, nData.Proofs[rcvIndex])
		}

		rData := crypto.RoundData{
			Round:    round,
			Root:     root,
			IndexSet: indexSets,
			Commits:  commits,
			EncEvals: encEvals,
			Proofs:   proofs,
		}
		go c.sendPrivateDataNode(view, rcvAddr, rData)
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
func (c *core) sendCommitment(view *istanbul.View, seq uint64) {
	logger := c.logger.New("state", c.state)
	leader := c.valSet.GetProposer().Address()
	nData := crypto.ShareRandomSecret(c.getPubKeys(), c.numNodes, c.threshold, ed25519.Random())
	nData.Sender = c.address
	nData.Round = seq

	// creating a commitment using a nData
	commitment, err := Encode(&istanbul.Commitment{
		View:  view,
		NData: nData,
	})
	if err != nil {
		logger.Error("Failed to encode commitment", "view", view)
		return
	}
	// send commitment to leader
	self := leader == c.Address()
	c.sendToNode(leader, &message{
		Code: msgCommitment,
		Msg:  commitment,
	})
	log.Info("Sending commitment", "number", seq, "leader", leader, "self", self)
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
	// Notifying send preprepare thread to propose
	if aggregated := c.addCommitment(comm, src.Address()); aggregated {
		select {
		case c.commitmentCh <- cmsg.View:
		default:
		}
		log.Debug("Aggregated commitment", "number", comm.Round)
	}
	return errHandleCommitment
}

// addCommitment add commitments
func (c *core) addCommitment(com crypto.NodeData, sender common.Address) bool {
	// Locking state variables of leader
	// c.leaderMu.Lock()
	// defer c.leaderMu.Unlock()

	seq := com.Round
	if _, ok := c.leaderData[seq]; !ok {
		c.leaderData[seq] = make(map[common.Address]crypto.NodeData)
		c.indexSets[seq] = []common.Address{}
	}
	if _, ok := c.leaderData[seq][sender]; !ok {
		c.leaderData[seq][sender] = com
		indexCount := len(c.indexSets[seq])
		if indexCount < c.threshold {
			c.indexSets[seq] = append(c.indexSets[seq], sender)
			indexCount = indexCount + 1
			log.Debug("Adding commitment", "number", com.Round, "count", indexCount, "from", sender)

			// If received enough votes for the current seq
			if indexCount == c.threshold && c.current.Sequence().Uint64() == seq {
				c.aggregate(seq)
				return true
			}
		}
	}
	return false
}

// aggregate aggregates t+1 polynomial into a single commitment
func (c *core) aggregate(round uint64) {
	// This function assumes that leaderMu is alreagy locked
	var (
		indexSets []int
		data      []crypto.NodeData
	)
	// prepare input for the aggregate functions
	dataMap := c.leaderData[round]
	for _, addr := range c.indexSets[round] {
		indexSets = append(indexSets, c.addrIDMap[addr])
		data = append(data, dataMap[addr])
	}

	// invoke crypto AggregateCommit function
	aggData := crypto.AggregateCommit(c.numNodes, indexSets, data)
	aggData.Round = round // update round information
	c.leaderAggData[round] = aggData
}

// handleAggregate initiates the procedure to handle aggregated message
func (c *core) handleAggregate(sender common.Address, aData crypto.NodeData) error {
	if c.valSet.GetProposer().Address() != sender {
		return errNotFromProposer
	}

	if err := crypto.ValidateCommit(true, aData, c.getPubKeys(), c.numNodes, c.threshold); err != nil {
		return err
	}

	// adding aggregated information to the nodeAggData dictionary
	if _, ok := c.nodeAggData[aData.Round]; !ok {
		c.nodeAggData[aData.Round] = aData
	}

	log.Info("Handled Aggregate", "number", aData.Round, "root", aData.Root)
	return nil
}

func (c *core) handlePrivateData(msg *message, src istanbul.Validator) error {
	logger := c.logger.New("from", src, "state", c.state)
	var pData *istanbul.PrivateData
	err := msg.Decode(&pData)
	if err != nil {
		logger.Error("Private data decoding error", "error", err)
		return errFailedDecodePrivateData
	}
	seq := pData.View.Sequence.Uint64()
	if _, ok := c.nodePrivData[seq]; !ok {
		c.nodePrivData[seq] = pData.RData
	}
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

	round := preprepare.View.Sequence.Uint64()
	if round > c.startSeq {
		// Create a NodeData using the Preprepare message
		aData = crypto.NodeData{
			Round:    round,
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

			if round > c.startSeq {
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

func (c *core) handlePreprepareAsync(preprepare *istanbul.Preprepare, round uint64) {
	// TODO(sourav): We may have to add a timer to avoid a deadlock
	// Wait till the node recieves private data from the leader
	if _, ok := c.nodePrivData[round]; !ok {
		done := false
		log.Debug("Waiting for private data from leader!")
		for {
			select {
			// TODO(sourav): We can change this to a bool value indicating
			// whether the leader sent correct data or not.
			case view := <-c.privDataCh:
				log.Debug("Received private data!", "around", round, "vround", view.Sequence.Uint64())
				if view.Sequence.Uint64() == round {
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
