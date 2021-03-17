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
	"reflect"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/istanbul"
	crypto "github.com/ethereum/go-ethereum/crypto"
	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
)

func (c *core) sendCommit(root common.Hash) {
	sub := c.current.Subject()
	c.broadcastCommit(sub, root)
}

func (c *core) sendCommitForOldBlock(view *istanbul.View, digest common.Hash) {
	sub := &istanbul.Subject{
		View:   view,
		Digest: digest,
	}
	c.broadcastCommit(sub, digest)
}

func (c *core) broadcastCommit(sub *istanbul.Subject, root common.Hash) {
	logger := c.logger.New("state", c.state)

	var pubkeys []*bn256.G2

	for _, value := range c.blspubKeys {
		pubkeys = append(pubkeys, value)
	}
	sig := crypto.BlsSign(pubkeys, &c.blsKey.Skey, &c.blsKey.Mkey, root.Bytes())
	encodedCommit, err := Encode(&istanbul.Commit{
		Sub:  sub,
		Root: root,
		Sign: sig,
	})
	if err != nil {
		logger.Error("Failed to encode", "commit", "in boradcastCommit")
		return
	}

	// for raddr, rID := range c.addrIDMap {
	// 	if rID == 0 {
	// 		go c.sendToNode(raddr, &message{
	// 			Code: msgCommit,
	// 			Msg:  encodedCommit,
	// 		})
	// 		break
	// 	}
	// }
	c.broadcast(&message{
		Code: msgCommit,
		Msg:  encodedCommit,
	})
}

func (c *core) handleCommit(msg *message, src istanbul.Validator) error {

	// Decode COMMIT message
	var commit *istanbul.Commit
	err := msg.Decode(&commit)
	if err != nil {
		return errFailedDecodeCommit
	}

	if err := c.checkMessage(msgCommit, commit.Sub.View); err != nil {
		return err
	}

	if err := c.verifyCommit(commit, src); err != nil {
		return err
	}

	c.acceptCommit(msg, src)

	// Commit the proposal once we have enough COMMIT messages and we are not in the Committed state.
	//
	// If we already have a proposal, we may have chance to speed up the consensus process
	// by committing the proposal without PREPARE messages.
	if c.current.Commits.Size() >= c.QuorumSize() && c.state.Cmp(StateCommitted) < 0 {
		// @sourav, Here we might have to add an event to start the reconsturction
		// phase of the protocol!
		// It might be easier to start the reconstruction somewhere else
		// as such a design will keep the consensus layer intact!
		// Still need to call LockHash here since state can skip Prepared state and jump directly to the Committed state.
		c.current.LockHash()

		nodelist, aggpk, aggsign := c.GenerateAggSig() // use c.current.Commits.Values() for list of msg and msg.Address() for address

		c.commit(commit.Sub.View.Sequence.Uint64(), commit.Sub.Digest, nodelist, aggpk, aggsign)
	}

	return nil
}

// verifyCommit verifies if the received COMMIT message is equivalent to our subject
func (c *core) verifyCommit(commit *istanbul.Commit, src istanbul.Validator) error {
	logger := c.logger.New("from", src, "state", c.state)

	sub := c.current.Subject()
	if !reflect.DeepEqual(commit.Sub, sub) {
		logger.Warn("Inconsistent subjects between commit and proposal", "expected", sub, "got", commit)
		return errInconsistentSubject
	}

	return nil
}

func (c *core) acceptCommit(msg *message, src istanbul.Validator) error {
	logger := c.logger.New("from", src, "state", c.state)

	// var commit *istanbul.Commit
	// err := msg.Decode(&commit)

	// if err != nil {
	// 	return errFailedDecodeCommit
	// }

	// encodedSubject, err := Encode(&istanbul.Subject{
	// 	View:   commit.Sub.View,
	// 	Digest: commit.Sub.Digest,
	// })

	// submsg := &message{
	// 	Code: msgCommit, //@Vinith using same message type here , is this alright?
	// 	Msg:  encodedSubject,
	// }

	// Add the COMMIT message to current round state
	if err := c.current.Commits.Add(msg); err != nil {
		logger.Error("Failed to record commit message", "msg", msg, "err", err)
		return err
	}

	return nil
}

func (c *core) GenerateAggSig() ([]int, *bn256.G2, *bn256.G1) {

	var nodelist []int
	var aggpk *bn256.G2
	var aggsig *bn256.G1
	var SignList []*bn256.G1
	var PkList []*bn256.G2
	for _, msg := range c.current.Commits.Values() {
		var commit *istanbul.Commit
		_ = msg.Decode(&commit)
		SignList = append(SignList, commit.Sign)
		PkList = append(PkList, c.blspubKeys[msg.Address])
		nodelist = append(nodelist, c.addrIDMap[msg.Address])
	}
	aggpk, aggsig = crypto.SignAggregator(PkList, SignList)

	return nodelist, aggpk, aggsig

}
