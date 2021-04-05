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
	"encoding/hex"
	"fmt"
	"os"

	// "github.com/cloudflare/bn256"
	"github.com/ethereum/go-ethereum/consensus/istanbul"
	"github.com/ethereum/go-ethereum/crypto"

	// bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"

	// "github.com/ethereum/go-ethereum/crypto/ed25519"
	"github.com/ethereum/go-ethereum/common"
	ed25519 "github.com/ethereum/go-ethereum/filippo.io/edwards25519"
	"github.com/ethereum/go-ethereum/log"
)

// func (c *core) updateDecidedValues(seq uint64,digest common.Hash) {

// }
// sendReconstruct sends a reconstruction message for a particular view
func (c *core) sendReconstruct(seq uint64, digest common.Hash) {
	// TODO(@vinith):
	// Remove this from here
	// Compute this (once) on explicit request,
	// store it somewhere, and re-use on later request.
	nodelist, aggpk, aggsign := c.GenerateAggSig()
	aggpkbytes := aggpk.Marshal()
	aggsigbytes := aggsign.Marshal()
	c.nodeMu.Lock() // @Vinith:should i move this to commit()?
	aData, ok := c.nodeAggData[seq]

	c.nodeDecidedCommitCert[seq] = &istanbul.CommitCert{
		Nodelist: nodelist,
		Aggpk:    aggpkbytes,
		Aggsig:   aggsigbytes,
	}
	// remove till here

	c.nodeDecidedRoot[seq] = digest
	c.nodeMu.Unlock()
	log.Debug("Deciding commit cert", "Seq", seq, "nodelist", nodelist, "roothash in bytes", digest.Bytes(), "aggpk", aggpk, "aggsig", aggsign)
	if ok {
		index := c.addrIDMap[c.Address()]

		encEval := aData.EncEvals[index] // aggregated encrypted data
		recData := crypto.ReconstructData(encEval, c.edKey.Pkey, c.edKey.Skey)

		recData.Index = uint64(index)

		irecData := istanbul.RecDataEncode(recData)
		reconstruct, err := Encode(&istanbul.Reconstruct{
			Seq:     seq,
			RecData: irecData,
		})
		if err != nil {
			log.Error("Failed to encode reconstruction message", "number", seq)
			return
		}
		c.broadcast(&message{
			Code: msgReconstruct,
			Msg:  reconstruct,
		})
		log.Info("Broadcast recontstuction message", "number", seq)
	} else {
		log.Info("No private message received from leader yet.")
	}
}

// handleReconstruct reconstructs given enough share has been received
func (c *core) handleReconstruct(msg *message, src istanbul.Validator) error {
	c.nodeMu.Lock()
	defer c.nodeMu.Unlock()
	index := c.getIndex(src.Address())
	log.Debug("Handling reconstruction message from", "addr", src.Address(), "index", index)

	var rmsg *istanbul.Reconstruct
	err := msg.Decode(&rmsg)
	if err != nil {
		log.Error("Reconstruct decoding failed", "from", src.Address(), "index", "err", err)
		return errFailedDecodeReconstruct
	}

	rSeq := rmsg.Seq
	recon := istanbul.RecDataDecode(rmsg.RecData)
	rIndex := recon.Index

	if _, ok := c.nodeRecData[rSeq]; !ok {
		c.nodeRecData[rSeq] = make(map[uint64]*crypto.RecData)
	}
	c.nodeRecData[rSeq][rIndex] = &recon
	log.Debug("Added Reconstrcution data for", "number", rSeq, "from", rIndex)

	// Beacon output already available, no need to process further
	if _, rok := c.beacon[rSeq]; rok {
		return errHandleReconstruct
	}
	// check whether root has been decided or not
	_, rok := c.nodeDecidedRoot[rSeq]
	if !rok {
		// log.Error("PrePrepare message not received from leader")
		// c.SendReqMultiSig(rSeq, src.Address()) // should i make this synchronous?
		return errRootNotDecided

	}

	aData, aok := c.nodeAggData[rSeq]
	if !aok {
		// log.Error("Aggregate Data not received from leader")
		// c.SendReqMerklePath(rSeq, src.Address()) // should i make this asynchronous?
		return errAggDataNotFound
	}

	rPkey := c.pubKeys[src.Address()]
	encShare := aData.EncEvals[rIndex]

	if !crypto.ValidateReconstruct(*rPkey, encShare, recon.DecShare, recon.Proof) {
		log.Error("Invalid reconstruct message", "from", src.Address(), "index", rIndex)
		return errInvalidReconstruct
	}
	c.addReconstruct(rSeq, rIndex, recon.DecShare)
	return errHandleReconstruct
}

// addReconstruct adds a reconstruction message
func (c *core) addReconstruct(seq, index uint64, share ed25519.Point) {

	if _, ok := c.nodeConfShares[seq]; !ok {
		c.nodeConfShares[seq] = make(map[uint64]*ed25519.Point)
	}
	c.nodeConfShares[seq][index] = &share

	if len(c.nodeConfShares[seq]) == c.threshold {
		output := crypto.RecoverBeacon(c.nodeConfShares[seq], c.threshold)
		c.beacon[seq] = &output
		log.Info("Beacon output for", "number", seq, "output", hex.EncodeToString(output.Bytes()))

		// Logging handle prepare time
		rectime := c.logdir + "rectime"
		rectimef, err := os.OpenFile(rectime, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Error("Can't open rectimef  file", "error", err)
		}
		fmt.Fprintln(rectimef, seq, hex.EncodeToString(output.Bytes()), c.position, c.Now())
		rectimef.Close()
	}
}
