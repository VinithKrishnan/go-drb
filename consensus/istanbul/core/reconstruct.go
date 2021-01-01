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

	"github.com/ethereum/go-ethereum/consensus/istanbul"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ed25519"
	"github.com/ethereum/go-ethereum/log"
)

// sendReconstruct sends a reconstruction message for a particular view
func (c *core) sendReconstruct(view *istanbul.View) {
	logger := c.logger.New("state", c.state)
	seq := view.Sequence.Uint64()
	if aData, ok := c.nodeAggData[seq]; ok {
		index := c.addrIDMap[c.Address()]
		aCommit := aData.Points[index]
		encEval := aData.EncEvals[index] // aggregated encrypted data
		recData := crypto.ReconstructData(aCommit, encEval, c.edKey.Pkey, c.edKey.Skey)
		recData.Index = uint64(index)

		reconstruct, err := Encode(&istanbul.Reconstruct{
			View:    view,
			RecData: recData,
		})
		if err != nil {
			logger.Error("Failed to encode reconstruction message", "view", view)
			return
		}
		c.broadcast(&message{
			Code: msgReconstruct,
			Msg:  reconstruct,
		})
		logger.Debug("@drb, Broadcast recontstuction message", "number", seq, "index", index)
	}
}

// handleReconstruct reconstructs given enough share has been received
func (c *core) handleReconstruct(msg *message, src istanbul.Validator) error {
	index := c.getIndex(src.Address())
	log.Debug("Handling reconstruction message from", "addr", src.Address(), "index", index)

	var rmsg *istanbul.Reconstruct
	err := msg.Decode(&rmsg)
	if err != nil {
		log.Error("Reconstruct decoding failed", "from", src.Address(), "index", "err", err)
		return errFailedDecodeReconstruct
	}

	rSeq := rmsg.View.Sequence.Uint64()
	// Beacon output already available, no need to process further
	if _, rok := c.beacon[rSeq]; rok {
		return errHandleReconstruct
	}

	recon := rmsg.RecData
	rIndex := recon.Index
	rPkey := c.pubKeys[src.Address()]
	if err := crypto.ValidateReconstruct(rPkey, recon.DecShare, recon.Proof); err != nil {
		log.Error("Invalid reconstruct message", "from", src.Address(), "index", "err", err)
		return errInvalidReconstruct
	}
	c.addReconstruct(rSeq, rIndex, recon.DecShare)
	return errHandleReconstruct
}

// addReconstruct adds a reconstruction message
func (c *core) addReconstruct(seq, index uint64, share ed25519.Point) {
	if _, ok := c.nodeRecData[seq]; !ok {
		c.nodeRecData[seq] = make(map[uint64]ed25519.Point)
	}
	c.nodeRecData[seq][index] = share
	log.Debug("Added share for", "number", seq, "share", hex.EncodeToString(share.Val), "from", index)

	if len(c.nodeRecData[seq]) == c.threshold {
		output := crypto.RecoverBeacon(c.nodeRecData[seq], c.threshold)
		c.beacon[seq] = output
		log.Info("Beacon output for", "number", seq, "output", hex.EncodeToString(output.Val))
	}
}
