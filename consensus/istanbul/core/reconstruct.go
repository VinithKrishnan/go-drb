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
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/istanbul"
	"github.com/ethereum/go-ethereum/log"
)

/**
* 1. Fetch the message based on round number.
* 2. Aggregate the shares.
* 3. Generate proof.
* 4. broadcast it to everyone
**/
func (c *core) sendReconstruct(view *istanbul.View, digest common.Hash) {
	c.broadcast(&message{
		Code: msgReconstruct,
	})
}

/**
* 1. Check if already validated based on index
* 2. Validate
* 3. Upon succesful validation, add to the list
* 4. If more than t+1 valid shares, reconstruct!
**/
func (c *core) handleReconstruct(msg *message, src istanbul.Validator) error {
	index := c.getIndex(src.Address())
	log.Info("@drb ", "addr", src.Address(), "index", index)
	return nil
}
