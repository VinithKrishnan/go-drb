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

package istanbul

import (
	// "encoding/hex"
	"fmt"
	"io"
	"math/big"

	ed25519 "github.com/ethereum/go-ethereum/filippo.io/edwards25519"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	// "github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
)

// Proposal supports retrieving height and serialized block to be used during Istanbul consensus.
type Proposal interface {
	// Number retrieves the sequence number of this proposal.
	Number() *big.Int

	// Hash retrieves the hash of this proposal.
	Hash() common.Hash

	RBRoot() common.Hash
	Commitments() [][]byte
	EncEvals() [][]byte
	UpdateDRB([]byte, [][]byte, [][]byte, common.Hash)

	EncodeRLP(w io.Writer) error

	DecodeRLP(s *rlp.Stream) error

	String() string
}

type Request struct {
	Proposal Proposal
}

// View includes a round number and a sequence number.
// Sequence is the block number we'd like to commit.
// Each round has a number and is composed by 3 steps: preprepare, prepare and commit.
//
// If the given block is not accepted by validators, a round change will occur
// and the validators start a new round with round+1.
type View struct {
	Round    *big.Int
	Sequence *big.Int
}

// EncodeRLP serializes b into the Ethereum RLP format.
func (v *View) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, []interface{}{v.Round, v.Sequence})
}

// DecodeRLP implements rlp.Decoder, and load the consensus fields from a RLP stream.
func (v *View) DecodeRLP(s *rlp.Stream) error {
	var view struct {
		Round    *big.Int
		Sequence *big.Int
	}

	if err := s.Decode(&view); err != nil {
		return err
	}
	v.Round, v.Sequence = view.Round, view.Sequence
	return nil
}

func (v *View) String() string {
	return fmt.Sprintf("{Round: %d, Sequence: %d}", v.Round.Uint64(), v.Sequence.Uint64())
}

// Cmp compares v and y and returns:
//   -1 if v <  y
//    0 if v == y
//   +1 if v >  y
func (v *View) Cmp(y *View) int {
	if v.Sequence.Cmp(y.Sequence) != 0 {
		return v.Sequence.Cmp(y.Sequence)
	}
	if v.Round.Cmp(y.Round) != 0 {
		return v.Round.Cmp(y.Round)
	}
	return 0
}

type Preprepare struct {
	View     *View
	Proposal Proposal
}

// Reconstruct for the reconstruction phase
type Reconstruct struct {
	Seq     uint64
	RecData RecData
}

type NodeData struct {
	Round    uint64
	Root     common.Hash // Nil root indicates commitment phase poly. commitment
	Points   [][]byte
	EncEvals [][]byte
	Proofs   []NizkProof
}

type RoundData struct {
	Round    uint64
	Root     common.Hash
	IndexSet []common.Address
	Proofs   []NizkProof
}

type RecData struct {
	Index    uint64
	DecShare []byte
	Proof    NizkProof
}

type NizkProof struct {
	Commit   []byte
	EncEval  []byte
	Chal     []byte
	Response []byte
}

func PointsToBytes(points []ed25519.Point) [][]byte {
	total := len(points)
	var ipoints = make([][]byte, total)
	for i := 0; i < total; i++ {
		ipoints[i] = points[i].Bytes()
	}
	return ipoints
}

func BytesToPoints(ipoints [][]byte) []ed25519.Point {
	total := len(ipoints)
	var points = make([]ed25519.Point, total)
	for i := 0; i < total; i++ {
		point, _ := ed25519.NewIdentityPoint().SetBytes(ipoints[i])
		points[i] = *point
	}
	return points
}

func RecDataEncode(recData crypto.RecData) RecData {
	return RecData{
		Index:    recData.Index,
		DecShare: recData.DecShare.Bytes(),
		Proof:    getIProof(recData.Proof),
	}
}

func RecDataDecode(recData RecData) crypto.RecData {
	decShare, _ := ed25519.NewIdentityPoint().SetBytes(recData.DecShare)
	return crypto.RecData{
		Index:    recData.Index,
		DecShare: *decShare,
		Proof:    getCProof(recData.Proof),
	}
}

func RoundDataEncode(rData crypto.RoundData) RoundData {
	proofs := rData.Proofs
	total := len(proofs)
	var iproofs = make([]NizkProof, total)
	for i := 0; i < total; i++ {
		iproofs[i] = getIProof(proofs[i])
	}
	return RoundData{
		Round:    rData.Round,
		Root:     rData.Root,
		IndexSet: rData.IndexSet,
		Proofs:   iproofs,
	}
}

func RoundDataDecode(rData RoundData) crypto.RoundData {
	iproofs := rData.Proofs
	total := len(iproofs)
	proofs := make([]crypto.NizkProof, total)
	for i := 0; i < total; i++ {
		proofs[i] = getCProof(iproofs[i])
	}
	return crypto.RoundData{
		Round:    rData.Round,
		Root:     rData.Root,
		IndexSet: rData.IndexSet,
		Proofs:   proofs,
	}
}

func NodeDataEncode(nData crypto.NodeData) NodeData {
	points := nData.Points
	total := len(points)
	encEvals := nData.EncEvals
	proofs := nData.Proofs

	var (
		iPoints   = make([][]byte, total)
		iEncEvals = make([][]byte, total)
		iProofs   = make([]NizkProof, total)
	)

	for i := 0; i < total; i++ {
		iPoints[i] = points[i].Bytes()
		iEncEvals[i] = encEvals[i].Bytes()
		iProofs[i] = getIProof(proofs[i])
	}

	return NodeData{
		Round:    nData.Round,
		Root:     nData.Root,
		Points:   iPoints,
		EncEvals: iEncEvals,
		Proofs:   iProofs,
	}
	// for i := 0; i < total; i++ {
	// 	log.Info("pcompare", "cp", hex.EncodeToString(points[i].Bytes()), "ip", hex.EncodeToString(iPoints[i]))
	// 	log.Info("ccompare", "cc", hex.EncodeToString(encEvals[i].Bytes()), "ic", hex.EncodeToString(iEncEvals[i]))
	// }
}

func getIProof(proof crypto.NizkProof) NizkProof {
	return NizkProof{
		Commit:   proof.Commit.Bytes(),
		EncEval:  proof.EncEval.Bytes(),
		Chal:     proof.Chal.Bytes(),
		Response: proof.Response.Bytes(),
	}
	// log.Info("compar", "cp", hex.EncodeToString(proof.Commit.Bytes()), "ci", hex.EncodeToString(iproof.Commit))
	// log.Info("compar", "ce", hex.EncodeToString(proof.EncEval.Bytes()), "ie", hex.EncodeToString(iproof.EncEval))
	// log.Info("compar", "cc", hex.EncodeToString(proof.Chal.Bytes()), "ci", hex.EncodeToString(iproof.Chal))
	// log.Info("compar", "cr", hex.EncodeToString(proof.Response.Bytes()), "ci", hex.EncodeToString(iproof.Response))
}

func getCProof(proof NizkProof) crypto.NizkProof {
	commit, _ := ed25519.NewIdentityPoint().SetBytes(proof.Commit)
	encEval, _ := ed25519.NewIdentityPoint().SetBytes(proof.EncEval)
	chal, _ := ed25519.NewScalar().SetCanonicalBytes(proof.Chal)
	resp, _ := ed25519.NewScalar().SetCanonicalBytes(proof.Response)
	return crypto.NizkProof{
		Commit:   *commit,
		EncEval:  *encEval,
		Chal:     *chal,
		Response: *resp,
	}
}

func NodeDataDecode(nData NodeData) crypto.NodeData {
	points := nData.Points
	total := len(points)
	encEvals := nData.EncEvals
	proofs := nData.Proofs

	var (
		cPoints   = make([]ed25519.Point, total)
		cEncEvals = make([]ed25519.Point, total)
		cProofs   = make([]crypto.NizkProof, total)
	)

	for i := 0; i < total; i++ {
		cpoint, _ := ed25519.NewIdentityPoint().SetBytes(points[i])
		cPoints[i] = *cpoint
		enc, _ := ed25519.NewIdentityPoint().SetBytes(encEvals[i])
		cEncEvals[i] = *enc
		cProofs[i] = getCProof(proofs[i])
	}

	return crypto.NodeData{
		Round:    nData.Round,
		Root:     nData.Root,
		Points:   cPoints,
		EncEvals: cEncEvals,
		Proofs:   cProofs,
	}

	// for i := 0; i < total; i++ {
	// 	log.Info("dpcompare", "cp", hex.EncodeToString(cPoints[i].Bytes()), "ip", hex.EncodeToString(points[i]))
	// 	log.Info("dccompare", "cc", hex.EncodeToString(cEncEvals[i].Bytes()), "ic", hex.EncodeToString(encEvals[i]))
	// }
}

// Commitment is sent during the commitment phase
type Commitment struct {
	NData NodeData
}

// PrivateData has the data a leader privately sends to a node
type PrivateData struct {
	RData RoundData
}

// EncodeRLP serializes b into the Ethereum RLP format.
func (b *Preprepare) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, []interface{}{b.View, b.Proposal})
}

// DecodeRLP implements rlp.Decoder, and load the consensus fields from a RLP stream.
func (b *Preprepare) DecodeRLP(s *rlp.Stream) error {
	var preprepare struct {
		View     *View
		Proposal *types.Block
	}

	if err := s.Decode(&preprepare); err != nil {
		return err
	}
	b.View, b.Proposal = preprepare.View, preprepare.Proposal

	return nil
}

type Subject struct {
	View   *View
	Digest common.Hash
}

// EncodeRLP serializes b into the Ethereum RLP format.
func (b *Subject) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, []interface{}{b.View, b.Digest})
}

// DecodeRLP implements rlp.Decoder, and load the consensus fields from a RLP stream.
func (b *Subject) DecodeRLP(s *rlp.Stream) error {
	var subject struct {
		View   *View
		Digest common.Hash
	}

	if err := s.Decode(&subject); err != nil {
		return err
	}
	b.View, b.Digest = subject.View, subject.Digest
	return nil
}

func (b *Subject) String() string {
	return fmt.Sprintf("{View: %v, Digest: %v}", b.View, b.Digest.String())
}
