package types

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto/ed25519"
)

// StringKey is a secret key in the string format
type StringKey struct {
	Pkey string `json:"pkey"`
	Skey string `json:"skey"`
}

// Key consists of both public and private key of a node
type Key struct {
	Pkey ed25519.Point
	Skey ed25519.Scalar
}

// StringToKey converts a string to ed25519.Point
// TODO, @sourav implement this function
func StringToKey(strKey StringKey) Key {
	return Key{
		Pkey: ed25519.RawPoint(),
		Skey: ed25519.RawScalar(),
	}
}

// StringToPoint converts a string to ed25519.Point
// TODO, @sourav implement this function
func StringToPoint(str string) ed25519.Point {
	return ed25519.RawPoint()
}

// PolyCommit implements the polynomial commitment type
type PolyCommit struct {
	Round  int
	Root   common.Hash
	Sender common.Address
	Points ed25519.Points
}

// EncEval are encryptions of evaluation points
type EncEval struct {
	Round  int
	Root   common.Hash
	Sender common.Address
	Encs   ed25519.Points
}

// RoundData stores data received from the leader
type RoundData struct {
	Root     common.Hash
	IndexSet map[int]bool
	Commits  map[int]ed25519.Point
	EncEvals map[int]ed25519.Point
	Proofs   map[int]NizkProof
}

// NizkProof is a zk-knowledege of dleq
type NizkProof struct {
	Commit   ed25519.Point
	Chal     ed25519.Scalar
	Response ed25519.Scalar
}

// NizkProofs array of proofs
type NizkProofs []NizkProof
