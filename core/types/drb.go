package types

import (
	"github.com/ethereum/go-ethereum/crypto/ed25519"
	"math/big"
	"strings"
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

// StringToKey converts a StringKey to public-private key parii
func StringToKey(strKey StringKey) Key {
	xy := strings.Split(strKey.Pkey, ":")
	xbint, _ := new(big.Int).SetString(xy[0], 10)
	ybint, _ := new(big.Int).SetString(xy[1], 10)
	sbint, _ := new(big.Int).SetString(strKey.Skey, 10)
	return Key{
		Pkey: ed25519.NewPoint(*xbint, *ybint),
		Skey: ed25519.NewScalar(*sbint),
	}
}

// StringToPoint converts a string to ed25519.Point
func StringToPoint(str string) ed25519.Point {
	// split string and then
	xy := strings.Split(str, ":")
	xbint, _ := new(big.Int).SetString(xy[0], 10)
	ybint, _ := new(big.Int).SetString(xy[1], 10)
	return ed25519.NewPoint(*xbint, *ybint)
}

// public_key(string format) = x:y // first line of key_i.txt in edkeys folder
// var xbint, _ = new(big.Int).SetString(x,10)
// var ybint, _ = new(big.Int).SetString(y,10)
// public_key(Point format)= NewPoint(xbtin.ybint)
// secret_key(string format) = s // second line of key_i.txt in edkeys folder. Also ,every line in pubkey.txt.
// var sbint, _ = new(big.Int).SetString(s,10)
// secret_key(Scalar format) = NewScalar(sbint)

// NewNodeData creates a new node data
// func NewNodeData(round uint64, addr common.Address) crypto.NodeData {
// 	return NodeData{
// 		Round:    round,
// 		Root:     common.Hash{},
// 		Sender:   addr,
// 		Points:   make(crypto.Points),
// 		EncEvals: make(crypto.Points),
// 		Proofs:   make(crypto.NizkProofs),
// 	}
// }
