package types

import (
	// "math/big"
	// "strings"

	"encoding/hex"

	// "github.com/ethereum/go-ethereum/crypto/ed25519"
	// "github.com/ethereum/go-ethereum/filippo.io/edwards25519"
	ed25519 "github.com/ethereum/go-ethereum/filippo.io/edwards25519"
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
// func StringToKey(strKey StringKey) Key {
// 	xy := strings.Split(strKey.Pkey, ":")
// 	xbint, _ := new(big.Int).SetString(xy[0], 10)
// 	ybint, _ := new(big.Int).SetString(xy[1], 10)
// 	sbint, _ := new(big.Int).SetString(strKey.Skey, 10)
// 	return Key{
// 		Pkey: ed25519.NewPoint(*xbint, *ybint),
// 		Skey: ed25519.NewScalar(*sbint),
// 	}
// }

// // StringToPoint converts a string to ed25519.Point
// func StringToPoint(str string) ed25519.Point {
// 	// split string and then
// 	xy := strings.Split(str, ":")
// 	xbint, _ := new(big.Int).SetString(xy[0], 10)
// 	ybint, _ := new(big.Int).SetString(xy[1], 10)
// 	return ed25519.NewPoint(*xbint, *ybint)
// }

// StringToKey converts a StringKey to public-private key parii
func StringToKey(strKey StringKey) Key {
	bPkey, _ := hex.DecodeString(strKey.Pkey)
	bSkey, _ := hex.DecodeString(strKey.Skey)

	pkey, _ := ed25519.NewIdentityPoint().SetBytes(bPkey)
	skey, _ := ed25519.NewScalar().SetCanonicalBytes(bSkey)
	return Key{
		Pkey: *pkey,
		Skey: *skey,
	}
}

// StringToPoint converts a string to ed25519.Point
func StringToPoint(str string) *ed25519.Point {
	bPkey, _ := hex.DecodeString(str)
	pkey, _ := ed25519.NewIdentityPoint().SetBytes(bPkey)
	return pkey
}
