package types

import (
	"math/big"
	// "strings"

	"encoding/hex"

	// "github.com/ethereum/go-ethereum/crypto/ed25519"
	// "github.com/ethereum/go-ethereum/filippo.io/edwards25519"
	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	ed25519 "github.com/ethereum/go-ethereum/filippo.io/edwards25519"
	"github.com/ethereum/go-ethereum/log"
)

// StringKey is a secret key in the string format
type EdStringKey struct {
	Pkey string `json:"pkey"`
	Skey string `json:"skey"`
}

// StringKey is a secret key in the string format
type BLSStringKey struct {
	Mkey string `json:"mkey"`
	Skey string `json:"skey"`
}

// Key consists of both public and private key of a node
type EdKey struct {
	Pkey ed25519.Point
	Skey ed25519.Scalar
}

// Key consists of both public and private key of a node
type BLSKey struct {
	Mkey bn256.G1
	Skey big.Int
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
func EdStringToKey(strKey EdStringKey) EdKey {
	bPkey, err1 := hex.DecodeString(strKey.Pkey)
	bSkey, err2 := hex.DecodeString(strKey.Skey)

	pkey, err3 := ed25519.NewIdentityPoint().SetBytes(bPkey)
	skey, err4 := ed25519.NewScalar().SetCanonicalBytes(bSkey)

	if err1 != nil {
		log.Error("Error 1")
	}
	if err2 != nil {
		log.Error("Error 2")
	}
	if err3 != nil {
		log.Error("Error 3")
	}
	if err4 != nil {
		log.Error("Error 4")
	}
	return EdKey{
		Pkey: *pkey,
		Skey: *skey,
	}
}

// StringToKey converts a StringKey to public-private key parii
func BLSStringToKey(strKey BLSStringKey) BLSKey {
	bMkey, err1 := hex.DecodeString(strKey.Mkey)
	bSkey, err2 := hex.DecodeString(strKey.Skey)
	var mkey *bn256.G1
	_, err3 := mkey.Unmarshal(bMkey)
	skey := new(big.Int).SetBytes(bSkey)

	if err1 != nil {
		log.Error("Error 1")
	}
	if err2 != nil {
		log.Error("Error 2")
	}
	if err3 != nil {
		log.Error("Error 3")
	}

	return BLSKey{
		Mkey: *mkey,
		Skey: *skey,
	}
}

// StringToPoint converts a string to ed25519.Point
func EdStringToPoint(str string) *ed25519.Point {
	bPkey, _ := hex.DecodeString(str)
	pkey, _ := ed25519.NewIdentityPoint().SetBytes(bPkey)
	return pkey
}

// StringToPoint converts a string to bn256 point
func G2StringToPoint(str string) *bn256.G2 {
	bPkey, _ := hex.DecodeString(str)
	key := new(bn256.G2)
	_, _ = key.Unmarshal(bPkey)
	return key
}

// StringToPoint converts a string to bn256 point
func G1StringToPoint(str string) *bn256.G1 {
	bPkey, _ := hex.DecodeString(str)
	key := new(bn256.G1)
	_, _ = key.Unmarshal(bPkey)
	return key
}
