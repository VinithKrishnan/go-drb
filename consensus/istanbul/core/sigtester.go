package main

import (
	"encoding/hex"
	"math/big"
	"reflect"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/istanbul"
	"github.com/ethereum/go-ethereum/core/types"
	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	ed25519 "github.com/ethereum/go-ethereum/filippo.io/edwards25519"
	elog "github.com/ethereum/go-ethereum/log"
	crypto "github.com/ethereum/go-ethereum/crypto"
)

var pubKeys map[common.Address]*ed25519.Point
var blspubKeys map[common.Address]*bn256.G2
var blsmemkeys map[common.Address]*bn256.G1
var addrIDMap map[common.Address]int
var idAddrMap map[int]common.Address
var addrs []string
var vals []common.Address
var edKey types.EdKey
var blsKey types.BLSKey
var logdir string


func init() {
	pkPath := "pubkey.json"
	blspkPath := "blspubkey.json"
	blsmkPath := "blsmemkey.json"
	edkeyPath := "key.json"
	blskeyPath := "blskey.json"

	local := true

	logdir = "/home/ubuntu/drb/"
	if local {
		edkeyPath = "/mnt/c/Users/VinithKrishnan/drb-expt/edkeys/k" + strconv.Itoa(0) + ".json"
		blskeyPath = "/mnt/c/Users/VinithKrishnan/drb-expt/blskeys/k" + strconv.Itoa(0) + ".json"

		logdir = "/mnt/c/Users/VinithKrishnan/drb-expt/drb/log/" // should be changed to variable ofr reproducability purpose
	}

	// initializing number of nodes an threshold
	// c.setNumNodesTh(len(vals))

	// Load the nodes from the config file.
	var ednodelist []string
	if err := common.LoadJSON(pkPath, &ednodelist); err != nil {
		elog.Error("Can't load node file", "path", pkPath, "error", err)

	}
	var blspknodelist []string
	if err := common.LoadJSON(blspkPath, &blspknodelist); err != nil {
		elog.Error("Can't load node file", "path", blspkPath, "error", err)

	}
	var blsmknodelist []string
	if err := common.LoadJSON(blsmkPath, &blsmknodelist); err != nil {
		elog.Error("Can't load node file", "path", blsmkPath, "error", err)

	}

	addrs = []string{"d1589d31c6674d5540be85baf60850bd39752e40", "9cc76c660e8679241090e69a967d17ea236e5bd3", "82ba6627a3453997fc46730e8dd54798f0253f00", "1d40498b6c909a40cba517e94f37692d54ea604f"}

	for _, s := range addrs {
		data, _ := hex.DecodeString(s)
		vals = append(vals, common.BytesToAddress(data))
	}

	pubKeys = make(map[common.Address]*ed25519.Point)
	blspubKeys = make(map[common.Address]*bn256.G2)
	blsmemkeys = make(map[common.Address]*bn256.G1)
	addrIDMap = make(map[common.Address]int)
	idAddrMap = make(map[int]common.Address)

	for i, val := range vals {
		addrIDMap[val] = i
		idAddrMap[i] = val
		pubKeys[val] = types.EdStringToPoint(ednodelist[i])
		blspubKeys[val] = types.G2StringToPoint(blspknodelist[i])
		blsmemkeys[val] = types.G1StringToPoint(blsmknodelist[i])
		elog.Trace("Initializing pkeys", "addr", val, "idx", i)
	}
	address := idAddrMap[0]
	// position := addrIDMap[address]

	// loads the key into the key of the user
	var edstrKey types.EdStringKey
	if err := common.LoadJSON(edkeyPath, &edstrKey); err != nil {
		elog.Error("Can't load node file", "path", edkeyPath, "error", err)

	}
	// log.Info("String Key is:", strKey)
	edKey = types.EdStringToKey(edstrKey)
	elog.Debug("Initializing local key", "addr", address, "pkey", edstrKey.Pkey)

	var BLSstrKey types.BLSStringKey
	if err := common.LoadJSON(blskeyPath, &BLSstrKey); err != nil {
		elog.Error("Can't load node file", "path", blskeyPath, "error", err)

	}
	// log.Info("String Key is:", strKey)
	blsKey = types.BLSStringToKey(BLSstrKey)
	elog.Debug("Initializing local key", "addr", address, "pkey", BLSstrKey.Mkey)

}


func TestBLSSign() {
	init()
	var pubkeys []*bn256.G2

	for _, value := range blspubKeys {
		pubkeys = append(pubkeys, value)
	}
	sig := crypto.BlsSign(pubkeys, &blsKey.Skey, &blsKey.Mkey, root.Bytes())
}

func main() {
	TestBLSSign()
}