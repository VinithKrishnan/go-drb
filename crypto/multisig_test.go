package crypto

import (
	
	// // "errors"
	// // "strconv"
	// // "bytes"
	// // "unsafe"
	// "crypto/sha512"
	// "crypto/sha256"
	// "ed25519"
	// ed25519 "filippo.io/edwards25519"
	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"math/big"
	// "reflect"
	"testing"
	// "github.com/ethereum/go-ethereum/crypto/ed25519"
)

var NUM_NODES = 16
var RECOVERY_THRESHOLD = NUM_NODES/3 + 1


var MemKeys []*bn256.G1
var PublicKeys []*bn256.G2
var SecretKeys []*big.Int
var apk *bn256.G2
var apkbytes []byte
var message []byte


func init(){
 
	PublicKeys,SecretKeys,MemKeys = GroupSetup(NUM_NODES)
	apk,_ = KeyAgg(PublicKeys)
	apkbytes = apk.Marshal()
	message = []byte("benchmark message")

	

}


func BenchmarkBlsSign(b *testing.B){
	// message := []byte(" bls sign benchmark message")
	for i:=0;i<b.N;i++ {
		_ = BlsSign(apkbytes,SecretKeys[0],MemKeys[0],message)
	}
}


func BenchmarkSignAggregator(b *testing.B){
	var signlist []*bn256.G1
	var pubkeys []*bn256.G2
	for j:=0;j<(RECOVERY_THRESHOLD-1)*2+1;j++ {
		signlist = append(signlist,BlsSign(apkbytes,SecretKeys[j],MemKeys[j],message))
		pubkeys = append(pubkeys,PublicKeys[j])
	}
	b.ResetTimer()
	for i:=0;i<b.N;i++ {
		_,_ = SignAggregator(pubkeys,signlist)
	}

}

func BenchmarkSingleSignVer(b *testing.B){
	var nodelist[] int
	nodelist = append(nodelist,1)
	signature:= BlsSign(apkbytes,SecretKeys[0],MemKeys[0],message)
	b.ResetTimer()
	for i:=0;i<b.N;i++ {
		_ = Verify(nodelist,apk,message,PublicKeys[0],signature)
	}
}


func BenchmarkMultiSignVer(b *testing.B){
	var nodelist[] int
	var signlist []*bn256.G1
	var pubkeys []*bn256.G2
	for j:=0;j<(RECOVERY_THRESHOLD-1)*2+1;j++ {
		nodelist = append(nodelist,j+1)
		signlist = append(signlist,BlsSign(apkbytes,SecretKeys[j],MemKeys[j],message))
		pubkeys = append(pubkeys,PublicKeys[j])
	}
	aggpk,aggsig := SignAggregator(pubkeys,signlist)
	b.ResetTimer()
	for i:=0;i<b.N;i++ {
		_ = Verify(nodelist,apk,message,aggpk,aggsig)
	}


}