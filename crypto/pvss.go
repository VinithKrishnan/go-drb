package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"math/big"

	rnd "math/rand"

	"github.com/ethereum/go-ethereum/common"
	ed25519 "github.com/ethereum/go-ethereum/filippo.io/edwards25519"
	"github.com/ethereum/go-ethereum/onrik/gomerkle"

	// ed25519 "github.com/ethereum/go-ethereum/crypto/edwards25519"
	"github.com/ethereum/go-ethereum/log"
)

var TEMP, _ = new(big.Int).SetString("27742317777372353535851937790883648493", 10)
var GROUP_ORDER = new(big.Int).Add(new(big.Int).Exp(big.NewInt(2), big.NewInt(252), nil), TEMP)

var (
	errInvalidSanityCheck = errors.New("sanity check failed")
	errInvalidPolyCommit  = errors.New("Invalid polynomial commitment")
	errInvalidNIZK        = errors.New("Invalid NIZK proof")
)

// NodeData implements the polynomial commitment type
type NodeData struct {
	Round    uint64
	Root     common.Hash // Nil root indicates commitment phase poly. commitment
	Points   Points
	EncEvals Points
	Proofs   NizkProofs
	IndexSet []uint64
}

// RoundData stores data received from the leader
type RoundData struct {
	Round    uint64
	Root     common.Hash
	IndexSet []common.Address
	Proofs   NizkProofs
}

// NizkProof is a zk-knowledege of dleq
type NizkProof struct {
	Commit   ed25519.Point
	EncEval  ed25519.Point
	Chal     ed25519.Scalar
	Response ed25519.Scalar
}

// RecData is the reconstruction message of a node
type RecData struct {
	Index    uint64
	DecShare ed25519.Point
	Proof    NizkProof
}

type NizkProofs []NizkProof
type Points []ed25519.Point
type Scalars []ed25519.Scalar

var (
	ONE = ed25519.NewIdentityPoint()
	G   = PointG()
	H   = ed25519.NewGeneratorPoint()
)

func PointG() ed25519.Point {
	r := rnd.New(rnd.NewSource(int64(10)))
	v := new(big.Int).Rand(r, GROUP_ORDER)
	val := (*v).Bytes()
	for i, j := 0, len(val)-1; i < j; i, j = i+1, j-1 { // reversal of bytes
		val[i], val[j] = val[j], val[i]
	}
	for len(val) < 32 {
		val = append(val, 0)
	}
	tempsc, _ := ed25519.NewScalar().SetCanonicalBytes(val)
	return *ed25519.NewIdentityPoint().ScalarBaseMult(tempsc)
}

// Polynomial is defined as a list of scalars
type Polynomial struct {
	coeffs []*ed25519.Scalar
}

// Init Initializes polynomial with given coefficients
// func (p Polynomial) Init(s []*ed25519.Scalar) {
// 	copy(p.coeffs, s)
// }

// BintToScalar returns scalar given a big integer
func BintToScalar(v *big.Int) *ed25519.Scalar {
	val := v.Bytes()
	for i, j := 0, len(val)-1; i < j; i, j = i+1, j-1 { // reversal of bytes
		val[i], val[j] = val[j], val[i]
	}
	for len(val) < 32 {
		val = append(val, 0)
	}
	tempsc, _ := ed25519.NewScalar().SetCanonicalBytes(val)
	return tempsc
}

// Eval returns the polynomial evaluation point
func (p Polynomial) Eval(arg int) *ed25519.Scalar {
	x := BintToScalar(big.NewInt(int64(arg)))
	result := ed25519.NewScalar().Add(p.coeffs[0], ed25519.NewScalar().Multiply(x, p.coeffs[1]))
	xPow := ed25519.NewScalar().Set(x)
	for i := 2; i < len(p.coeffs); i++ {
		xPow.Multiply(xPow, x)
		result.Add(result, ed25519.NewScalar().Multiply(p.coeffs[i], xPow))
	}
	return result
}

// Random returns a random scalar
func Random() *ed25519.Scalar {
	v, _ := rand.Int(rand.Reader, GROUP_ORDER)
	return BintToScalar(v)
}

// RandomWithSecret returns a polynomial with random coefficients from Zq.
// p(x) = c_0 + c_1*x + ... c_{degree} * x^{degree}
func RandomWithSecret(degree int, secret *ed25519.Scalar) Polynomial {
	var coeffs = make([]*ed25519.Scalar, degree+1)
	coeffs[0] = ed25519.NewScalar().Set(secret)
	// coeffs = append(coeffs, secret)
	for i := 1; i <= degree; i++ {
		coeffs[i] = Random()
		// coeffs = append(coeffs, Random())
	}
	return Polynomial{coeffs}
}

// RandomPoly similar to above function . But randomly chooses secret Scalar parameter
func RandomPoly(degree int) Polynomial {
	var coeffs = make([]*ed25519.Scalar, degree+1)
	for i := 0; i <= degree; i++ {
		// coeffs = append(coeffs, Random())
		coeffs[i] = Random()
	}
	return Polynomial{coeffs}
}

// KeyGen generates a fresh ed25519 keypair (sk, pk = h^sk) for a participant in the PVSS protocol
func KeyGen() (*ed25519.Scalar, *ed25519.Point) {
	secretKey := Random()
	publicKey := ed25519.NewIdentityPoint().ScalarMult(secretKey, H)
	return secretKey, publicKey
}

// ShareRandomSecret secret shares a random data
func ShareRandomSecret(pubKeys Points, total, ths int, secret *ed25519.Scalar) NodeData {
	var (
		shares      = make(Scalars, total)
		commitments = make(Points, total)
		encEvals    = make(Points, total)
	)
	// creates a random polynomial
	poly := RandomWithSecret(ths-1, secret)
	// computes commitments, encrypted shares for each party
	for i := 1; i <= total; i++ {
		share := poly.Eval(i)
		shares[i-1] = *ed25519.NewScalar().Set(share)
		encEvals[i-1] = *ed25519.NewIdentityPoint().ScalarMult(share, &pubKeys[i-1])
		commitments[i-1] = *ed25519.NewIdentityPoint().ScalarMult(share, &G)
	}
	// generating proof for each party
	proofs := ProveShareCorrectness(shares, commitments, encEvals, pubKeys)
	return NodeData{
		Points:   commitments,
		EncEvals: encEvals,
		Proofs:   proofs,
	}
}

// ReconstructData returns the data for the reconstruction phase
func ReconstructData(enc, pkey ed25519.Point, skey ed25519.Scalar) RecData {
	dec := DecryptShare(enc, skey)
	chal, res := DleqProve(*H, dec, pkey, enc, skey)
	return RecData{
		DecShare: dec,
		Proof: NizkProof{
			Commit:   pkey,
			EncEval:  enc,
			Chal:     chal,
			Response: res,
		},
	}
}

// DecryptShare encryptedshare * secret_key.inverse()
func DecryptShare(share ed25519.Point, secretKey ed25519.Scalar) ed25519.Point {
	return *ed25519.NewIdentityPoint().ScalarMult(ed25519.NewScalar().Invert(&secretKey), &share)
}

// DleqVerify verifies a sequene of discrete logarithms
func DleqVerify(numProofs int, proofs NizkProofs, h Points) bool {
	for i := 0; i < numProofs; i++ {
		// each proof contains (Commit, EncEval, Chal, Response)
		proof := proofs[i]
		temp11 := ed25519.NewIdentityPoint().ScalarMult(&proof.Chal, &proof.Commit)
		a1 := ed25519.NewIdentityPoint().ScalarMult(&proof.Response, &G)
		a1.Add(temp11, a1)

		temp21 := ed25519.NewIdentityPoint().ScalarMult(&proof.Chal, &proof.EncEval)
		a2 := ed25519.NewIdentityPoint().ScalarMult(&proof.Response, &h[i])
		a2.Add(temp21, a2)

		eLocal := DleqDeriveChal(proof.Commit, proof.EncEval, *a1, *a2)
		if eLocal.Equal(&proof.Chal) != 1 {
			return false
		}
	}
	return true
}

// DleqBatchVerify same as DleqVerify except a single chal is computed for the entire challenge
// func DleqBatchVerify(g Points, h Points, x Points, y Points, e ed25519.Scalar, z Scalars) bool {
// 	n := len(g)
// 	if n != len(x) || n != len(h) || n != len(y) || n != len(z) {
// 		panic("Lenghts are not equal(DLEQ Verify)!")
// 	}
// 	var a1 Points
// 	for i := 0; i < n; i++ {
// 		a1 = append(a1, g[i].Mul(z[i]).Add(x[i].Mul(e)))
// 	}
// 	var a2 Points
// 	for i := 0; i < n; i++ {
// 		a2 = append(a2, h[i].Mul(z[i]).Add(y[i].Mul(e)))
// 	}
// 	eLocal := DleqDeriveBatchChal(x, y, a1, a2)
// 	return reflect.DeepEqual(e, eLocal)
// }

// DleqDeriveBatchChal computes the challenge using the entire batch
// func DleqDeriveBatchChal(x Points, y Points, a1 Points, a2 Points) ed25519.Scalar {
// 	n := len(x)
// 	var bytestring []byte
// 	for i := 0; i < n; i++ {
// 		bytestring = append(bytestring, x[i].Bytes()...)
// 		bytestring = append(bytestring, y[i].Bytes()...)
// 		bytestring = append(bytestring, a1[i].Bytes()...)
// 		bytestring = append(bytestring, a2[i].Bytes()...)
// 	}
// 	hash := sha512.New()
// 	hash.Write(bytestring)
// 	bs := hash.Sum(nil)
// 	return ed25519.ScalarReduce(bs)
// }

// ProveShareCorrectness returns commitments to the shares and a NIZK proof
// (DLEQ) proofing that the encrypted_shares are correctly derived.
func ProveShareCorrectness(shares Scalars, commits, encEvals Points, pubKeys Points) NizkProofs {
	n := len(shares)
	// Validate length of each vector
	if n != len(commits) || n != len(pubKeys) || n != len(encEvals) {
		panic("Lengths not equal!")
	}
	// Compute proof of each node
	var proofs NizkProofs
	for j := 0; j < n; j++ {
		chal, res := DleqProve(G, pubKeys[j], commits[j], encEvals[j], shares[j])
		proofs = append(proofs, NizkProof{
			Commit:   commits[j],
			EncEval:  encEvals[j],
			Chal:     chal,
			Response: res,
		})
	}
	return proofs
}

// DleqProve proves equality of discrete log for a single tuple
func DleqProve(g, h, x, y ed25519.Point, alpha ed25519.Scalar) (ed25519.Scalar, ed25519.Scalar) {
	// w random element  from Zq
	w := Random()
	a1 := ed25519.NewIdentityPoint().ScalarMult(w, &g)
	a2 := ed25519.NewIdentityPoint().ScalarMult(w, &h)
	e := DleqDeriveChal(x, y, *a1, *a2)
	z := ed25519.NewScalar().Subtract(w, ed25519.NewScalar().Multiply(e, &alpha))
	return *e, *z
}

// DleqDeriveChal computes the dleq challenge
func DleqDeriveChal(x, y, a1, a2 ed25519.Point) *ed25519.Scalar {
	var bytestring []byte
	bytestring = append(bytestring, x.Bytes()...)
	bytestring = append(bytestring, y.Bytes()...)
	bytestring = append(bytestring, a1.Bytes()...)
	bytestring = append(bytestring, a2.Bytes()...)

	hash := sha512.New()
	hash.Write(bytestring)
	bs := hash.Sum(nil)
	return ScalarReduce(bs)
}

// ScalarReduce reduces a 512 hash output into a scalar
func ScalarReduce(data []byte) *ed25519.Scalar {
	return ed25519.NewScalar().SetUniformBytes(data)
}

// ProveShareCorrectnessBatch uses a batched challenge
// func ProveShareCorrectnessBatch(shares Scalars, commits, encEvals Points, pubKeys Points) NizkProofs {
// 	n := len(shares)
// 	if n != len(commits) || n != len(pubKeys) || n != len(encEvals) {
// 		panic("Lengths not equal!")
// 	}

// 	var (
// 		gArray Points
// 		proofs NizkProofs
// 	)
// 	for j := 0; j < n; j++ {
// 		gArray = append(gArray, G)
// 	}
// 	// computing the nizk challenge
// 	chal, responses := DleqBatchProve(gArray, pubKeys, commits, encEvals, shares)
// 	// initializing proofs
// 	for j := 0; j < n; j++ {
// 		proofs = append(proofs, NizkProof{
// 			Commit:   commits[j],
// 			EncEval:  encEvals[j],
// 			Chal:     chal,
// 			Response: responses[j],
// 		})
// 	}
// 	return proofs
// }

// DleqBatchProve computes the challenges using the entire batch
// func DleqBatchProve(g []ed25519.Point, h []ed25519.Point, x []ed25519.Point, y []ed25519.Point, alpha Scalars) (ed25519.Scalar, Scalars) {
// 	n := len(g)
// 	if n != len(x) || n != len(h) || n != len(y) || n != len(alpha) {
// 		panic("Lenghts are not equal!")
// 	}
// 	var w Scalars // w random element  from Zq
// 	for i := 0; i < n; i++ {
// 		w = append(w, ed25519.Random())
// 	}
// 	var a1 Points // a1 = g^w
// 	for i := 0; i < n; i++ {
// 		a1 = append(a1, g[i].Mul(w[i]))
// 	}
// 	var a2 Points // a2 = h^w
// 	for i := 0; i < n; i++ {
// 		a2 = append(a2, h[i].Mul(w[i]))
// 	}
// 	e := DleqDeriveBatchChal(x, y, a1, a2) // the challenge e
// 	var z Scalars
// 	for i := 0; i < n; i++ {
// 		z = append(z, w[i].Sub(alpha[i].Mul(e)))
// 	}
// 	return e, z
// }

// VerifyShares verify that the given encrypted shares are computed accoring to the protocol.
// Returns True if the encrypted shares are valid.
// If this functions returns True, a collaboration of t nodes is able to recover the secret S.
func VerifyShares(proofs NizkProofs, pubKeys Points, total, ths int) bool {
	numProofs := len(proofs)
	if numProofs != total {
		log.Error("Incorrect nizk proofs")
		return false
	}
	// 1. verify the DLEQ NIZK proof
	if !DleqVerify(numProofs, proofs, pubKeys) {
		return false
	}
	// 2. verify the validity of the shares by sampling and testing with a random codeword
	codeword := RandomCodeword(total, ths)
	var commitments = make([]*ed25519.Point, total)
	for i := 0; i < total; i++ {
		commitments[i] = ed25519.NewIdentityPoint().Set(&proofs[i].Commit)
	}
	product := ed25519.NewIdentityPoint().VarTimeMultiScalarMult(codeword, commitments)
	return product.Equal(ONE) == 1
	// return true
}

// AggregateCommit aggregates polynomial commitment

func AggregateCommit(total int, indexSets []int, data []*NodeData) *NodeData {
	var (
		commits  = make(Points, total)
		encEvals = make(Points, total)
		i        int
		proof    NizkProof
		nData    *NodeData
	)
	lenIS := len(indexSets)
	nDataZero := data[0]
	proofs := nDataZero.Proofs
	// <<<<<<< HEAD

	// =======
	// >>>>>>> 32f352ed86787ac38255333891822e4542bcba4a
	for i, proof = range proofs {
		commits[i] = proof.Commit
		encEvals[i] = proof.EncEval
	}
	// <<<<<<< HEAD
	// 	for id := 1; id < lenIS; id++ {
	// =======
	uindexsets := make([]uint64, lenIS)
	if lenIS > 0 {
		for t := 0; t < lenIS; t++ {
			uindexsets[t] = uint64(indexSets[t])
		}
	} else {
		uindexsets = []uint64{}
	}
	for id := 1; id < lenIS; id++ {

		// >>>>>>> 32f352ed86787ac38255333891822e4542bcba4a
		nData = data[id]
		proofs = nData.Proofs
		for i, proof = range proofs {
			(&commits[i]).Add(&commits[i], &proof.Commit)
			(&encEvals[i]).Add(&encEvals[i], &proof.EncEval)
		}
	}

	root, _ := AggrMerkleRoot(uindexsets, commits, encEvals) // compute merkle root of "commits|encEvals|indexSets"
	return &NodeData{
		Root:     root,
		Points:   commits,
		EncEvals: encEvals,
	}
}

// sanityNodeData checks basic structure of a polynomial commitment
func sanityNodeData(aggr bool, com *NodeData, total, ths int) bool {
	// Check for existence of Merkle root
	if aggr && com.Root == (common.Hash{}) {
		return false
	}
	// length of the aggregate
	commitLen := len(com.Points)
	encLen := len(com.EncEvals)
	proofLen := len(com.Proofs)
	if aggr {
		proofLen = commitLen
	}
	log.Debug("Sanity check", "aggr", aggr, "cl", commitLen, "el", encLen, "pl", proofLen)
	if (commitLen != encLen) || (proofLen != encLen) || (encLen != total) {
		return false
	}
	return true
}

// sanityRoundData performs basic checks about RoundData
func sanityRoundData(rdata *RoundData, smrRoot common.Hash, ths int) bool {
	if smrRoot != rdata.Root {
		return false
	}
	if len(rdata.IndexSet) < ths {
		return false
	}
	return true
}

// validatePCommit validates the polynomial commitment using a random codeword
func validatePCommit(commitments Points, numNodes, threshold int) bool {
	codeword := RandomCodeword(numNodes, threshold)
	var lcoms = make([]*ed25519.Point, numNodes)
	for i := 0; i < numNodes; i++ {
		commitment := commitments[i]
		lcoms[i] = &commitment
	}
	product := ed25519.NewIdentityPoint().VarTimeMultiScalarMult(codeword, lcoms)
	return product.Equal(ONE) == 1
}

// aggrMerkleRoot computes the merkleroot of aggregate
func AggrMerkleRoot(isets []uint64, commits, encEvals Points) (common.Hash, gomerkle.Tree) {
	var byteslices [][]byte

	for _, idx := range isets {
		bs := make([]byte, 4)
		binary.LittleEndian.PutUint32(bs, uint32(idx))
		byteslices = append(byteslices, bs)
	}
	for _, enc := range encEvals {
		byteslices = append(byteslices, enc.Bytes())
	}
	for _, com := range commits {
		byteslices = append(byteslices, com.Bytes())
	}
	tree := gomerkle.NewTree(sha256.New())

	tree.AddData(byteslices...)

	err := tree.Generate()
	if err != nil {
		panic(err)
	}

	// // Proof for Jessie
	// proof := tree.GetProof(4)
	// leaf := tree.GetLeaf(4)
	// newtree := gomerkle.NewTree(sha256.New())
	// println(newtree.VerifyProof(proof, tree.Root(), leaf))

	return common.BytesToHash(tree.Root()), tree
}

// ValidateCommit checks for correctness of a aggregated message
func ValidateCommit(aggr bool, com *NodeData, pubKeys Points, total, ths int) error {
	// check basic sanity such as length
	if !sanityNodeData(aggr, com, total, ths) {
		return errInvalidSanityCheck
	}
	// check for validity of polynomial commitments
	if !validatePCommit(com.Points, total, ths) {
		return errInvalidPolyCommit
	}
	// check for validity of the NIZK proofs
	if !aggr && !DleqVerify(total, com.Proofs, pubKeys) {
		return errInvalidNIZK
	}
	return nil
}

// ValidateReconstruct whether a received reconstruction message is valid or not
func ValidateReconstruct(pkey, encshare, share ed25519.Point, proof NizkProof) bool {
	// Using values from the output of the SMR
	temp11 := ed25519.NewIdentityPoint().ScalarMult(&proof.Chal, &pkey)
	temp12 := ed25519.NewIdentityPoint().ScalarMult(&proof.Response, H)
	a1 := temp11.Add(temp11, temp12)

	temp21 := ed25519.NewIdentityPoint().ScalarMult(&proof.Chal, &encshare)
	temp22 := ed25519.NewIdentityPoint().ScalarMult(&proof.Response, &share)
	a2 := temp21.Add(temp21, temp22)

	eLocal := DleqDeriveChal(pkey, encshare, *a1, *a2)
	if eLocal.Equal(&proof.Chal) == 1 {
		return true
	}
	return false
}

// ValidatePrivData validates the private data sent by the leaer
// TODO(sourav): implement this function
func ValidatePrivData(rData RoundData, root common.Hash) error {
	return nil
}

// ValidateRoundData validates private messages received from leader
func ValidateRoundData(rData RoundData, root common.Hash) bool {
	return true
}

// VerifySecret does the following:
// 1. Obtain v_0 via Langrange interpolation from v_1, ..., v_t, or from any
//  other t-sized subset of {v_1, ..., v_n}. This is possible as the commitments
// 	v_1, ... v_n are all public information after the secret has been shared.
// 2. Use the fact v_0 = g^p(0) = g^s to verify that the given secret s is valid.
// func VerifySecret(secret ed25519.Scalar, commitments []ed25519.Point, threshold int) bool {
// 	v0 := Recover(commitments, threshold)
// 	return v0.Equal(G.Mul(secret))
// }
// func VerifySecret(secret *ed25519.Scalar, commitments Points, threshold int) bool {
// 	v0 := Recover(commitments, threshold)
// 	// return v0.Equal(G.Mul(secret))
// 	return v0.Equal(ed25519.NewGeneratorPoint().ScalarMult(secret, G)) == 1
// }

// Recover takes EXACTLY t (idx, share) tuples and performs Langrange interpolation
// to recover the secret S. The validity of the decrypted shares has to be verified
// prior to a call of this function.
// func Recover(shares Points, threshold int) ed25519.Point {
// 	var idxs Scalars
// 	for i := 1; i <= threshold; i++ {
// 		idxs = append(idxs, ed25519.BintToScalar(*big.NewInt(int64(i))))
// 	}

// 	// rec := ed25519.B // initialing it, will be subtracted later

// 	var LagrangeCoefficients []ed25519.Scalar
// 	var Shares []ed25519.Point
// 	for idx := 0; idx < threshold; idx++ {
// 		// t := LagrangeCoefficientScalar(ed25519.BintToScalar(*big.NewInt(int64(idx + 1))), idxs)
// 		// a := shares[idx].Mul(t)
// 		// rec = rec.Add(a)
// 		LagrangeCoefficients = append(LagrangeCoefficients, LagrangeCoefficientScalar(BintToScalar(*big.NewInt(int64(idx + 1))), idxs))
// 		Shares = append(Shares, shares[idx])
// 	}
// 	rec := ed25519.MSM(LagrangeCoefficients, Shares)
// 	return rec
// }

// RecoverBeacon computes the beacon output
// TODO(sourav): Optimize this!
// DOUBT: Will number of shares always be equal tp threshold?
func RecoverBeacon(shares map[uint64]*ed25519.Point, threshold int) ed25519.Point {
	// initializing indeces
	idxs := make([]*ed25519.Scalar, threshold)
	i := 0
	for idx := range shares {
		idxs[i] = BintToScalar(new(big.Int).SetUint64(idx + 1))
		i++
	}

	var LagrangeCoefficients = make([]*ed25519.Scalar, threshold)
	var lshares = make([]*ed25519.Point, threshold)
	ii := 0
	for idx, point := range shares {
		// point := shares[idx]
		lc := LagrangeCoefficientScalar(BintToScalar(new(big.Int).SetUint64(idx+1)), idxs)
		LagrangeCoefficients[ii] = lc
		lshares[ii] = point
		ii++
	}
	return *ed25519.NewIdentityPoint().VarTimeMultiScalarMult(LagrangeCoefficients, lshares)
}

// RandomCodeword returns a random dual code
func RandomCodeword(numNodes int, threshold int) []*ed25519.Scalar {
	var codeword []*ed25519.Scalar
	f := RandomPoly(numNodes - threshold - 1)
	for i := 1; i <= numNodes; i++ {
		vi := BintToScalar(big.NewInt(1))
		// vi := &vid
		for j := 1; j <= numNodes; j++ {
			if j != i {
				numerator := new(big.Int).Sub(big.NewInt(int64(i)), big.NewInt(int64(j)))
				modNum := BintToScalar(new(big.Int).Mod(numerator, GROUP_ORDER))
				vi.Multiply(vi, modNum)
			}
		}
		vi.Invert(vi)
		feval := f.Eval(i)
		codeword = append(codeword, vi.Multiply(vi, feval))
	}
	return codeword
}

// LagrangeCoefficientScalar compute lagrange coefficints
func LagrangeCoefficientScalar(i *ed25519.Scalar, indices []*ed25519.Scalar) *ed25519.Scalar {
	numerator := BintToScalar(big.NewInt(1))
	denominator := BintToScalar(big.NewInt(1))
	for j := 0; j < len(indices); j++ {
		idx := indices[j]
		if idx.Equal(i) != 1 {
			numerator.Multiply(numerator, idx)
			denominator.Multiply(denominator, ed25519.NewScalar().Subtract(idx, i))
		}
	}
	return numerator.Multiply(numerator, denominator.Invert(denominator))
}
