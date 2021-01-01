package crypto

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"math/big"
	"reflect"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto/ed25519"
	"github.com/ethereum/go-ethereum/log"
)

var (
	errInvalidSanityCheck = errors.New("sanity check failed")
	errInvalidPolyCommit  = errors.New("Invalid polynomial commitment")
	errInvalidNIZK        = errors.New("Invalid NIZK proof")
)

// NodeData implements the polynomial commitment type
type NodeData struct {
	Round    uint64
	Root     common.Hash // Nil root indicates commitment phase poly. commitment
	Sender   common.Address
	Points   Points
	EncEvals Points
	Proofs   NizkProofs
}

// RoundData stores data received from the leader
type RoundData struct {
	Round    uint64
	Root     common.Hash
	IndexSet []common.Address
	Commits  Points
	EncEvals Points
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

// Base points
var (
	G = PointG()
	H = ed25519.B
)

// PointG computes the base point
func PointG() ed25519.Point {
	has := sha256.New()
	has.Write(ed25519.B.Val)
	bs := has.Sum(nil)
	Pt, _ := ed25519.Point_from_uniform(bs)
	return Pt
}

// Polynomial is defined as a list of scalars
type Polynomial struct {
	coeffs Scalars
}

// Init Initializes polynomial with given coefficients
func (p Polynomial) Init(s Scalars) {
	copy(p.coeffs, s)
}

// Eval evaluates polynomial at arg and returns evaluation
func (p Polynomial) Eval(arg int) ed25519.Scalar {
	x := ed25519.NewScalar(*big.NewInt(int64(arg)))
	result := p.coeffs[0].Add(p.coeffs[1].Mul(x))
	xpow := x.Copy()
	for i := 2; i < len(p.coeffs); i++ {
		xpow = xpow.Mul(x)
		result = result.Add(p.coeffs[i].Mul(xpow))
	}
	return result
}

// RandomWithSecret returns a polynomial with random coefficients from Zq.
// p(x) = c_0 + c_1*x + ... c_{degree} * x^{degree}
func RandomWithSecret(degree int, secret ed25519.Scalar) Polynomial {
	var coeffs Scalars
	coeffs = append(coeffs, secret)
	for i := 1; i <= degree; i++ {
		coeffs = append(coeffs, ed25519.Random())
	}
	return Polynomial{coeffs}
}

// Random similar to above function . But randomly chooses secret Scalar parameter
func Random(degree int) Polynomial {
	var coeffs Scalars
	for i := 0; i <= degree; i++ {
		coeffs = append(coeffs, ed25519.Random())
	}
	return Polynomial{coeffs}
}

// KeyGen generates a fresh ed25519 keypair (sk, pk = h^sk) for a participant in the PVSS protocol
func KeyGen() (ed25519.Scalar, ed25519.Point) {
	secretKey := ed25519.Random()
	publicKey := H.Mul(secretKey)
	return secretKey, publicKey
}

// ShareRandomSecret Use this function to send message to leader in Commitment phase
// generate a fresh random base secret s (or uses the provided one)
func ShareRandomSecret(rcvPublicKeys Points, total, ths int, secret ed25519.Scalar) NodeData {
	var (
		shares      Scalars
		commitments Points
		encEvals    Points
	)
	// creates a random polynomial
	poly := RandomWithSecret(ths-1, secret)
	// computes commitments, encrypted shares for each party
	for i := 1; i <= total; i++ {
		share := poly.Eval(i)
		shares = append(shares, share)
		encEvals = append(encEvals, rcvPublicKeys[i-1].Mul(share))
		commitments = append(commitments, G.Mul(share))
	}
	// generating proof for each party
	proofs := ProveShareCorrectness(shares, commitments, encEvals, rcvPublicKeys)
	return NodeData{
		Points:   commitments,
		EncEvals: encEvals,
		Proofs:   proofs,
	}
}

// ReconstructData returns the data for the reconstruction phase
func ReconstructData(commit, enc, pkey ed25519.Point, skey ed25519.Scalar) RecData {
	dec := DecryptShare(enc, skey)
	chal, res := DleqProve(H, dec, pkey, enc, skey)
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
	return share.Mul(secretKey.Inverse())
}

// Performs a the DLEQ NIZK protocol for the given values g, x, h, y and the exponent α.
//         I.e. the prover shows that he knows α such that x = g^α and y = h^α holds.
//         Returns challenge e and z to verifier
// Should I build function to prove in parallel for same chalenge e
// func DLEQ_prove(g []ed25519.Point, h []ed25519.Point, x []ed25519.Point, y []ed25519.Point, alpha Scalars) (ed25519.Scalar, Scalars) {
// 	n := len(g)
// 	if n != len(x) || n != len(h) || n != len(y) || n != len(alpha) {
// 		panic("Lenghts are not equal!")
// 	}
// 	var w Scalars // w random element  from Zq
// 	for i := 0; i < n; i++ {
// 		w = append(w, ed25519.Random())
// 	}
// 	var a1 []ed25519.Point // a1 = g^w
// 	for i := 0; i < n; i++ {
// 		a1 = append(a1, g[i].Mul(w[i]))
// 	}
// 	var a2 []ed25519.Point // a2 = h^w
// 	for i := 0; i < n; i++ {
// 		a2 = append(a2, h[i].Mul(w[i]))
// 	}
// 	e := DLEQ_derive_challenge(x, y, a1, a2) // the challenge e

// 	var z Scalars // a2 = h^w
// 	for i := 0; i < n; i++ {
// 		z = append(z, w[i].Sub(alpha[i].Mul(e)))
// 	}
// 	return e, z
// }

// DleqVerify performs a the verification procedure of DLEQ NIZK protocol for the
// given values g, x, h, y the (common) challenge e and the response z.
func DleqVerify(numProofs int, proofs NizkProofs, h Points) bool {
	for i := 0; i < numProofs; i++ {
		// each proof contains (Commit, EncEval, Chal, Response)
		proof := proofs[i]
		a1 := G.Mul(proof.Response).Add(proof.Commit.Mul(proof.Chal))
		a2 := h[i].Mul(proof.Response).Add(proof.EncEval.Mul(proof.Chal))
		eLocal := DleqDeriveChal(proof.Commit, proof.EncEval, a1, a2)
		// log.Info("Verify, Deriving challenge", "i", i, "pk", h[i], "a1", a1, "a2", a2)
		// checking for equality of challenges
		if !reflect.DeepEqual(proof.Chal, eLocal) {
			return false
		}
	}
	return true
}

// DleqBatchVerify same as DleqVerify except a single chal is computed for the entire challenge
func DleqBatchVerify(g Points, h Points, x Points, y Points, e ed25519.Scalar, z Scalars) bool {
	n := len(g)
	if n != len(x) || n != len(h) || n != len(y) || n != len(z) {
		panic("Lenghts are not equal(DLEQ Verify)!")
	}
	var a1 Points
	for i := 0; i < n; i++ {
		a1 = append(a1, g[i].Mul(z[i]).Add(x[i].Mul(e)))
	}
	var a2 Points
	for i := 0; i < n; i++ {
		a2 = append(a2, h[i].Mul(z[i]).Add(y[i].Mul(e)))
	}
	eLocal := DleqDeriveBatchChal(x, y, a1, a2)
	return reflect.DeepEqual(e, eLocal)
}

// DleqDeriveBatchChal computes the challenge using the entire batch
func DleqDeriveBatchChal(x Points, y Points, a1 Points, a2 Points) ed25519.Scalar {
	n := len(x)
	var bytestring []byte
	for i := 0; i < n; i++ {
		bytestring = append(bytestring, x[i].Val...)
		bytestring = append(bytestring, y[i].Val...)
		bytestring = append(bytestring, a1[i].Val...)
		bytestring = append(bytestring, a2[i].Val...)
	}
	hash := sha512.New()
	hash.Write(bytestring)
	bs := hash.Sum(nil)
	return ed25519.ScalarReduce(bs)
}

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
func DleqProve(g ed25519.Point, h ed25519.Point, x ed25519.Point, y ed25519.Point, alpha ed25519.Scalar) (ed25519.Scalar, ed25519.Scalar) {
	// w random element  from Zq
	w := ed25519.Random()
	a1 := g.Mul(w)
	a2 := h.Mul(w)
	e := DleqDeriveChal(x, y, a1, a2)
	// log.Info("Prove, Deriving challenge", "pk", h, "a1", a1, "a2", a2)
	z := w.Sub(alpha.Mul(e))
	return e, z
}

// DleqDeriveChal computes the dleq challenge
func DleqDeriveChal(x ed25519.Point, y ed25519.Point, a1 ed25519.Point, a2 ed25519.Point) ed25519.Scalar {
	var bytestring []byte
	bytestring = append(bytestring, x.Val...)
	bytestring = append(bytestring, y.Val...)
	bytestring = append(bytestring, a1.Val...)
	bytestring = append(bytestring, a2.Val...)

	hash := sha512.New()
	hash.Write(bytestring)
	bs := hash.Sum(nil)
	return ed25519.ScalarReduce(bs)
}

// ProveShareCorrectnessBatch uses a batched challenge
func ProveShareCorrectnessBatch(shares Scalars, commits, encEvals Points, pubKeys Points) NizkProofs {
	n := len(shares)
	if n != len(commits) || n != len(pubKeys) || n != len(encEvals) {
		panic("Lengths not equal!")
	}

	var (
		gArray Points
		proofs NizkProofs
	)
	for j := 0; j < n; j++ {
		gArray = append(gArray, G)
	}
	// computing the nizk challenge
	chal, responses := DleqBatchProve(gArray, pubKeys, commits, encEvals, shares)
	// initializing proofs
	for j := 0; j < n; j++ {
		proofs = append(proofs, NizkProof{
			Commit:   commits[j],
			EncEval:  encEvals[j],
			Chal:     chal,
			Response: responses[j],
		})
	}
	return proofs
}

// DleqBatchProve computes the challenges using the entire batch
func DleqBatchProve(g []ed25519.Point, h []ed25519.Point, x []ed25519.Point, y []ed25519.Point, alpha Scalars) (ed25519.Scalar, Scalars) {
	n := len(g)
	if n != len(x) || n != len(h) || n != len(y) || n != len(alpha) {
		panic("Lenghts are not equal!")
	}
	var w Scalars // w random element  from Zq
	for i := 0; i < n; i++ {
		w = append(w, ed25519.Random())
	}
	var a1 Points // a1 = g^w
	for i := 0; i < n; i++ {
		a1 = append(a1, g[i].Mul(w[i]))
	}
	var a2 Points // a2 = h^w
	for i := 0; i < n; i++ {
		a2 = append(a2, h[i].Mul(w[i]))
	}
	e := DleqDeriveBatchChal(x, y, a1, a2) // the challenge e
	var z Scalars
	for i := 0; i < n; i++ {
		z = append(z, w[i].Sub(alpha[i].Mul(e)))
	}
	return e, z
}

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
	product := proofs[0].Commit.Mul(codeword[0])
	for i := 1; i < total; i++ {
		product = product.Add(proofs[i].Commit.Mul(codeword[i]))
	}
	return product.Equal(ed25519.ONE)
}

// AggregateCommit aggregates polynomial commitment
func AggregateCommit(total int, indexSets []int, data []NodeData) NodeData {
	var (
		commits  = make(Points, total)
		encEvals = make(Points, total)
	)
	lenIS := len(indexSets)
	for id := 0; id < lenIS; id++ {
		nodeData := data[id]
		for i, point := range nodeData.Points {
			if id == 0 {
				commits[i] = point
				encEvals[i] = nodeData.EncEvals[i]
			} else {
				commits[i].Add(point)
				encEvals[i].Add(nodeData.EncEvals[i])
			}
		}
	}
	root := aggrMerkleRoot(indexSets, commits, encEvals) // compute merkle root of "commits|encEvals|indexSets"
	return NodeData{
		Root:     root,
		Points:   commits,
		EncEvals: encEvals,
	}
}

// sanityNodeData checks basic structure of a polynomial commitment
func sanityNodeData(aggr bool, com NodeData, total, ths int) bool {
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
func sanityRoundData(rdata RoundData, smrRoot common.Hash, index, total, ths int) bool {
	if smrRoot != rdata.Root {
		return false
	}
	indexLen := len(rdata.IndexSet)
	commitLen := len(rdata.Commits)
	encLen := len(rdata.EncEvals)
	if indexLen < ths || indexLen != commitLen || indexLen != encLen {
		return false
	}
	return true
}

// validatePCommit validates the polynomial commitment using a random
// codeword
func validatePCommit(commitments Points, numNodes, threshold int) bool {
	codeword := RandomCodeword(numNodes, threshold)
	product := commitments[0].Mul(codeword[0])
	for i := 1; i < numNodes; i++ {
		product = product.Add(commitments[i].Mul(codeword[i]))
	}
	return product.Equal(ed25519.ONE)
}

// ValidateNIZK checks for correctness of zk proof in the aggregate
func validateNIZK(aggr NodeData) bool {
	return false
}

// aggrMerkleRoot computes the merkleroot of aggregate
func aggrMerkleRoot(isets []int, commits, encEvals Points) common.Hash {
	var bytestring []byte

	for _, idx := range isets {
		bs := make([]byte, 4)
		binary.LittleEndian.PutUint32(bs, uint32(idx))
		bytestring = append(bytestring, bs...)
	}
	for _, com := range commits {
		bytestring = append(bytestring, com.Val...)
	}
	for _, enc := range encEvals {
		bytestring = append(bytestring, enc.Val...)
	}

	hash := sha256.New()
	hash.Write(bytestring)
	bs := hash.Sum(nil)
	return common.BytesToHash(bs)
}

// MerkleRoot of a byte array
// TODO: Compute Merkle Root of a binary data!
func MerkleRoot(data []byte) common.Hash {
	return common.Hash{}
}

// ValidateCommit checks for correctness of a aggregated message
func ValidateCommit(aggr bool, com NodeData, pubKeys Points, total, ths int) error {
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
	a1 := H.Mul(proof.Response).Add(pkey.Mul(proof.Chal))
	a2 := share.Mul(proof.Response).Add(encshare.Mul(proof.Chal))
	eLocal := DleqDeriveChal(pkey, encshare, a1, a2)
	if !reflect.DeepEqual(proof.Chal, eLocal) {
		return false
	}
	return true
}

// ValidateRoundData validates private messages received from leader
func ValidateRoundData(rData RoundData, root common.Hash) bool {
	// check for correct formation of the MerkleRoot
	// if rData.Root != aggrMerkleRoot(rData) {
	// 	return false
	// }
	return true
}

// """ Checks if a revealed secret indeed corresponding to a provided commitment.
//         Returns True if the secret is valid.
//         Returns False is the secret is invalid.
//         Also returns False if the secret is valid but the commitment
//         (i.e. the coefficients of the underlying polynomial) where not derive according to the protocol.
//     """

// VerifySecret does the following
// 1. Obtain v_0 via Langrange interpolation from v_1, ..., v_t, or from any other t-sized subset of {v_1, ..., v_n}.
// This is possible as the commitments v_1, ... v_n are all public information after the secret has been shared.
//  2. Use the fact v_0 = g^p(0) = g^s to verify that the given secret s is valid.
func VerifySecret(secret ed25519.Scalar, commitments []ed25519.Point, threshold int) bool {
	v0 := Recover(commitments, threshold)
	return v0.Equal(G.Mul(secret))
}

// Recover takes EXACTLY t (idx, share) tuples and performs Langrange interpolation to recover the secret S.
// The validity of the decrypted shares has to be verified prior to a call of this function.
// TODO: Take in indices of shares instead of recovery threshold
// NOTE: Indices of shares are [1 ... recovery_threshold]
func Recover(shares Points, threshold int) ed25519.Point {
	var idxs Scalars
	for i := 1; i <= threshold; i++ {
		idxs = append(idxs, ed25519.NewScalar(*big.NewInt(int64(i))))
	}

	rec := ed25519.B // initialing it, will be subtracted later
	for idx := 0; idx < threshold; idx++ {
		t := LagrangeCoeffecientScalar(ed25519.NewScalar(*big.NewInt(int64(idx + 1))), idxs)
		a := shares[idx].Mul(t)
		rec = rec.Add(a)
	}
	return rec.Sub(ed25519.B)
}

// RecoverBeacon computes the beacon output
// TODO: Optimize this!
func RecoverBeacon(shares map[uint64]ed25519.Point, threshold int) ed25519.Point {
	// initializing indeces
	idxs := make(Scalars, threshold)
	i := 0
	for idx := range shares {
		idxs[i] = ed25519.NewScalar(*new(big.Int).SetUint64(idx))
		i++
	}

	// Interpolating the beacon output
	rec := ed25519.B
	for idx, point := range shares {
		sIdx := ed25519.NewScalar(*new(big.Int).SetUint64(idx))
		t := LagrangeCoeffecientScalar(sIdx, idxs)
		log.Info("after LC", "t", t, "point", point)
		a := point.Mul(t)
		rec = rec.Add(a)
	}
	return rec.Sub(ed25519.B)
}

// RandomCodeword returns a random dual code
func RandomCodeword(numNodes int, threshold int) Scalars {
	var codeword Scalars
	f := Random(numNodes - threshold - 1)
	for i := 1; i <= numNodes; i++ {
		vi := ed25519.NewScalar(*big.NewInt(1))
		for j := 1; j <= numNodes; j++ {
			if j != i {
				numerator := new(big.Int).Sub(big.NewInt(int64(i)), big.NewInt(int64(j)))
				vi = vi.Mul(ed25519.NewScalar(*new(big.Int).Mod(numerator, ed25519.GROUP_ORDER)))
			}
		}
		vi.Invert()
		codeword = append(codeword, vi.Mul(f.Eval(i)))
	}
	return codeword
}

// // LagrangeCoeffecient compute lagrange coefficints
// func LagrangeCoeffecient(i uint64, indices []uint64) ed25519.Scalar {
// 	numerator := *big.NewInt(1)
// 	denominator := *big.NewInt(1)
// 	for j := 0; j < len(indices); j++ {
// 		if indices[j] != i {
// 			numerator = numerator.Mul(big.NewInt(indices[j]))
// 			denominator = denominator.Mul(*big.NewInt(indices[j]).Sub(*big.NewInt(i)))
// 		}
// 	}
// 	return ed25519.NewScalar(numerator.Div(denominator))
// }

// LagrangeCoeffecientScalar compute lagrange coefficints
func LagrangeCoeffecientScalar(i ed25519.Scalar, indices Scalars) ed25519.Scalar {
	numerator := ed25519.NewScalar(*big.NewInt(1))
	denominator := ed25519.NewScalar(*big.NewInt(1))
	for j := 0; j < len(indices); j++ {
		if indices[j].Not_equal(i) {
			numerator = numerator.Mul(indices[j])
			denominator = denominator.Mul(indices[j].Sub(i))
		}
	}
	return numerator.Div(denominator)
}
