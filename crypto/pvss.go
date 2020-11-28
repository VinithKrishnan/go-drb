package crypto

import (
	// "fmt"
	// "math"
	"math/big"
	// "errors"
	// "strconv"
	// "bytes"
	// "unsafe"
	"crypto/sha256"
	"crypto/sha512"
	// "ed25519"
	"github.com/ethereum/go-ethereum/crypto/ed25519"
	"reflect"
)

// -------------------------------

// Sent out at end of commitment phase ((vi,ci,πi))
type CommitmentMessage struct {
	encrypted_shares []ed25519.Point
	proof            ShareCorrectnessProof
}

// Sent out at end of aggragation phase (root,ˆv,ˆc,I, ̄cj, ̄πj, ̄vj,ht,X)
type AggregationMessage struct {
	root                []byte            // merkle root
	aggregated_commit   ed25519.Point     // ˆv
	aggregated_encshare ed25519.Point     // ˆc
	I_list              []int             // I
	proofs              CommitmentMessage // (cj, ̄πj, ̄vj)
	height              int               //ht
	X                   Ht_proof          // ht proof
}

//Sent out at end of prepare phase
type PrepareMessage struct {
	root []byte
}

// sent out during reconstruction phase( ̃sj, ̃πj)
type ReconstructionMessage struct {
	secret ed25519.Point         // sj
	proof  ShareCorrectnessProof //πj
}

// -----------------------------------

// var temp = make([] byte,32)
var G = Point_G() // TODO:finish this
var H = ed25519.B

type ShareCorrectnessProof struct {
	commitments []ed25519.Point
	challenge   ed25519.Scalar
	responses   []ed25519.Scalar
}

type ShareDecryptionProof struct {
	challenge ed25519.Scalar
	response  []ed25519.Scalar
}

type Ht_proof struct {
}

type Polynomial struct {
	coeffs []ed25519.Scalar
}

func Point_G() ed25519.Point {
	has := sha256.New()
	has.Write(ed25519.B.Val)
	bs := has.Sum(nil)
	Pt, _ := ed25519.Point_from_uniform(bs)
	return Pt
}

// Initializes polynomial with given coefficients
func (p Polynomial) Init(s []ed25519.Scalar) {
	copy(p.coeffs, s)
}

// evaluates polynomial at arg and returns evaluation
func (p Polynomial) Eval(arg int) ed25519.Scalar {
	x := ed25519.New_scalar(*big.NewInt(int64(arg)))
	result := p.coeffs[0].Add(p.coeffs[1].Mul(x))
	x_pow := x.Copy()
	for i := 2; i <= len(p.coeffs); i++ {
		x_pow = x_pow.Mul(x)
		result = result.Add(p.coeffs[i].Mul(x_pow))
	}
	return result
}

// Return a polynomial with random coefficients from Zq.
//           p(x) = c_0 + c_1*x + ... c_{degree} * x^{degree}

func Random_with_secret(degree int, secret ed25519.Scalar) Polynomial {
	var coeffs []ed25519.Scalar
	coeffs = append(coeffs, secret)
	for i := 1; i < degree; i++ {
		coeffs = append(coeffs, ed25519.Random())
	}
	return Polynomial{coeffs}
}

// similar to above function . But randomly chooses secret Scalar parameter
func Random(degree int) Polynomial {
	var coeffs []ed25519.Scalar
	for i := 0; i < degree; i++ {
		coeffs = append(coeffs, ed25519.Random())
	}
	return Polynomial{coeffs}
}

// --------------------------

// generates a fresh ed25519 keypair (sk, pk = h^sk) for a participant in the PVSS protocol
func Keygen() (ed25519.Scalar, ed25519.Point) {
	secret_key := ed25519.Random()
	public_key := H.Mul(secret_key)
	return secret_key, public_key
}

// Use this function to send message to leader in Commitment phase
// TODO:COmplete this function
func Share_random_secret(receiver_public_keys []ed25519.Point, recovery_threshold int, secret_scalar ed25519.Scalar) CommitmentMessage {
	//  generate a fresh random base secret s (or uses the provided one)
	// computes share (s_1, ..., s_n) for S = h^s
	// encrypts them with the public keys to obtain ŝ_1, ..., ŝ_n
	// compute the verification information
	// returns

	//  - the encrypted shares ŝ_1, ..., ŝ_n
	//  - the share verification information, i.e. PROOF_D, which consists of
	// 	- the commitments v_1, ..., v_n   (v_i = g^{s_i})
	// 	- the (common) challenge e
	// 	- the responses z_1, ..., z_n

	num_receivers := len(receiver_public_keys)
	secret := secret_scalar
	poly := Random_with_secret(recovery_threshold-1, secret)
	var shares []ed25519.Scalar
	for i := 1; i <= num_receivers; i++ {
		shares = append(shares, poly.Eval(i))
	}
	var encrypted_shares []ed25519.Point
	for j := 0; j < num_receivers; j++ {
		encrypted_shares = append(encrypted_shares, receiver_public_keys[j].Mul(shares[j]))
	}
	proof := prove_share_correctness(shares, encrypted_shares, receiver_public_keys)

	return CommitmentMessage{encrypted_shares, proof}
}

// encryptedshare * secret_key.inverse()
func Decrypt_share(share ed25519.Scalar, secret_key ed25519.Scalar) ed25519.Scalar {
	return share.Mul(secret_key.Inverse())
}

// Performs a the DLEQ NIZK protocol for the given values g, x, h, y and the exponent α.
//         I.e. the prover shows that he knows α such that x = g^α and y = h^α holds.
//         Returns challenge e and z to verifier
// Should I build function to prove in parallel for same chalenge e
func DLEQ_prove(g []ed25519.Point, h []ed25519.Point, x []ed25519.Point, y []ed25519.Point, α []ed25519.Scalar) (ed25519.Scalar, []ed25519.Scalar) {
	n := len(g)
	if n != len(x) || n != len(h) || n != len(y) || n != len(α) {
		panic("Lenghts are not equal!")
	}
	var w []ed25519.Scalar // w random element  from Zq
	for i := 0; i < n; i++ {
		w = append(w, ed25519.Random())
	}
	var a1 []ed25519.Point // a1 = g^w
	for i := 0; i < n; i++ {
		a1 = append(a1, g[i].Mul(w[i]))
	}
	var a2 []ed25519.Point // a2 = h^w
	for i := 0; i < n; i++ {
		a2 = append(a2, h[i].Mul(w[i]))
	}
	e := DLEQ_derive_challenge(x, y, a1, a2) // the challenge e

	var z []ed25519.Scalar // a2 = h^w
	for i := 0; i < n; i++ {
		z = append(z, w[i].Sub(α[i].Mul(e)))
	}

	return e, z

}

// Performs a the verification procedure of DLEQ NIZK protocol for the given values g, x, h, y
//         the (common) challenge e and the response z.
func DLEQ_verify(g []ed25519.Point, h []ed25519.Point, x []ed25519.Point, y []ed25519.Point, e ed25519.Scalar, z []ed25519.Scalar) bool {
	n := len(g)
	if n != len(x) || n != len(h) || n != len(y) || n != len(z) {
		panic("Lenghts are not equal(DLEQ Verify)!")
	}
	var a1 []ed25519.Point
	for i := 0; i < n; i++ {
		a1 = append(a1, g[i].Mul(z[i]).Add(x[i].Mul(e)))
	}
	var a2 []ed25519.Point
	for i := 0; i < n; i++ {
		a2 = append(a2, h[i].Mul(z[i]).Add(y[i].Mul(e)))
	}
	e_computed := DLEQ_derive_challenge(x, y, a1, a2)
	return reflect.DeepEqual(e, e_computed)
}

//Compute (common) challenge e = H(x, y, a1,a2).
// a1 = g^z * x^e ,a2 = h^z * y^e
func DLEQ_derive_challenge(x []ed25519.Point, y []ed25519.Point, a1 []ed25519.Point, a2 []ed25519.Point) ed25519.Scalar {
	n := len(x)
	var bytestring []byte
	for i := 0; i < n; i++ {
		bytestring = append(bytestring, x[i].Val...)
		bytestring = append(bytestring, y[i].Val...)
		bytestring = append(bytestring, a1[i].Val...)
		bytestring = append(bytestring, a2[i].Val...)
	}
	has := sha512.New()
	has.Write(bytestring)
	bs := has.Sum(nil)
	return ed25519.Scalar_reduce(bs)
}

// Returns commitments to the shares and a NIZK proof (DLEQ) proofing that
// the encrypted_shares are correctly derived.

// # notation used in Scrape paper and analogs here
// # x... commitments
// # y... encrypted shares
// # g... G
// # h... public_keys
// # α... shares
// # e... challenge
// # z... responses

func prove_share_correctness(shares []ed25519.Scalar, encrypted_shares []ed25519.Point, public_keys []ed25519.Point) ShareCorrectnessProof {
	// return ShareCorrectnessProof{[]ed25519.Point{ed25519.Raw_point()},ed25519.Raw_scalar(),[]ed25519.Scalar{ed25519.Raw_scalar()}}
	n := len(shares)
	var commitments []ed25519.Point
	for i := 0; i < len(shares); i++ {
		commitments = append(commitments, G.Mul(shares[i]))
	}
	if n != len(commitments) || n != len(public_keys) || n != len(encrypted_shares) || n != len(shares) {
		panic("Lengths not equal!")
	}
	var G_bytestring []ed25519.Point
	for j := 0; j < n; j++ {
		G_bytestring = append(G_bytestring, G)
	}
	challenge, responses := DLEQ_prove(G_bytestring, commitments, public_keys, encrypted_shares, shares)
	return ShareCorrectnessProof{commitments, challenge, responses}

}

// """ Verify that the given encrypted shares are computed accoring to the protocol.
// Returns True if the encrypted shares are valid.
// If this functions returns True, a collaboration of t nodes is able to recover the secret S.
// """

func verify_shares(encrypted_shares []ed25519.Point, proof ShareCorrectnessProof, public_keys []ed25519.Point, recovery_threshold int) bool {
	num_nodes := len(public_keys)
	commitments, challenge, responses := proof.commitments, proof.challenge, proof.responses

	var G_bytestring []ed25519.Point
	for j := 0; j < num_nodes; j++ {
		G_bytestring = append(G_bytestring, G)
	}
	// 1. verify the DLEQ NIZK proof
	if !DLEQ_verify(G_bytestring, commitments, public_keys, encrypted_shares, challenge, responses) {
		return false
	}

	// 2. verify the validity of the shares by sampling and testing with a random codeword

	codeword := Random_codeword(num_nodes, recovery_threshold)
	product := commitments[0].Mul(codeword[0])
	for i := 1; i < num_nodes; i++ {
		product = product.Add(commitments[i].Mul(codeword[i]))
	}
	return product.Equal(ed25519.ONE)

}

// """ Checks if a revealed secret indeed corresponding to a provided commitment.
//         Returns True if the secret is valid.
//         Returns False is the secret is invalid.
//         Also returns False if the secret is valid but the commitment
//         (i.e. the coefficients of the underlying polynomial) where not derive according to the protocol.
//     """

// # 1. Obtain v_0 via Langrange interpolation from v_1, ..., v_t, or from any other t-sized subset of {v_1, ..., v_n}.
//     #    This is possible as the commitments v_1, ... v_n are all public information after the secret has been shared.
//     # 2. Use the fact v_0 = g^p(0) = g^s to verify that the given secret s is valid.
func verify_secret(secret ed25519.Scalar, commitments []ed25519.Point, recovery_threshold int) bool {
	v0 := Recover(commitments, recovery_threshold)
	return v0.Equal(G.Mul(secret))
}

// """ Proves that decrypted_share is a valid decryption for the given public key.
// i.e. implements DLEQ(h, pk_i, s~_i, ŝ_i)
// """
func prove_share_decryption(decrypted_share ed25519.Point, encrypted_share ed25519.Point, secret_key ed25519.Scalar, public_key ed25519.Point) ShareDecryptionProof {
	challenge, response := DLEQ_prove([]ed25519.Point{H}, []ed25519.Point{public_key}, []ed25519.Point{decrypted_share}, []ed25519.Point{encrypted_share}, []ed25519.Scalar{secret_key})

	return ShareDecryptionProof{challenge, response}
}

// """ Check that the given share does indeed correspond to the given encrypted share.
// Returns True if the share is valid.
// """

func verify_decrypted_share(decrypted_share ed25519.Point, encrypted_share ed25519.Point, public_key ed25519.Point, proof ShareDecryptionProof) bool {
	challenge, response := proof.challenge, proof.response
	return DLEQ_verify([]ed25519.Point{H}, []ed25519.Point{public_key}, []ed25519.Point{decrypted_share}, []ed25519.Point{encrypted_share}, challenge, response)

}

// """ Takes EXACTLY t (idx, decrypted_share) tuples and performs Langrange interpolation to recover the secret S.
//         The validity of the decrypted shares has to be verified prior to a call of this function.
//     """

// NOTE: Indices of shares are [1 ... recovery_threshold]
func Recover(decrypted_shares []ed25519.Point, recovery_threshold int) ed25519.Point {
	var idxs []ed25519.Scalar
	for i := 1; i <= recovery_threshold; i++ {
		idxs = append(idxs, ed25519.New_scalar(*big.NewInt(int64(i))))
	}
	var rec ed25519.Point
	for idx := 1; idx <= recovery_threshold; idx++ {
		rec = rec.Add(decrypted_shares[idx].Mul(Lagrange_coeffecient(ed25519.New_scalar(*big.NewInt(int64(idx))), idxs)))
	}
	return rec
}

func Random_codeword(num_nodes int, recovery_threshold int) []ed25519.Scalar {
	var codeword []ed25519.Scalar
	f := Random(num_nodes - recovery_threshold - 1)
	for i := 1; i <= num_nodes; i++ {
		vi := ed25519.New_scalar(*big.NewInt(1))
		for j := 1; i <= num_nodes; i++ {
			if j != i {
				numerator := big.NewInt(int64(i - j))
				vi = vi.Mul(ed25519.New_scalar(*new(big.Int).Mod(numerator, ed25519.GROUP_ORDER)))
			}
		}
		vi.Invert()
		codeword = append(codeword, vi.Mul(f.Eval(i)))

	}
	return codeword
}

func Lagrange_coeffecient(i ed25519.Scalar, indexes []ed25519.Scalar) ed25519.Scalar {
	numerator := ed25519.New_scalar(*big.NewInt(1))
	denominator := ed25519.New_scalar(*big.NewInt(1))
	for j := 0; j < len(indexes); j++ {
		if indexes[j].Not_equal(i) {
			numerator = numerator.Mul(indexes[j])
			denominator = denominator.Mul(indexes[j].Sub(i))
		}
	}
	return numerator.Div(denominator)
}

// func hello() (ed25519.Point) {
// 	return ed25519.Point_one()
// }
