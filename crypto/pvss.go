package crypto

import (
	// "fmt"
	// "math"
	// "math/big"
	// "errors"
	// "strconv"
	// "bytes"
	// "unsafe"
	// "crypto/sha512"
	// "reflect"
	"github.com/ethereum/go-ethereum/crypto/ed25519"
)

// -------------------------------

// Sent out at end of commitment phase ((vi,ci,πi))
type CommitmentMessage struct {
	encrypted_shares []ed25519.Point
	proof ShareCorrectnessProof
}

// Sent out at end of aggragation phase (root,ˆv,ˆc,I, ̄cj, ̄πj, ̄vj,ht,X)
type AggregationMessage struct {
	root []byte // merkle root
	aggregated_commit ed25519.Point  // ˆv
	aggregated_encshare ed25519.Point  // ˆc
	I_list []int    // I
	proofs CommitmentMessage // (cj, ̄πj, ̄vj)
	height int //ht
	X Ht_proof  // ht proof
}

//Sent out at end of prepare phase
type PrepareMessage struct {
	root []byte
}

// sent out during reconstruction phase( ̃sj, ̃πj)
type ReconstructionMessage struct {
	secret ed25519.Point  // sj
	proof ShareCorrectnessProof  //πj
}


// -----------------------------------

var temp = make([] byte,32)
var G,_ = ed25519.Point_from_uniform(temp)  // TODO:finish this
var H = ed25519.B


type ShareCorrectnessProof struct {
	commitments []ed25519.Point
	challenge ed25519.Scalar
	responses []ed25519.Scalar
}

type ShareDecryptionProof struct {
	challenge ed25519.Scalar
	response ed25519.Scalar
}

type Ht_proof struct {

}



type Polynomial struct {
	coeffs []ed25519.Scalar
}



// Initializes polynomial with given coefficients
func (p Polynomial) Init(s []ed25519.Scalar) { 
   copy(p.coeffs,s)
}
// evaluates polynomial at arg and returns evaluation
func (p Polynomial) Call(arg int) (ed25519.Scalar) {
	return ed25519.Raw_scalar()
}


// Return a polynomial with random coefficients from Zq.
 //           p(x) = c_0 + c_1*x + ... c_{degree} * x^{degree}
        
func Random_with_secret(degree int,secret ed25519.Scalar) (Polynomial) {
	return Polynomial{}
}

// similar to above function . But randomly chooses secret Scalar parameter 
func Random(degree int) (Polynomial) {
	return Polynomial{}
}


// --------------------------


// generates a fresh ed25519 keypair (sk, pk = h^sk) for a participant in the PVSS protocol
func Keygen() (ed25519.Scalar,ed25519.Point) {
	return ed25519.Raw_scalar(),ed25519.Raw_point()
}

// Use this function to send message to leader in Commitment phase
// TODO:COmplete this function
func Share_random_secret(receiver_public_keys []ed25519.Point,recovery_threshold int,secret_scalar ed25519.Scalar) (CommitmentMessage){
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
	return CommitmentMessage{[]ed25519.Point{ed25519.Raw_point()},ShareCorrectnessProof{[]ed25519.Point{ed25519.Raw_point()},ed25519.Raw_scalar(),[]ed25519.Scalar{ed25519.Raw_scalar()}}}
}
// encryptedshare * secret_key.inverse()
func Decrypt_share(share ed25519.Scalar,secret_key ed25519.Scalar)(ed25519.Point) {
	return ed25519.Raw_point()
}


// Performs a the DLEQ NIZK protocol for the given values g, x, h, y and the exponent α.
//         I.e. the prover shows that he knows α such that x = g^α and y = h^α holds.
//         Returns challenge e and z to verifier
// Should I build function to prove in parallel for same chalenge e
func DLEQ_prove(g ed25519.Point,h ed25519.Point,x ed25519.Point,y ed25519.Point,α ed25519.Scalar) (ed25519.Scalar,ed25519.Scalar) {
	return ed25519.Raw_scalar(),ed25519.Raw_scalar()
}
// Performs a the verification procedure of DLEQ NIZK protocol for the given values g, x, h, y
//         the (common) challenge e and the response z.
func DLEQ_verify(g ed25519.Point,h ed25519.Point,x ed25519.Point,y ed25519.Point,e ed25519.Scalar,z ed25519.Scalar) (bool) {
	return false
}
//Compute (common) challenge e = H(x, y, a1,a2).
// a1 = g^z * x^e ,a2 = h^z * y^e
func DLEQ_derive_challenge(x ed25519.Point,y ed25519.Point,a1 ed25519.Point,a2 ed25519.Point) (ed25519.Scalar) {
	return ed25519.Raw_scalar()
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


func prove_share_correctness(shares []ed25519.Scalar,encrypted_shares []ed25519.Point,public_keys []ed25519.Point) (ShareCorrectnessProof) {
	return ShareCorrectnessProof{[]ed25519.Point{ed25519.Raw_point()},ed25519.Raw_scalar(),[]ed25519.Scalar{ed25519.Raw_scalar()}}
}


// """ Verify that the given encrypted shares are computed accoring to the protocol.
// Returns True if the encrypted shares are valid.
// If this functions returns True, a collaboration of t nodes is able to recover the secret S.
// """

func verify_shares(encrypted_shares []ed25519.Point,proof ShareCorrectnessProof,public_keys []ed25519.Point,recovery_threshold int) (bool) {
	return false
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
func verify_secret(secret ed25519.Scalar,commitments []ed25519.Point,recovery_threshold int) (bool){
	return false
}

// """ Proves that decrypted_share is a valid decryption for the given public key.
// i.e. implements DLEQ(h, pk_i, s~_i, ŝ_i)
// """
func prove_share_decryption(decrypted_share ed25519.Point, encrypted_share ed25519.Point, secret_key ed25519.Scalar,public_key ed25519.Point) (ShareDecryptionProof) {
	return ShareDecryptionProof{ed25519.Random(),ed25519.Random()}
}

// """ Check that the given share does indeed correspond to the given encrypted share.
// Returns True if the share is valid.
// """

func verify_decrypted_share(decrypted_share ed25519.Point, encrypted_share ed25519.Point, public_key ed25519.Point,proof ShareDecryptionProof) (bool) {
	return false
}

// """ Takes EXACTLY t (idx, decrypted_share) tuples and performs Langrange interpolation to recover the secret S.
//         The validity of the decrypted shares has to be verified prior to a call of this function.
//     """
func Recover(indexes []int,decrypted_shares []ed25519.Point) (ed25519.Point) {
	return ed25519.Raw_point()
}

func Random_codeword (num_nodes int,recovery_threshold int) ([] ed25519.Scalar) {
	return []ed25519.Scalar{ed25519.Random()}
}


func Lagrange_coeffecient (i int, indexes []int) (ed25519.Scalar) {
	return ed25519.Random()
}















// func hello() (ed25519.Point) {
// 	return ed25519.Point_one()
// }

