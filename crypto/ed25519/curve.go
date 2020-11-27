package ed25519


/*
#cgo CFLAGS: -g -Wall
#cgo LDFLAGS: -L. -lsodium
#include<stdlib.h>
#include<stdio.h>
#include<string.h>
#include "helper.h"
*/
import "C"
import (
	// "fmt"
	// "math"
	"math/big"
	"errors"
	"strconv"
	"bytes"
	"unsafe"
	"crypto/sha512"
	"reflect"
	"crypto/rand"
)
// libsodium linking code above import C statement
// type ldconfig if lib sodium is not found
//TODO: replace assignment of array woth copy of array

const BYTE_ORDER = "little"
var FIELD_MODULUS = new(big.Int).Sub(new(big.Int).Exp(big.NewInt(2), big.NewInt(255), nil),big.NewInt(19)) // FIELD_MODULUS = 2 ** 255 - 19
var TEMP, _ = new(big.Int).SetString("27742317777372353535851937790883648493",10)
var GROUP_ORDER = new(big.Int).Add(new(big.Int).Exp(big.NewInt(2), big.NewInt(255), nil),TEMP) //GROUP_ORDER = 2 ** 252 + 27742317777372353535851937790883648493

	// struct representing a group element, wraps to the underlying implementation in C 
type Point struct {

	x big.Int  // x coordinate  // TODO: Remove x and y coordiantes
	y big.Int  // y coordinate
	val []byte // y_packed value in little endian format

}

// returns new point given co-ordinates
func New_point(x big.Int,y big.Int) (Point) {
	

	// if !(0 <= x && float64(x)<FIELD_MODULUS) || !(0 <= y && float64(y)< FIELD_MODULUS){
	// 	return Point{value: val},errors.New("Invalid value")
	// }
	//  y_packed = y | ((x & 1) << 255)
	temp_x := x
	temp_y := y
	y_packed := new(big.Int).Or(&temp_y,new(big.Int).Mul(new(big.Int).And(&temp_x,big.NewInt(1)),new(big.Int).Exp(big.NewInt(2), big.NewInt(255), nil)))
	val := y_packed.Bytes()
	for i, j := 0, len(val)-1; i < j; i, j = i+1, j-1 { // reversal of bytes for little endian rep.
		val[i], val[j] = val[j], val[i]
	}
	for len(val)<32 {
		val = append(val,0)
	}
	return Point{x,y,val}
	// TODO: Error Checking
	
	
}

//returns blank invalid point template, used for creating valid point later
func Raw_point() (Point) { 
	token := make([]byte,32)
	return Point{*big.NewInt(0),*big.NewInt(0),token}
}
// g^0 = 1 in liitle endian format
func Point_one() (Point) { 
	token := make([]byte,32)
	token[0]=1
	return Point{*big.NewInt(0),*big.NewInt(0),token}
}

// returns a point with value as byte representation
func Point_from_bytes(value []byte) (Point,error) {
	if len(value)!=32 {
		return Raw_point(),errors.New("must be of len 32")
	}
	result:= Raw_point()
	result.val = value
	if result.Is_valid()==0 {
		return Raw_point(),errors.New("not a valid point value")
	}
	return result,nil
}

// returns a point from byte representation of y_packed
func Point_from_uniform(data []byte) (Point,error) {  // TODO:check if it return valid point in test
	for i, j := 0, len(data)-1; i < j; i, j = i+1, j-1 { // reversal of bytes
		data[i], data[j] = data[j], data[i]
	}
	for len(data)<32 {    // TODO: Ouput error on len< 32 or add zeros
		data = append(data,0)
	}
	temp := Raw_point()
	if C.crypto_core_ed25519_from_uniform((*C.uchar)(&temp.val[0]), (*C.uchar)(&data[0])) == 0 {
		return temp,nil
	}
	return temp,errors.New("from uniform op not working")
  
}

// Checks if given point is valid
func (p Point) Is_valid() (C.int){
	return (C.crypto_core_ed25519_is_valid_point((*C.uchar)(&p.val[0])))
}

// raises base to power s
func Base_times(s Scalar) (Point,error) {
	temp := Raw_point()
	if C.crypto_scalarmult_ed25519_base_noclamp((*C.uchar)(&temp.val[0]),(*C.uchar)(&s.val[0])) == 0 {
		return temp,nil
	}
	return temp,errors.New("calarmult_ed25519_base_noclamp not working")
}

//TODO: implement x and y functions?? convert int64 to bigint?

// returns sign +/- of point
func (p Point) Sign() (int64) {
	num, _ :=strconv.Atoi(string(p.val[len(p.val)-1]))
	tempnum:= (int64(num)/128)
	return tempnum
}

func (p Point) Equal(o Point) (bool) { //TODO test function
	if bytes.Equal(p.val,o.val) {
		return true
	}
	return (C.sodium_memcmp(unsafe.Pointer(&p.val[0]), unsafe.Pointer(&o.val[0]) , 32) == 0)
}

func (p Point) Not_equal(o Point) (bool) { //TODO test function
	if !bytes.Equal(p.val,o.val) {
		return true
	}
	return !(C.sodium_memcmp(unsafe.Pointer(&p.val[0]), unsafe.Pointer(&o.val[0]) , 32) == 0)
}

func (p Point) Add(o Point) (Point) { // removed error handling
	result:= Raw_point()
	if C.crypto_core_ed25519_add((*C.uchar)(&result.val[0]), (*C.uchar)(&p.val[0]), (*C.uchar)(&o.val[0])) == 0 {
		return result
	}
	return result
}


func (p Point) Sub(o Point) (Point) { //removed error handling
	result:= Raw_point()
	if C.crypto_core_ed25519_sub((*C.uchar)(&result.val[0]), (*C.uchar)(&p.val[0]), (*C.uchar)(&o.val[0])) == 0 {
		return result
	}
	return result
}

func (p Point) Mul(s Scalar) (Point) {  // removed error handling
	temp := Raw_point()
	if C.crypto_scalarmult_ed25519_noclamp((*C.uchar)(&temp.val[0]),(*C.uchar)(&s.val[0]),(*C.uchar)(&p.val[0])) == 0 {
		return temp
	}
	return temp
}


func (p Point) Bytes() ([] byte) {
	return p.val
}

func (p Point) Copy() (Point) {
	temp:= Raw_point()
	copy(temp.val,p.val)
	return temp
}

// Base point B of curve
var B_x, _ = new(big.Int).SetString("15112221349535400772501151409588531511454012693041857206046113283949847762202",10)
var B_y, _ = new(big.Int).SetString("46316835694926478169428394003475163141307993866256225615783033603165251855960",10)
var B = New_point(*B_x,*B_y)

// Point One on curve
var ONE = Point_one()



// ----------------------------------------------------------------------------------
type Scalar struct {
	bint big.Int// bigint value
	val []byte //little endian rep of bint
}

	
func New_scalar(v big.Int) (Scalar) {
	val := v.Bytes()

	for i, j := 0, len(val)-1; i < j; i, j = i+1, j-1 { // reversal of bytes
		val[i], val[j] = val[j], val[i]
	}
	for len(val)<32 {
		val = append(val,0)
	}
	return Scalar{v,val}
}

func Raw_scalar() (Scalar) {
	token := make([]byte,32)
	return Scalar{*big.NewInt(0),token}
}
// returns scalar from little endian rep of value
func Scalar_from_bytes(data []byte) (Scalar,error) {
	copy_data := make([]byte,len(data))
	if len(data)!= 32 {
		return Raw_scalar(),errors.New("len data must be 32")
	}
	copy(copy_data,data)
	sc:= Raw_scalar()
	for i, j := 0, len(copy_data)-1; i < j; i, j = i+1, j-1 { // reversal of bytes
		copy_data[i], copy_data[j] = copy_data[j], copy_data[i]
	}
	sc.bint = *new(big.Int).SetBytes(copy_data)
	sc.val = data
	return sc,nil

}
// set/refresh value of bint from val
func (sc Scalar) Refresh_bint() {
	copy_data := make([]byte,len(sc.val))
	if len(sc.val)!= 32 {
	// print error
	}
	copy(copy_data,sc.val)
	for i, j := 0, len(copy_data)-1; i < j; i, j = i+1, j-1 { // reversal of bytes
		copy_data[i], copy_data[j] = copy_data[j], copy_data[i]
	}
	sc.bint = *new(big.Int).SetBytes(copy_data)
}

func Scalar_reduce(data []byte) (Scalar) { 
	// obtain a uniformly distributed scalar value from a at least 40 bytes (~317 bit) random data,
           // typically the output of a cryptographic hashfunction
	scalar:=Raw_scalar()
	if len(data)>=40 {
		C.crypto_core_ed25519_scalar_reduce((*C.uchar)(&scalar.val[0]),(*C.uchar)(&data[0]))
	}
	scalar.Refresh_bint()
	return scalar
}


// checks if 0 <= s < CURVE_ORDER holds
func (s Scalar) Is_valid() (bool) {  // TODO test this fun
	if s.bint.Cmp(big.NewInt(0))>=0 && s.bint.Cmp(GROUP_ORDER)<0 {
		return true
	}
	return false
}

func Random() (Scalar) {  //TODO: make it seedable
 rand_big_int,_ := rand.Int(rand.Reader,GROUP_ORDER)
 return New_scalar(*rand_big_int)
}

func (s Scalar) Equal(o Scalar) (bool){ // Test this function
	// if reflect.DeepEqual(s,o) {
	// 	return true
	// }
	return C.sodium_memcmp(unsafe.Pointer(&s.val[0]), unsafe.Pointer(&o.val[0]) , 32)==0
}

func (s Scalar) Not_equal(o Scalar) (bool){ // Test this function
	// if reflect.DeepEqual(s,o) {
	// 	return false
	// }
	return C.sodium_memcmp(unsafe.Pointer(&s.val[0]), unsafe.Pointer(&o.val[0]) , 32)!=0
}

func (a Scalar) Add(b Scalar) (Scalar) { 
  result:= Raw_scalar()
  C.crypto_core_ed25519_scalar_add((*C.uchar)(&result.val[0]), (*C.uchar)(&a.val[0]), (*C.uchar)(&b.val[0]))
  result.Refresh_bint()
  return result

}


func (a Scalar) Sub(b Scalar) (Scalar) { 
	result:= Raw_scalar()
	C.crypto_core_ed25519_scalar_sub((*C.uchar)(&result.val[0]), (*C.uchar)(&a.val[0]), (*C.uchar)(&b.val[0])) 
	result.Refresh_bint()
	return result
}

func (a Scalar) Mul(b Scalar) (Scalar) { 
	result:= Raw_scalar()
	C.crypto_core_ed25519_scalar_mul((*C.uchar)(&result.val[0]), (*C.uchar)(&a.val[0]), (*C.uchar)(&b.val[0]))
	result.Refresh_bint()
	return result
}

func (a Scalar) Div(b Scalar) (Scalar) { 
	inv,_:=b.Inverse()
	return a.Mul(inv)
}

func (a Scalar) Neg() (Scalar) { 
	//compute the negation of the current scalar as new scalar
	// a + neg = 0 (mod CURVE_ORDER)
	result:=Raw_scalar()
	C.crypto_core_ed25519_scalar_negate((*C.uchar)(&result.val[0]),(*C.uchar)(&a.val[0]))
	result.Refresh_bint()
	return result
}

// a^b
func (a Scalar) Pow(b Scalar) (Scalar) { 
	a_int,_ := Scalar_from_bytes(a.val)
	b_int,_ := Scalar_from_bytes(b.val)
	result_int := new(big.Int).Exp(&a_int.bint,&b_int.bint,nil)
	return New_scalar(*result_int)
}

func (a Scalar)Negate() { 
	//compute the negation of the current scalar inplace
	// a + neg = 0 (mod CURVE_ORDER) using crypto_core_ed25519_scalar_negate
	C.crypto_core_ed25519_scalar_negate((*C.uchar)(&a.val[0]),(*C.uchar)(&a.val[0]))
	a.Refresh_bint()
}

func (a Scalar) Inverse() (Scalar,error) { 
	// return a new Scalar with is the multiplicate inverse of the current one
	result:= Raw_scalar()
	C.crypto_core_ed25519_scalar_invert((*C.uchar)(&result.val[0]),(*C.uchar)(&a.val[0]));
	result.Refresh_bint()
	return result,nil
}


// compute the multiplicate inverse of the current scalar inplace
func (a Scalar) Invert() { 
	C.crypto_core_ed25519_scalar_invert((*C.uchar)(&a.val[0]),(*C.uchar)(&a.val[0]));
	a.Refresh_bint()
}

func (a Scalar) Bytes() ([] byte) {
	return a.val
}

func (a Scalar) Int() (big.Int){
	return a.bint
}

func (a Scalar) Copy() (Scalar) {
	cpy:= Raw_scalar()
	cpy.bint = a.bint 
	copy(cpy.val,a.val)
	return cpy
}


// ---------------------------------------------

type SecretKey struct {
	val []byte
}

func (sk SecretKey) Bytes() ([] byte) { // TODO: return a copy?
	return sk.val
}

func H(message []byte) (Scalar) {  //TODO test this function
	has:= sha512.New()
	has.Write(message)
	bs := has.Sum(nil)
	// for i, j := 0, len(bs)-1; i < j; i, j = i+1, j-1 { // reversal of bytes
	// 	bs[i], bs[j] = bs[j], bs[i]
	// }
	num, _ :=Scalar_from_bytes(bs)
	result:= new(big.Int).Mod(&num.bint,GROUP_ORDER)
	return New_scalar(*result)

}

func Load_key(secret_key_seed []byte) (Scalar,Point,[]byte,error){
	dummy := make([]byte,32)
	if(len(secret_key_seed)!=32) {
		return Raw_scalar(), Raw_point(), dummy, errors.New("seed should be of len 32")
	}
	has:= sha512.New()
	has.Write(secret_key_seed)
	bs := has.Sum(nil)
	secret_bs:= bs[:32]
	r_seed:= bs[32:]
	// for i, j := 0, len(secret_bs)-1; i < j; i, j = i+1, j-1 { // reversal of bytes
	// 	secret_bs[i], secret_bs[j] = secret_bs[j], secret_bs[i]
	// }
	scl, _ :=Scalar_from_bytes(secret_bs)
	a := &scl.bint
	a = new(big.Int).And(a,new(big.Int).Sub(new(big.Int).Exp(big.NewInt(2), big.NewInt(254), nil),big.NewInt(8))) //a &= (1 << 254) - 8
	a = new(big.Int).Or(a,new(big.Int).Exp(big.NewInt(2), big.NewInt(254), nil)) // a |= 1 << 254
	secret_key:= New_scalar(*new(big.Int).Mod(a,GROUP_ORDER))
	public_key,err := Base_times(secret_key)
	if err!=nil {
		return secret_key, public_key , r_seed , errors.New("Base_times returned an error")
	}
	return secret_key, public_key , r_seed , nil

}

func Sign(secret_key_seed []byte,message []byte) (Point,Scalar,error) {
	secret_key, public_key, r_seed , err := Load_key(secret_key_seed)
	if err != nil {
		return Raw_point(),Raw_scalar(),errors.New("load_Key returned an error")
	}
	r:= H(append(r_seed[:],message[:]...))
	R,_ := Base_times(r)  //TODO: Handle error
	h:= H(append(R.Bytes()[:],append(public_key.Bytes()[:],message[:]...)...))
    s:= r.Add(h.Mul(secret_key))
   return R,s,nil
}

// func Sign(secret_key_seed []byte,message []byte) (Point,big.Int,error) { // IMPLEMENT
//   return Raw_point(),*new(big.Int),nil
// }



// --------------------------------------------------------------
type KeyPair struct {
	seed []byte // The seed is used a root value to derive all other values.
	// Must be keept secret!
	
	// Notice that this is the actual private scalar value used to derive the Point representing the public key.
    // This value is different from the notion of a secret key in libsodiums terminology.
    // It is used mostly by the PVSS algorithms.
	secret_scalar Scalar

	// This is what libsodium consider to be a secret key used to Signing messages.
    // I.e. a 64 bytes vector concatinated of the seed (32 bytes) and the public! key (32 bytes).
	// This might be somewhat confusing! See e.g. https://blog.mozilla.org/warner/2011/11/29/ed25519-keys/ for an
    // in depth explaination on how keys are derived.

	secret_key SecretKey

	// Point object representating a public key.
    // This value is equivalent to what libsodium considers to be a public key.
    // Also used in the PVSS algorithms.
    public_key Point
}

func (kp KeyPair) Init(seed []byte) { 

	kp.public_key = Raw_point()
	barray := make([]byte,64)
	kp.secret_key = SecretKey{barray}
	if C.crypto_sign_seed_keypair((*C.uchar)(&kp.public_key.val[0]),(*C.uchar)(&kp.secret_key.val[0]),(*C.uchar)(&seed[0])) !=0 {
		panic("crypto_sign_seed_keypair not working")
	}
	kp.seed = kp.secret_key.val[:32]
	has:= sha512.New()
	has.Write(kp.seed)
	bs := has.Sum(nil)
	sb,_ := Scalar_from_bytes(bs[:32])
	s:= &sb.bint
	s = new(big.Int).And(s,new(big.Int).Sub(new(big.Int).Exp(big.NewInt(2), big.NewInt(254), nil),big.NewInt(8))) //s &= (1 << 254) - 8
	s = new(big.Int).Or(s,new(big.Int).Exp(big.NewInt(2), big.NewInt(254), nil)) // s |= 1 << 254
	kp.secret_scalar = New_scalar(*new(big.Int).Mod(s,GROUP_ORDER))


}


func (kp KeyPair) Equal(o KeyPair) (bool){ // TODO test
	return reflect.DeepEqual(kp.seed,o.seed)
	
}

func Random_kp() (KeyPair) {
	token:= make([]byte,32)
	rand.Read(token)
	kp:= KeyPair{}
	kp.Init(token)
	return kp
}

// -----------------------------

func Sign_detached(message []byte,secret_key SecretKey) ([] byte) { 
	sig:= make([]byte,64)
	temp:= C.ulonglong(0)
	if C.crypto_sign_detached((*C.uchar)(&sig[0]),&temp,(*C.uchar)(&message[0]),C.ulonglong(len(message)),(*C.uchar)(&secret_key.val[0])) !=0 {
		panic(" sign detached not working")
	}
	return sig
}

func Verify_attached(signed_message []byte,public_key Point) (bool) {
	msg_len := len(signed_message) - 64
	return C.crypto_sign_verify_detached((*C.uchar)(&signed_message[msg_len]),(*C.uchar)(&signed_message[0]),C.ulonglong(msg_len),(*C.uchar)(&public_key.val[0])) == 0
}

func Verify_detached(message []byte,signature []byte,public_key Point) (bool) { // IMPLEMENT
	return C.crypto_sign_verify_detached((*C.uchar)(&signature[0]),(*C.uchar)(&message[0]),C.ulonglong(len(message)),(*C.uchar)(&public_key.val[0])) == 0
}

// Testing functionality (will be removed later)
// func main(){

// 	u := new(big.Int)
// 	d := new(big.Int)
// 	u, _ = u.SetString("15112221349535400772501151409588531511454012693041857206046113283949847762202",10)
// 	d, _ = d.SetString("46316835694926478169428394003475163141307993866256225615783033603165251855960",10)
// 	pt:= New_point(*u,*d)
// 	fmt.Println(pt.val)
// 	fmt.Println(pt.Sign())
// 	pt2:=Raw_point()
// 	copy(pt2.val,pt.val)
// 	sum:=pt.Add(pt2)
// 	fmt.Println(sum)
// 	diff:= sum.Sub(pt2)
// 	fmt.Println(diff)
// 	two:= big.NewInt(2)
// 	Scalar_2:= New_scalar(*two)
// 	fmt.Println(pt.Mul(Scalar_2))
// 	fmt.Println(Random().val)
// 	// fmt.Println(C.crypto_core_ed25519_Is_valid_point((*C.uchar)(&pt.val[0])))
// 	fmt.Println(pt.Is_valid())
// 	s := New_scalar(*big.NewInt(2))
// 	// e := New_scalar(*big.NewInt(3))
// 	t,_:=s.Inverse()
// 	fmt.Println(t.Mul(s))
// 	token := make([]byte,32)

// 	// fmt.Println(C.crypto_scalarmult_ed25519_base_noclamp((*C.uchar)(&token[0]),(*C.uchar)(&s.val[0])))
// 	C.crypto_scalarmult_ed25519_noclamp((*C.uchar)(&token[0]),(*C.uchar)(&s.val[0]),(*C.uchar)(&pt.val[0]));
// 	fmt.Println(token)
// 	fmt.Println(C.crypto_core_ed25519_is_valid_point((*C.uchar)(&token[0])))
    
// }