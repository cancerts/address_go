package main

import (
	"fmt"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"log"	
	"math/big"

	"golang.org/x/crypto/ripemd160"
)

func main() {
	
	wallet := NewWallet()
	fmt.Println("=======================")
	//私钥
	fmt.Println("0 - USDT账户的私钥")
	fmt.Println(byteString(wallet.PrivateKey))
	fmt.Println("=======================")
	//wif-钱包导入格式私钥
	fmt.Println("1 - 私钥对应的钱包导入格式WIF--用于导入钱包使用")
	fmt.Println(ToWIF(wallet.PrivateKey))
	fmt.Println("=======================")
	fmt.Println("2 - USDT账户公钥")
	fmt.Println(byteString(wallet.PublicKey))
	fmt.Println("=======================")
	//USDT地址--公钥哈希地址以1开头的，也就是比特币地址
	fmt.Println("3 - 对应私钥的USDT地址")
	fmt.Println(wallet.GetAddress())
	fmt.Println("=======================")
}
//版本号
const version = byte(0x00)
const addressChecksumLen = 4

// Wallet stores private and public keys
type Wallet struct {
	PrivateKey []byte
	PublicKey  []byte
}

// NewWallet creates and returns a Wallet
func NewWallet() *Wallet {
	private, public := newKeyPair()
	wallet := Wallet{private, public}

	return &wallet
}

// GetAddress returns wallet address
func (w Wallet) GetAddress() (address string) {
	/* See https://en.bitcoin.it/wiki/Technical_background_of_Bitcoin_addresses */

	/* Convert the public key to bytes */
	pub_bytes := w.PublicKey

	/* SHA256 Hash */
	sha256_h := sha256.New()
	sha256_h.Reset()
	sha256_h.Write(pub_bytes)
	pub_hash_1 := sha256_h.Sum(nil)

	/* RIPEMD-160 Hash */
	ripemd160_h := ripemd160.New()
	ripemd160_h.Reset()
	ripemd160_h.Write(pub_hash_1)
	pub_hash_2 := ripemd160_h.Sum(nil)
	
	/* Convert hash bytes to base58 check encoded sequence */
	address = b58checkencode(0x00, pub_hash_2)

	return address
}

// HashPubKey hashes public key
func HashPubKey(pubKey []byte) []byte {
	publicSHA256 := sha256.Sum256(pubKey)

	RIPEMD160Hasher := ripemd160.New()
	_, err := RIPEMD160Hasher.Write(publicSHA256[:])
	if err != nil {
		log.Panic(err)
	}
	publicRIPEMD160 := RIPEMD160Hasher.Sum(nil)

	return publicRIPEMD160
}
// 私钥长度32字节
const privKeyBytesLen = 32

//new a ecdsa random
func newKeyPair() ([]byte, []byte) {
	curve := elliptic.P256()
	private, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		log.Panic(err)
	}
	d := private.D.Bytes()
	b := make([]byte, 0, privKeyBytesLen)
	priKet := paddedAppend(privKeyBytesLen, b, d)
	pubKey := append(private.PublicKey.X.Bytes(), private.PublicKey.Y.Bytes()...)

	return priKet, pubKey
}

// ToWIF converts a Bitcoin private key to a Wallet Import Format string.
func ToWIF(priv []byte) (wif string) {
	/* Convert bytes to base-58 check encoded string with version 0x80 */
	wif = b58checkencode(0x80, priv)

	return wif
}
func byteString(b []byte) (s string) {
	s = ""
	for i := 0; i < len(b); i++ {
		s += fmt.Sprintf("%02X", b[i])
	}
	return s
}

// b58encode encodes a byte slice b into a base-58 encoded string.
func b58encode(b []byte) (s string) {
	/* See https://en.bitcoin.it/wiki/Base58Check_encoding */

	const BITCOIN_BASE58_TABLE = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

	/* Convert big endian bytes to big int */
	x := new(big.Int).SetBytes(b)

	/* Initialize */
	r := new(big.Int)
	m := big.NewInt(58)
	zero := big.NewInt(0)
	s = ""

	/* Convert big int to string */
	for x.Cmp(zero) > 0 {
		/* x, r = (x / 58, x % 58) */
		x.QuoRem(x, m, r)
		/* Prepend ASCII character */
		s = string(BITCOIN_BASE58_TABLE[r.Int64()]) + s
	}

	return s
}

// b58checkencode encodes version ver and byte slice b into a base-58 check encoded string.
func b58checkencode(ver uint8, b []byte) (s string) {
	/* Prepend version */
	bcpy := append([]byte{ver}, b...)
	
	/* Create a new SHA256 context */
	sha256H := sha256.New()

	/* SHA256 Hash #1 */	
	sha256H.Reset()
	sha256H.Write(bcpy)
	hash1 := sha256H.Sum(nil)
	
	/* SHA256 Hash #2 */
	sha256H.Write(hash1)
	hash2 := sha256H.Sum(nil)

	/* Append first four bytes of hash */
	bcpy = append(bcpy, hash2[0:4]...)
	
	/* Encode base58 string */
	s = b58encode(bcpy)

	/* For number of leading 0's in bytes, prepend 1 */
	for _, v := range bcpy {
		if v != 0 {
			break
		}
		s = "1" + s
	}
	return s

}

// paddedAppend appends the src byte slice to dst, returning the new slice.
// If the length of the source is smaller than the passed size, leading zero
// bytes are appended to the dst slice before appending src.
func paddedAppend(size uint, dst, src []byte) []byte {
	for i := 0; i < int(size)-len(src); i++ {
		dst = append(dst, 0)
	}
	return append(dst, src...)
}
