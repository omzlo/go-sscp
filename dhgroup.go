package sscp

import (
	"crypto/rand"
	"crypto/sha256"
	//"fmt"
	"math/big"
)

const (
    Group15Prime = `FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF`
    Group15Generator = 2
    Group15BlockLen = 384
)

type B384 [Group15BlockLen]byte

type DHKey struct {
	P  *big.Int
	G  *big.Int
	R  *big.Int
	GR *big.Int
}

var Zero = big.NewInt(0)

func NewDHKey() *DHKey {
	var private_key *big.Int
	var err error

	prime := new(big.Int)
	prime.SetString(Group15Prime, 16)
	generator := big.NewInt(Group15Generator)

	for {
		private_key, err = rand.Int(rand.Reader, prime)
		if err != nil {
			panic(err)
		}
		if private_key.Cmp(Zero) != 0 {
			break
		}
	}
	// Note: Modular exponentiation of inputs of a particular size is not a cryptographically constant-time operation.
	public_key := new(big.Int)
	if public_key.Exp(generator, private_key, prime) == nil {
		panic("Exp failed")
	}

  return &DHKey{P: prime, G: generator, R: private_key, GR: public_key}
}

func (key *DHKey) GRMul(val []byte, result []byte) []byte {
	a := new(big.Int).SetBytes(val)
	b := key.GR
	r := new(big.Int).Mul(a, b)
	r.Mod(r, key.P)
  return r.FillBytes(result)
}

func (key *DHKey) Div(a []byte, b []byte, result []byte) []byte {
	//fmt.Println("#### DIV ####")
	//fmt.Printf("a = %q\nb=%q\n", a, b)
	aa := new(big.Int).SetBytes(a)
	bb := new(big.Int).SetBytes(b)
	//fmt.Printf("aa = %s\nbb=%s\n", aa, bb)
	cc := new(big.Int)
	cc.ModInverse(bb, key.P)
	rr := new(big.Int).Mul(aa, cc)
	ss := new(big.Int)
	ss.Mod(rr, key.P)
	//fmt.Printf("ss = %s\n\n", ss)
	return ss.FillBytes(result)
}

func (key *DHKey) ExpR(val []byte, result []byte) []byte {
	v := new(big.Int).SetBytes(val)
	r := new(big.Int).Exp(v, key.R, key.P)
	return r.FillBytes(result)
}

//--

func (key *DHKey) Mul(a []byte, b []byte, result []byte) []byte {
	aa := new(big.Int).SetBytes(a)
	bb := new(big.Int).SetBytes(b)
	r := new(big.Int).Mul(aa, bb)
	r.Mod(r, key.P)
	return r.FillBytes(result)
}

func hash128(i byte, j byte, z []byte) []byte {
	s := make([]byte, len(z)+2)
	s[0] = i
	s[1] = j
	copy(s[2:], z)
	r := sha256.Sum256(s)
	return r[:16]
}

func hash_long(j byte, z []byte) []byte {
	r := make([]byte, 400)

	for i := 0; i < 25; i++ {
		b := hash128(j, byte(i+1), z)
		copy(r[i*16:], b)
	}
	return r
}

func hash_short(j byte, z []byte) []byte {
	zz := make([]byte, len(z)*2+3)
	zz[0] = j
	zz[1] = byte(len(z) >> 8)
	zz[3] = byte(len(z))
	copy(zz[4:], z)
	copy(zz[4+len(z):], z)
	b := sha256.Sum256(zz)
	return b[:16]
}

func H1(z []byte) []byte {
	return hash_long(1, z)
}

func H2(z []byte) []byte {
	return hash_long(2, z)
}

func H3(z []byte) []byte {
	return hash_short(3, z)
}

func H4(z []byte) []byte {
	return hash_short(4, z)
}

func H5(z []byte) []byte {
	return hash_short(5, z)
}

func H6(z []byte) []byte {
	return hash_short(5, z)
}
