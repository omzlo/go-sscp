package sscp

import (
	"crypto/sha256"
)

const (
	KeyDerivationDefaultWidth = 128
	KeyDerivationDefaultDepth = 128
)

func AreEqual(a []byte, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func KeyDerivation(secret []byte, width int, depth int) []byte {
	var rblock [32]byte
	var sblock [68]byte

	hsecret := sha256.Sum256(secret)

	for i := 0; i < len(rblock); i++ {
		rblock[i] = 0
	}

	row := make([]byte, 32*width)

	for j := 0; j < depth; j++ {
		copy(sblock[36:], hsecret[:])
		sblock[0] = byte(j >> 24)
		sblock[1] = byte(j >> 16)
		sblock[2] = byte(j >> 8)
		sblock[3] = byte(j)
		for i := width - 1; i >= 0; i-- {
			copy(sblock[4:36], rblock[:])
			h := sha256.Sum256(sblock[:])
			copy(row[i*32:], h[:])
			copy(rblock[:], h[:])
		}
		hrow := sha256.Sum256(row)
		copy(rblock[:], hrow[:])
	}
	return rblock[:]
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

func PseudoRandomFunction1(s []byte) []byte {
	return hash_short(1, s)
}

func PseudoRandomFunction2(s []byte) []byte {
	return hash_short(2, s)
}
