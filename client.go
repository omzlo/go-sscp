package sscp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"time"
)

var SSCONN_VERSION byte = 1

type Conn struct {
	conn     net.Conn
	localId  [16]byte
	remoteId [16]byte
	Cipher   cipher.AEAD
	rIndex   uint32
	wIndex   uint32
	rBuf     []byte
}

func zeroize(b []byte) {
	for i := 0; i < len(b); i++ {
		b[i] = 0
	}
}
func iszero(b []byte) bool {
	for i := 0; i < len(b); i++ {
		if b[i] != 0 {
			return false
		}
	}
	return true
}
func isequal(a, b []byte) bool {
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

func ClientWrapper(conn net.Conn, id []byte, secret []byte) (*Conn, error) {
	var clientHelloMessage [33]byte
	var Ra [16]byte

	zeroize(clientHelloMessage[:])
	clientHelloMessage[0] = SSCONN_VERSION
	copy(clientHelloMessage[1:17], id)

	if _, err := io.ReadFull(rand.Reader, Ra[:]); err != nil {
		return nil, err
	}
	copy(clientHelloMessage[17:], Ra[:])

	_, err := conn.Write(clientHelloMessage[:])
	if err != nil {
		return nil, err
	}

	var serverHelloMessage [113]byte
	zeroize(serverHelloMessage[:])
	r, err := conn.Read(serverHelloMessage[:])
	if err != nil {
		return nil, err
	}

	if r != 113 {
		return nil, fmt.Errorf("Expected 113 bytes in ServerHelloMessage, got %d", r)
	}
	if serverHelloMessage[0] != 0 {
		return nil, fmt.Errorf("ServerHelloMessage returned status %d", serverHelloMessage[0])
	}

	var MK []byte
	//if len(secret) < 16 {
	//	MK = KeyDerivation(secret, KeyDerivationDefaultWidth, KeyDerivationDefaultDepth)
	//} else {
	x := sha256.Sum256([]byte(secret))
	MK = x[:]
	//}

	auth := hmac.New(sha256.New, MK[0:16])
	auth.Write(serverHelloMessage[1:81])
	mac1 := auth.Sum(nil)

	//fmt.Printf("Mac of\n%x is\n%x\nGot %x\n", serverHelloMessage[1:81], mac1, serverHelloMessage[81:])

	if !hmac.Equal(mac1, serverHelloMessage[81:]) {
		return nil, fmt.Errorf("ServerHelloMessage authentication failed")
	}

	if !AreEqual(serverHelloMessage[17:33], clientHelloMessage[1:17]) {
		return nil, fmt.Errorf("ServerHelloMessage identity mismatch, got %x, expected %x", serverHelloMessage[17:33], clientHelloMessage[1:17])
	}
	if !AreEqual(serverHelloMessage[33:49], Ra[:]) {
		return nil, fmt.Errorf("ServerHelloMessage nonce mismatch, got %x, expected %x", clientHelloMessage[16:32], Ra)
	}

	enc, err := aes.NewCipher(MK[16:])
	if err != nil {
		return nil, fmt.Errorf("Failed to decryt shared key: %s", err)
	}

	var Rb [16]byte
	var Key [16]byte

	copy(Rb[:], serverHelloMessage[49:])

	enc.Decrypt(Key[:], serverHelloMessage[65:])

	var clientHelloFinalize [64]byte
	copy(clientHelloFinalize[:16], id)
	copy(clientHelloFinalize[16:], Rb[:])
	auth.Reset()
	auth.Write(clientHelloFinalize[:32])
	mac2 := auth.Sum(nil)
	copy(clientHelloFinalize[32:], mac2)

	_, err = conn.Write(clientHelloFinalize[:])
	if err != nil {
		return nil, err
	}

	//encK := PseudoRandomFunc1(Key[:])
	//macK := PseudoRandomFunc2(Key[:])

	sconn := new(Conn)
	sconn.conn = conn
	copy(sconn.localId[:], id)
	copy(sconn.remoteId[:], serverHelloMessage[1:17])
	//copy(sconn.Key[:], Key)
	//copy(sconn.macKey[:], macK)
	block, err := aes.NewCipher(Key[:])
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	sconn.Cipher = aesgcm
	sconn.rIndex = 0
	sconn.wIndex = 0
	return sconn, nil

}

func Dial(network string, addr string, id []byte, password []byte) (*Conn, error) {
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}

	sconn, err := ClientWrapper(conn, id, password)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return sconn, nil
}

func putInt32(dest []byte, v uint32) {
	dest[0] = byte(v >> 24)
	dest[1] = byte(v >> 16)
	dest[2] = byte(v >> 8)
	dest[3] = byte(v)
}

func getInt32(src []byte) uint32 {
	return (uint32(src[0]) << 24) | (uint32(src[1]) << 16) | (uint32(src[2]) << 8) | uint32(src[3])
}

func (conn *Conn) readPacket() (int, error) {
	var aux [8]byte

	n, err := conn.conn.Read(aux[:])
	if err != nil {
		return 0, err
	}
	if n != 8 {
		return 0, fmt.Errorf("Truncated packet header")
	}

	payload_length := getInt32(aux[0:4])
	if payload_length < 16 {
		return 0, fmt.Errorf("Payload truncation: expected at last 16 bytes")
	}
	payload_length -= 4

	seqnum := getInt32(aux[4:8])
	if seqnum != conn.rIndex {
		return 0, fmt.Errorf("Sequence number mismatch in read, expected %d, got %d. Header=%v", conn.rIndex, seqnum, aux)
	}
	conn.rIndex++

	var payload []byte
	var rcurrent uint32 = 0
	for rcurrent < payload_length {
		var block [4096]byte
		var expected uint32
		var block_len uint32 = 4096

		if rcurrent+block_len > payload_length {
			expected = payload_length - rcurrent
		} else {
			expected = block_len
		}
		n, err = conn.conn.Read(block[:expected])
		if err != nil {
			return 0, err
		}
		if n < 0 {
			return 0, fmt.Errorf("Expected block of %d bytes of payload at offset %d, got %d", expected, rcurrent, n)
		}

		payload = append(payload, block[:n]...)
		rcurrent += uint32(n)
	}

	// fmt.Fprintf(os.Stderr, "> %v %v\n", aux, payload)

	nonce := payload[:12]
	ciphertext := payload[12:]
	plaintext, err := conn.Cipher.Open(nil, nonce, ciphertext, aux[4:8])
	if err != nil {
		return 0, NewCryptoError(err.Error())
	}

	conn.rBuf = plaintext
	return len(plaintext), nil
}

func (conn *Conn) Read(b []byte) (int, error) {
	var err error
	rblen := len(conn.rBuf)

	if rblen == 0 {
		rblen, err = conn.readPacket()
		if err != nil {
			return 0, err
		}
	}
	copy(b, conn.rBuf)
	if rblen >= len(b) {
		conn.rBuf = conn.rBuf[len(b):]
		return len(b), nil
	}
	conn.rBuf = conn.rBuf[:0]
	return rblen, nil
}

func (conn *Conn) Write(b []byte) (int, error) {
	aux := make([]byte, 8)

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return 0, err
	}

	// Seqnum
	putInt32(aux[4:8], conn.wIndex)
	conn.wIndex++

	ciphertext := conn.Cipher.Seal(nil, nonce, b, aux[4:8])

	// PayloadLength = len(ciphertext) + len(nounce) + len(seqnum)
	putInt32(aux[0:4], uint32(len(ciphertext)+12+4))

	packet := make([]byte, len(ciphertext)+len(aux)+12)
	copy(packet, aux)
	copy(packet[8:], nonce)
	copy(packet[20:], ciphertext)

	// fmt.Fprintf(os.Stderr, "< %v\n", packet)
	return conn.conn.Write(packet)
}

func (conn *Conn) LocalAddr() net.Addr {
	return conn.conn.LocalAddr()
}

func (conn *Conn) RemoteAddr() net.Addr {
	return conn.conn.RemoteAddr()
}

func (conn *Conn) SetDeadline(t time.Time) error {
	return conn.conn.SetDeadline(t)
}

func (conn *Conn) SetReadDeadline(t time.Time) error {
	return conn.conn.SetReadDeadline(t)
}

func (conn *Conn) SetWriteDeadline(t time.Time) error {
	return conn.conn.SetWriteDeadline(t)
}

func (conn *Conn) Close() error {
	return conn.conn.Close()
}
