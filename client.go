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
	encKey   [16]byte
	macKey   [16]byte
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

func ClientWrapper(conn net.Conn, id []byte, password []byte) (*Conn, error) {
	var clientHelloMessage [17]byte
	zeroize(clientHelloMessage[:])
	clientHelloMessage[0] = SSCONN_VERSION
	copy(clientHelloMessage[1:], id)

	_, err := conn.Write(clientHelloMessage[:])
	if err != nil {
		return nil, err
	}

	var serverHelloMessage [17]byte
	zeroize(serverHelloMessage[:])
	r, err := conn.Read(serverHelloMessage[:])
	if err != nil {
		return nil, err
	}
	if r != 17 {
		return nil, fmt.Errorf("Expected 17 bytes in ServerHelloMessage, got %d", r)
	}
	if serverHelloMessage[0] != 0 {
		return nil, fmt.Errorf("ServerHelloMessage returned status %d", serverHelloMessage[0])
	}

	dhkey := NewDHKey()
	var abpw []byte
	abpw = append(abpw, clientHelloMessage[1:]...)
	abpw = append(abpw, serverHelloMessage[1:]...)
	abpw = append(abpw, password...)
	//fmt.Printf("abpw=%q\n", abpw)
	H1_abpw := H1(abpw)
	if iszero(H1_abpw) {
		return nil, NewCryptoError("Null password hash H1")
	}
	//fmt.Printf("GRa = %q\n", dhkey.GR.Bytes())
	//fmt.Printf("H1_abpw = %q\n", H1_abpw)
  var X [384]byte
  dhkey.GRMul(H1_abpw, X[:])
	//fmt.Printf("X = GRa * H1(abpw) = %q\n", X)
	//dhkey.Div(X, H1_abpw)
	//fmt.Printf("X / H1(abpw) = %q\n", XX)
	//fmt.Printf("Xlen = %d\n", len(X))

  _, err = conn.Write(X[:])
	if err != nil {
		return nil, err
	}

	var Y_S1 [384 + 16]byte
	r, err = conn.Read(Y_S1[:])
	if err != nil {
		return nil, err
	}
	if r != len(Y_S1) {
		return nil, NewCryptoError("Server returned truncated response for Y_S1")
	}
	if iszero(Y_S1[:384]) {
		return nil, NewCryptoError("Server returned null Y")
	}
	H2_abpw := H2(abpw)
  var yba [384]byte
  dhkey.Div(Y_S1[:384], H2_abpw, yba[:])
  var yba_ra [384]byte
  var gr_bytes [384]byte
  dhkey.GR.FillBytes(gr_bytes[:])
  dhkey.ExpR(yba[:], yba_ra[:])
	s1check := abpw
  s1check = append(s1check, gr_bytes[:]...)
  s1check = append(s1check, yba[:]...)
  s1check = append(s1check, yba_ra[:]...)
	s1 := H3(s1check)
	if !isequal(Y_S1[384:], s1) {
		return nil, NewCryptoError("S1 mismatch")
	}

	S2 := H4(s1check)
	_, err = conn.Write(S2)
	if err != nil {
		return nil, err
	}

	encK := H5(s1check)
	macK := H6(s1check)

	sconn := new(Conn)
	sconn.conn = conn
	copy(sconn.localId[:], id)
	copy(sconn.remoteId[:], serverHelloMessage[1:])
	copy(sconn.encKey[:], encK)
	copy(sconn.macKey[:], macK)
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
	var plen [4]byte

	n, err := conn.conn.Read(plen[:])
	if err != nil {
		return 0, err
	}
	if n != 4 {
		return 0, fmt.Errorf("Truncated read (length)")
	}
	payload_length := getInt32(plen[:])
	if payload_length < 37 {
		return 0, fmt.Errorf("Payload truncation, expected at least 37 bytes, got %d", payload_length)
	}
	if (payload_length-37)&0xF != 0 {
		return 0, fmt.Errorf("Payload encrypted data must have a length multiple of 16")
	}
	var payload []byte
	var r uint32 = 0
	for r < payload_length {
		var block [4096]byte
		var expected uint32
		var block_len uint32 = 4096

		if r+block_len > payload_length {
			expected = payload_length - r
		} else {
			expected = block_len
		}
		n, err = conn.conn.Read(block[:])
		if err != nil {
			return 0, err
		}
		if uint32(n) != expected {
			return 0, fmt.Errorf("Expected block of %d bytes of payload, got %d", expected, n)
		}
		payload = append(payload, block[:expected]...)
		r += expected
	}
	// fmt.Printf("p = %q\n", payload)

	seqnum := getInt32(payload[0:])
	if seqnum != conn.rIndex {
		return 0, NewCryptoError("Sequence number mismatch in read")
	}
  conn.rIndex++

	mac := hmac.New(sha256.New, conn.macKey[:])
	mac.Write(payload[:payload_length-16])
	// fmt.Printf("MAC data len = %d\n", payload_length-16)
	// fmt.Printf("EncPay = %q\n", payload[:payload_length-16])
	sum := mac.Sum(nil)
	if !isequal(sum[:16], payload[payload_length-16:]) {
		return 0, NewCryptoError("MAC check failed")
	}

	enc, err := aes.NewCipher(conn.encKey[:])
	if err != nil {
		return 0, err
	}
	decryption := cipher.NewCBCDecrypter(enc, payload[4:20])
	data := payload[21 : len(payload)-16]
	decryption.CryptBlocks(data, data)
	pad := payload[20]
	if len(data) < int(pad) {
		return 0, NewCryptoError("Padding value error")
	}
	for i := 0; i < int(pad); i++ {
		if data[len(data)-i-1] != pad {
			return 0, NewCryptoError("Padding value check error")
		}
	}
	mlen := len(data) - int(pad)

	conn.rBuf = make([]byte, mlen)
	copy(conn.rBuf, data[:mlen])
	return mlen, nil
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

// Packet format:
// PayloadLength (4)
// Payload:
//  - Seqnum (4)
//  - IV (16)
//  - PayloadPadLen (1)
//	- PayloadEnc (n*16)
//  - PayLoadMac (16)

func (conn *Conn) Write(b []byte) (int, error) {
	block_count := (len(b) + 15) / 16
	payload_length := uint32(4 + 16 + 1 + block_count*16 + 16)
	packet := make([]byte, 4+payload_length)
	bpad := make([]byte, block_count*16)

	// PayloadLength
	putInt32(packet[0:], payload_length)

	// Seqnum
	putInt32(packet[4:], conn.wIndex)
	conn.wIndex++

	// IV
	if _, err := io.ReadFull(rand.Reader, packet[8:24]); err != nil {
		return 0, fmt.Errorf("Could not create IV: %s", err)
	}
	pad := byte(block_count*16 - len(b))
	packet[24] = pad
	copy(bpad, b)
	for i := 0; i < int(pad); i++ {
		bpad[len(bpad)-i-1] = pad
	}
	enc, err := aes.NewCipher(conn.encKey[:])
	if err != nil {
		return 0, err
	}
	encryption := cipher.NewCBCEncrypter(enc, packet[8:24])
	encryption.CryptBlocks(packet[25:], bpad)

	mac := hmac.New(sha256.New, conn.macKey[:])
	mac.Write(packet[4 : 4+payload_length-16])
	// fmt.Printf("MAC data len=%d\n", payload_length-16)
	// fmt.Printf("EncPay = %q\n", packet[4:4+payload_length-16])

	sum := mac.Sum(nil)
	copy(packet[25+len(bpad):], sum[:16])

	//fmt.Printf("P = %q\n", packet)

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
