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
)

func ServerWrapper(conn net.Conn, id []byte, secret []byte) (*Conn, error) {
	var clientHelloMessage [33]byte
	n, err := conn.Read(clientHelloMessage[:])
	if err != nil {
		return nil, err
	}
	if n != len(clientHelloMessage) {
		return nil, fmt.Errorf("sscp clientHelloMessage was only %d bytes, expected %d", n, len(clientHelloMessage))
	}

	Ra := clientHelloMessage[17:]
	var Rb [16]byte
	if _, err := io.ReadFull(rand.Reader, Rb[:]); err != nil {
		return nil, err
	}
	var Key [16]byte
	if _, err := io.ReadFull(rand.Reader, Key[:]); err != nil {
		return nil, err
	}

	MK := KeyDerivation(secret, 128, 1024)
	auth := hmac.New(sha256.New, MK[0:16])
	enc, err := aes.NewCipher(MK[16:])
	if err != nil {
		return nil, fmt.Errorf("Failed to generate shared key: %s", err)
	}

	var serverHelloMessage [113]byte
	zeroize(serverHelloMessage[:])
	if clientHelloMessage[0] != SSCONN_VERSION {
		serverHelloMessage[0] = 1
	} else {
		serverHelloMessage[0] = 0
	}
	copy(serverHelloMessage[1:], id)
	copy(serverHelloMessage[17:], clientHelloMessage[1:])
	copy(serverHelloMessage[33:], Ra)
	copy(serverHelloMessage[49:], Rb[:])
	enc.Encrypt(serverHelloMessage[65:], Key[:])
	auth.Write(serverHelloMessage[1:81])
	mac1 := auth.Sum(nil)
	copy(serverHelloMessage[81:], mac1)
	//fmt.Printf("Mac of %x\nis\n%x\n", serverHelloMessage[1:81], mac1)

	_, err = conn.Write(serverHelloMessage[:])
	if err != nil {
		return nil, err
	}
	if clientHelloMessage[0] != SSCONN_VERSION {
		return nil, fmt.Errorf("Client version mismatch: client is %d, want %d", clientHelloMessage[0], SSCONN_VERSION)
	}

	var clientHelloFinalize [64]byte
	n, err = conn.Read(clientHelloFinalize[:])
	if err != nil {
		return nil, err
	}
	if n != len(clientHelloFinalize) {
		return nil, fmt.Errorf("sscp clientHelloFinalize was only %d bytes, expected %d", n, len(clientHelloFinalize))
	}

	auth.Reset()
	auth.Write(clientHelloFinalize[:32])
	mac2 := auth.Sum(nil)
	if !hmac.Equal(mac2, clientHelloFinalize[32:]) {
		return nil, fmt.Errorf("ClientHelloFinalize failed authentication check")
	}

	if !AreEqual(clientHelloFinalize[:16], clientHelloMessage[1:17]) {
		return nil, fmt.Errorf("ClientHelloFinalize identity mismatch, got %x, expected %x", clientHelloMessage[1:17], clientHelloFinalize[:16])
	}
	if !AreEqual(clientHelloFinalize[16:32], Rb[:]) {
		return nil, fmt.Errorf("ClientHelloFinalize nonce mismatch, got %x, expected %x", clientHelloMessage[16:32], Rb)
	}

	sconn := new(Conn)
	sconn.conn = conn
	copy(sconn.localId[:], id)
	copy(sconn.remoteId[:], clientHelloMessage[1:])
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

type Listener struct {
	listener net.Listener
	id       []byte
	password []byte
}

func Listen(network, address string, id []byte, password []byte) (*Listener, error) {
	l, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	listener := new(Listener)
	listener.listener = l
	listener.id = make([]byte, len(id))
	copy(listener.id, id)
	listener.password = make([]byte, len(password))
	copy(listener.password, password)
	return listener, nil
}

func (l *Listener) Accept() (*Conn, error) {
	conn, err := l.listener.Accept()
	if err != nil {
		return nil, err
	}
	rconn, err := ServerWrapper(conn, l.id, l.password)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return rconn, nil
}

func (l *Listener) Close() error {
	return l.listener.Close()
}

func (l *Listener) Addr() net.Addr {
	return l.listener.Addr()
}
