package sscp

import (
	"fmt"
	"net"
)

func ServerWrapper(conn net.Conn, id []byte, password []byte) (*Conn, error) {
	var clientHelloMessage [17]byte
	n, err := conn.Read(clientHelloMessage[:])
	if err != nil {
		return nil, err
	}
	if n != len(clientHelloMessage) {
		return nil, fmt.Errorf("sscp clientHelloMessage was only %d bytes, expected %d", n, len(clientHelloMessage))
	}
	var serverHelloMessage [17]byte
	zeroize(serverHelloMessage[:])
	if clientHelloMessage[0] != SSCONN_VERSION {
		serverHelloMessage[0] = 1
	} else {
		serverHelloMessage[0] = 0
	}
	copy(serverHelloMessage[1:], id)
	_, err = conn.Write(serverHelloMessage[:])
	if err != nil {
		return nil, err
	}
	if clientHelloMessage[0] != SSCONN_VERSION {
		return nil, fmt.Errorf("Client version mismatch: client is %d, want %d", clientHelloMessage[0], SSCONN_VERSION)
	}

	var Q [384]byte
	n, err = conn.Read(Q[:])
	if err != nil {
		return nil, err
	}
	if iszero(Q[:]) {
		return nil, fmt.Errorf("Q is null")
	}
	dhkey := NewDHKey()
	var abpw []byte
	abpw = append(abpw, clientHelloMessage[1:]...)
	abpw = append(abpw, serverHelloMessage[1:]...)
	abpw = append(abpw, password...)
	H1_abpw := H1(abpw)
	//fmt.Printf("abpw=%q\n", abpw)
	//fmt.Printf("Q=%q\n", Q)
	//fmt.Printf("H1_abpw=%q\n", H1_abpw)
	xab := dhkey.Div(Q[:], H1_abpw)
	//fmt.Printf("Q / H1(abpw)=%q\n", xab)

	var Y_S1 [384 + 16]byte
	H2_abpw := H2(abpw)
	Y := dhkey.GRMul(H2_abpw)
	xab_rb := dhkey.ExpR(xab)
	s1chal := abpw
	s1chal = append(s1chal, xab...)
	s1chal = append(s1chal, dhkey.GR.Bytes()...)
	s1chal = append(s1chal, xab_rb...)
	S1 := H3(s1chal)
	copy(Y_S1[:], Y)
	copy(Y_S1[384:], S1)

	_, err = conn.Write(Y_S1[:])
	if err != nil {
		return nil, err
	}

	var S2 [16]byte
	n, err = conn.Read(S2[:])
	if err != nil {
		return nil, err
	}
	if n != len(S2) {
		return nil, fmt.Errorf("S2 length error: got %d bytes", n)
	}
	s2check := abpw
	s2check = append(s2check, xab...)
	s2check = append(s2check, dhkey.GR.Bytes()...)
	s2check = append(s2check, xab_rb...)
	S2p := H4(s2check)
	if !isequal(S2[:], S2p[:]) {
		return nil, fmt.Errorf("S2 mismatch")
	}

	encK := H5(s2check)
	macK := H6(s2check)

	sconn := new(Conn)
	sconn.conn = conn
	copy(sconn.localId[:], id)
	copy(sconn.remoteId[:], clientHelloMessage[1:])
	copy(sconn.encKey[:], encK)
	copy(sconn.macKey[:], macK)
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
