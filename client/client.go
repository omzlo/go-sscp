package main

import (
	"github.com/omzlo/sscp"
	"log"
)

func main() {
	log.Print("connect")
	conn, err := sscp.Dial("tcp", "localhost:4242", []byte("client"), []byte("password"))
	if err != nil {
		log.Fatal(sscp.UnsafeCryptoError(err))
	}
	log.Print("write")
	_, err = conn.Write([]byte("Hello there"))
	if err != nil {
		log.Fatal(sscp.UnsafeCryptoError(err))
	}
	log.Print("read")
	var buf [1000]byte
	n, err := conn.Read(buf[:])
	if err != nil {
		log.Fatal(sscp.UnsafeCryptoError(err))
	}
	log.Printf("Got %d bytes: %q", n, buf[:n])
	log.Print("close")
	err = conn.Close()
	if err != nil {
		log.Fatal(err)
	}
	log.Print("done")
}
