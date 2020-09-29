package main

import (
	"github.com/omzlo/go-sscp"
	"log"
	"os"
)

func main() {
	var buffer [100]byte
	var target, token string

	if len(os.Args) < 2 {
		target = "localhost:4242"
	} else {
		target = os.Args[1]
	}

	if len(os.Args) < 3 {
		token = "password"
	} else {
		token = os.Args[2]
	}

	log.Print("connect")
	conn, err := sscp.Dial("tcp", target, []byte("client"), []byte(token))
	if err != nil {
		log.Fatal(sscp.UnsafeCryptoError(err))
	}

	for l := 0; l < len(buffer); l++ {
		for i := 0; i < l; i++ {
			buffer[i] = byte(l)
		}
		log.Printf(">>> write %d bytes", l)
		_, err = conn.Write(buffer[:l])
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
	}
	log.Print("close")
	err = conn.Close()
	if err != nil {
		log.Fatal(err)
	}
	log.Print("done")
}
