package main

import (
	"github.com/omzlo/go-sscp"
	"log"
	"net"
)

func main() {
	log.Print("listen")
	l, err := sscp.Listen("tcp", ":4242", []byte("server"), []byte("password"))
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	for {
		log.Print("wait")
		sconn, err := l.Accept()
		if err != nil {
			log.Fatal(sscp.UnsafeCryptoError(err))
		}
		/*
			sconn, err := sscp.ServerWrapper(conn, []byte("Server"), []byte("password"))
			if err != nil {
				log.Fatal(err)
			}
		*/
		log.Print("Connected")
		go func(c net.Conn) {
			var buf [1000]byte
			n, err := c.Read(buf[:])
			if err != nil {
				log.Fatal(sscp.UnsafeCryptoError(err))
			}
			log.Printf("Got %d bytes: %q", n, buf[:n])
			_, err = c.Write(buf[:n])
			if err != nil {
				log.Fatal(sscp.UnsafeCryptoError(err))
			}
		}(sconn)
	}
}
