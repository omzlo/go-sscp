package main

import (
	"github.com/omzlo/go-sscp"
	"log"
	"net"
	"os"
)

func main() {
	var listen, token string

	if len(os.Args) < 2 {
		listen = ":4242"
	} else {
		listen = os.Args[1]
	}

	if len(os.Args) < 3 {
		token = "password"
	} else {
		token = os.Args[2]
	}

	log.Print("listen")
	l, err := sscp.Listen("tcp", listen, []byte("server"), []byte(token))
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

			for {
				n, err := c.Read(buf[:])
				if err != nil {
					log.Fatal(sscp.UnsafeCryptoError(err))
				}
				log.Printf(">>> Got %d bytes: %q", n, buf[:n])
				_, err = c.Write(buf[:n])
				if err != nil {
					log.Fatal(sscp.UnsafeCryptoError(err))
				}
				log.Printf("Wrote back %d bytes", n)
			}
		}(sconn)
	}
}
