package sscp

import (
	"testing"
)

const (
	BYTE_LEN     = 384
	BIT_LEN      = BYTE_LEN * 8
)

func TestSizes(t *testing.T) {
	dhkey := NewDHKey()
	if dhkey.P.BitLen() != BIT_LEN {
		t.Errorf("DHKey P length is incorrect: %d", dhkey.P.BitLen())
	}
}

func TestClientServer(t *testing.T) {
  l, err := Listen("tcp", ":4242", []byte("server"), []byte("password"))
  if err != nil {
    t.Fatal(err)
  }
  defer l.Close()

  go func() {
    t.Logf("S: Accepting")
    for {
      sconn, err := l.Accept()
      if err != nil {
        t.Fatal(UnsafeCryptoError(err))
      }
      t.Logf("S: Connected")

      var buf [10000]byte
      n, err := sconn.Read(buf[:])
      if err != nil {
        t.Fatal(UnsafeCryptoError(err))
      }
      t.Logf("S: Got %d bytes", n)
      _, err = sconn.Write(buf[:n])
      if err != nil {
        t.Fatal(UnsafeCryptoError(err))
      }
      sconn.Close()
      if n>8192 {
        break
      }
    }
    t.Logf("S: Ending it all.") 
  }()

  for l:=0; l<=13; l++ {

    length := (1<<l)+1
    message := make([]byte, length)
    for i:=0;i<length;i++ {
      message[i]=byte(l)
    }

    conn, err := Dial("tcp", "localhost:4242", []byte("client"), []byte("password"))
    if err != nil {
      t.Fatal(UnsafeCryptoError(err))
    }


    t.Logf("C: write %d", length)
    _, err = conn.Write(message)
    if err != nil {
      t.Fatal(UnsafeCryptoError(err))
    }
    t.Log("C: read")
    var buf [10000]byte
    n, err := conn.Read(buf[:])
    if err != nil {
      t.Fatal(UnsafeCryptoError(err))
    }
    t.Logf("C: Got %d bytes", n)
    t.Log("C: close")
    err = conn.Close()
    if err != nil {
      t.Fatal(err)
    }
  }
  t.Log("C: Ending it all")
}

const PingMax = 300

func TestClientServerPingPong(t *testing.T) {
  l, err := Listen("tcp", ":4242", []byte("server"), []byte("password"))
  if err != nil {
    t.Fatal(err)
  }
  defer l.Close()

  go func() {
    t.Logf("S: Accepting") 
    sconn, err := l.Accept()
    if err != nil {
      t.Fatal(UnsafeCryptoError(err))
    }
    t.Logf("S: Connected")

    for {
      var buf [1000]byte
      n, err := sconn.Read(buf[:])
      if err != nil {
        t.Fatal(UnsafeCryptoError(err))
      }
      t.Logf("S: Got %d bytes, sending %d", n, n+1)
      buf[n] = byte(n)
      _, err = sconn.Write(buf[:n+1])
      if err != nil {
        t.Fatal(UnsafeCryptoError(err))
      }
      if n+1==PingMax {
        break
      }
    }
    sconn.Close()
    t.Logf("S: Closing and ending it all")
  }()

  t.Logf("C: Dialing...")

  conn, err := Dial("tcp", "localhost:4242", []byte("client"), []byte("password"))
  if err != nil {
    t.Fatal(UnsafeCryptoError(err))
  }

  var sbuf [1000]byte
  var rbuf [1000]byte

  for l:=1; l<PingMax; l++ {
    for i:=0;i<l;i++ {
      sbuf[i]=byte(i)
    }

    t.Logf("C: write %d", l)
    _, err = conn.Write(sbuf[:l])
    if err != nil {
      t.Fatal(UnsafeCryptoError(err))
    }
    t.Log("C: read")
    n, err := conn.Read(rbuf[:])
    if err != nil {
      t.Fatal(UnsafeCryptoError(err))
    }
    t.Logf("C: Got %d bytes", n)
  }
  t.Log("C: close")
  err = conn.Close()
  if err != nil {
    t.Fatal(err)
  }
  t.Log("C: ending it all")
}


