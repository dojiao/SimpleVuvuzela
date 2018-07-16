package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"github.com/tjfoc/gmsm/sm2"
)

const (
	PublicKeyLength = 91
)

var (
	doinit        = flag.Bool("init", false, "create config file")
	destPublicKey = getDestpublicKey("101.200.37.186:3456")
	privateKey    *sm2.PrivateKey
)

func initServer() {
	err := os.Mkdir(doctrineHome, 0700)
	if err == nil {
		fmt.Printf("Created directory %s\n", doctrineHome)
	} else if !os.IsExist(err) {
		fmt.Printf("Init Server Error: %s\n", err)
	}

	fmt.Printf("--> Generating server key pair and doctrine.\n")
	if overwrite(doctrineHome) {
		writeNewDoctrine()
		fmt.Printf("--> Done.\n")
	}
}

func main() {
	flag.Parse()

	u, err := user.Current()
	if err != nil {
		fmt.Printf("get user home error: %s\n", err)
		return
	}
	doctrineHome = filepath.Join(u.HomeDir, ".vuvuzela")

	if *doinit {
		initServer()
		return
	}

	go preach()

	privateKey, err = sm2.ReadPrivateKeyFromPem(filepath.Join(doctrineHome, "priv.pem"), nil) // 读取密钥
	if err != nil {
		fmt.Printf("read key pair error: %s\n", err)
		return
	}

	l, err := net.Listen("tcp", ":2719")
	if err != nil {
		fmt.Println("listen error:", err)
		return
	}
	ticker := time.NewTicker(RoundDelay).C
	go func() {
		for {
			select {
			case <-ticker:
				go roundstart()
			}

		}
	}()

	for {
		conn, err := l.Accept()
		if err != nil {
			fmt.Printf("accept error: %s\n", err)
			break
		}
		go inConn(conn)
	}

}

func getDestpublicKey(ip string) *sm2.PublicKey {
	//conn, err := net.Dial("tcp", "211.159.187.82:3456")
	conn, err := net.Dial("tcp", ip)
	if err != nil {
		fmt.Printf("dial error: %s\n", err)
		return nil
	}
	doctrineBuf := make([]byte, 251)
	_, err = conn.Read(doctrineBuf[:])
	conn.Close()
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			fmt.Printf("read timeout: %s\n", err)
		} else {
			fmt.Printf("read publicKey error: %s\n", err)
		}
	}

	doctrine, err := parseDoctrine(doctrineBuf)
	if err != nil {
		fmt.Printf("unmarshal doctrine error: %s\n", err)
		return nil
	}
	signature := doctrine.Signature
	publicKeybuf := doctrine.PublicKey
	fmt.Printf("publicKey is %v\n", publicKeybuf)

	publicKey, err := sm2.ParseSm2PublicKey(publicKeybuf)
	if err != nil {
		fmt.Println("parse publickey err: ", err)
		return nil
	}
	signaturemsg := []byte("thankyou")
	if publicKey.Verify(signaturemsg, signature) {
		return publicKey
	}
	fmt.Printf("wrong signature for doctrine: %v\n", doctrineBuf)
	return nil
}
