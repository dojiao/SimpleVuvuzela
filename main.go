package main

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"github.com/tjfoc/gmsm/sm2"
)

var (
	doinit        = flag.Bool("init", false, "create config file")
	doctrineHome  string
	destPublickey = getDestPublickey()
)

type Doctrine struct {
	PublicKey []byte
	Signature []byte
}

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

func writeNewDoctrine() {
	keypair, err := sm2.GenerateKey()
	if err != nil {
		fmt.Printf("generate key error: %s\n", err)
	}
	publickey := &keypair.PublicKey
	// 生成密钥文件
	ok, err := sm2.WritePrivateKeytoPem(filepath.Join(doctrineHome, "priv.pem"), keypair, nil)
	if ok != true {
		fmt.Printf("generate key file error: %s\n", err)
		return
	}

	letter := []byte("thankyou")
	signature, err := keypair.Sign(rand.Reader, letter, nil)
	if err != nil {
		fmt.Printf("generate signature error: %s\n", err)
		return
	}

	der, err := sm2.MarshalSm2PublicKey(publickey)
	if err != nil {
		fmt.Printf("malshal publickey error: %s\n", err)
		return
	}
	doctrine := &Doctrine{
		PublicKey: der,
		Signature: signature,
	}
	buf, err := json.Marshal(doctrine)
	if err != nil {
		fmt.Printf("template error: %s\n", err)
		return
	}

	err = ioutil.WriteFile(filepath.Join(doctrineHome, "doctrine.json"), buf, 0600)
	if err != nil {
		fmt.Printf("write file error: %s\n", err)
		return
	}
	fmt.Printf("! Wrote new config file: %s\n", filepath.Join(doctrineHome, "doctrine.json"))
}

func overwrite(path string) bool {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return true
	}
	if err != nil {
		fmt.Errorf("%s\n", err)
	}
	fmt.Printf("%s already exists.\n", path)
	fmt.Printf("Overwrite (y/N)? ")
	var yesno [3]byte
	n, err := os.Stdin.Read(yesno[:])
	if err != nil {
		fmt.Errorf("%s\n", err)
	}
	if n == 0 {
		return false
	}
	if yesno[0] != 'y' && yesno[0] != 'Y' {
		return false
	}
	return true
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

	privateKey, err := sm2.ReadPrivateKeyFromPem(filepath.Join(doctrineHome, "priv.pem"), nil) // 读取密钥
	if err != nil {
		fmt.Printf("read key pair error: %s\n", err)
		return
	}

	l, err := net.Listen("tcp", ":4567")
	if err != nil {
		fmt.Println("listen error:", err)
		return
	}
	ticker := time.NewTicker(RoundDelay).C
	go func() {
		for {
			select {
			case <-ticker:
				roundstart()
			}

		}
	}()

	for {
		c, err := l.Accept()
		if err != nil {
			fmt.Println("accept error:", err)
			break
		}
		// start a new goroutine to handle
		// the new connection.
		go dealConn(c, privateKey)
	}

}

func handleConn(c net.Conn, privatekey *sm2.PrivateKey) {
	defer c.Close()
	for {
		var buf = make([]byte, 10)
		log.Println("start to read from conn")
		n, err := c.Read(buf)
		if err != nil {
			log.Println("conn read error:", err)
			return
		}
		log.Printf("read %d bytes, content is %s\n", n, string(buf[:n]))
	}
}

func preach() {
	doctrinePath := filepath.Join(doctrineHome, "doctrine.json")
	data, err := ioutil.ReadFile(doctrinePath)
	if err != nil {
		fmt.Printf("read doctrine error: %s\n", err)
		return
	}
	doctrine := new(Doctrine)
	err = json.Unmarshal(data, doctrine)
	if err != nil {
		fmt.Printf("parse doctrine error: %s\n", err)
		return
	}

	l, err := net.Listen("tcp", ":3456")
	if err != nil {
		fmt.Println("listen error:", err)
		return
	}
	for {
		c, err := l.Accept()
		if err != nil {
			fmt.Println("accept error:", err)
			break
		}
		c.Write(data)
		c.Close()
	}
}

func getDestPublickey() *sm2.PublicKey {
	//conn, err := net.Dial("tcp", "211.159.187.82:3456")
	conn, err := net.Dial("tcp", "101.200.37.186:3456")
	if err != nil {
		log.Printf("dial error: %s", err)
		return nil
	}
	doctrinebuf := make([]byte, 251)
	_, err = conn.Read(doctrinebuf[:])
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			fmt.Println("read timeout:", err)
		} else {
			fmt.Println("read publickey error:", err)
		}
	}
	fmt.Printf("received doctrine is %v\n", doctrinebuf)
	doctrine := new(Doctrine)
	err = json.Unmarshal(doctrinebuf, doctrine)
	if err != nil {
		log.Printf("unmarshal doctrine error: %s", err)
		return nil
	}
	signature := doctrine.Signature
	publickeybuf := doctrine.PublicKey
	fmt.Printf("publickey is %v\n", publickeybuf)
	publickey, err := sm2.ParseSm2PublicKey(publickeybuf)
	if err != nil {
		log.Printf("parse publickey error: %s", err)
		return nil
	}
	signaturemsg := []byte("thankyou")
	if publickey.Verify(signaturemsg, signature) {
		return publickey
	}
	return nil
}
