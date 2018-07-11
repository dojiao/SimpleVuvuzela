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

	"github.com/tjfoc/gmsm/sm2"
)

const (
	EncryptLenStep       = 96
	SizeSequence         = 4
	SizeMessageBody      = 240
	SizeEncryptedMessage = SizeSequence + SizeMessageBody + EncryptLenStep
	SizeOnionMessage     = SizeEncryptedMessage + EncryptLenStep
)

var (
	doinit       = flag.Bool("init", false, "create config file")
)

type Doctrine struct {
	PublicKey []byte
	Signature []byte
}

func initServer(doctrineHome string) {
	fmt.Printf("Create directory %s\n", doctrineHome)
	err := os.Mkdir(doctrineHome, 0700)
	if err == nil {
		fmt.Printf("Created directory %s\n", doctrineHome)
	} else if !os.IsExist(err) {
		fmt.Printf("Init Server Error: %s\n", err)
	}

	fmt.Printf("--> Generating server key pair and doctrine.\n")
	if overwrite(doctrineHome) {
		writeNewDoctrine(doctrineHome)
		fmt.Printf("--> Done.\n")
	}
}

func writeNewDoctrine(doctrineHome string) {
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
	doctrineHome, err := getDoctrineHome()
	fmt.Printf("Create directory %s\n", doctrineHome)
	if err != nil {
		fmt.Printf("get user home error: %s\n", err)
		return
	}

	flag.Parse()
	if *doinit {
		initServer(doctrineHome)
		return
	}

	go preach(doctrineHome)

	privateKey, err := sm2.ReadPrivateKeyFromPem(filepath.Join(doctrineHome, "priv.pem"), nil) // 读取密钥
	if err != nil {
		fmt.Printf("read key pair error: %s\n", err)
		return
	}

	l, err := net.Listen("tcp", ":20006")
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
		// start a new goroutine to handle
		// the new connection.
		go handleConn(c, privateKey)
	}

}

func handleConn(c net.Conn, privatekey *sm2.PrivateKey) {
	defer c.Close()
	buf := make([]byte, SizeEncryptedMessage)
	n, err := c.Read(buf)
	fmt.Printf("read :%v\n", buf)
	if err != nil {
		log.Println("conn read error:", err)
		return
	}
	if n != SizeEncryptedMessage {
		log.Printf("read conn msg length error: expected %d bytes, received %d bytes\n", SizeEncryptedMessage, n)
		return
	}
	msg, err := privatekey.Decrypt(buf)
	if err != nil {
		log.Println("decrypt msg error:", err)
		return
	}
	fmt.Printf("msg is %v\n", msg)
}

func preach(doctrineHome string) {
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

	fmt.Printf("doctrine is %v\n", data)
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

func getDoctrineHome() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	return filepath.Join(u.HomeDir, ".vuvuzela_remote"), nil
}
