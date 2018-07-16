package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"

	"github.com/tjfoc/gmsm/sm2"
)

var (
	doctrineHome string
)

type Doctrine struct {
	PublicKey []byte
	Signature []byte
}

func parseDoctrine(doctrineBuf []byte) (*Doctrine, error) {
	doctrine := new(Doctrine)
	err := json.Unmarshal(doctrineBuf, doctrine)
	return doctrine, err
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

	l, err := net.Listen("tcp", ":2718")
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
