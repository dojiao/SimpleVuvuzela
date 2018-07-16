package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"github.com/tjfoc/gmsm/sm2"
)

const (
	EncryptLenStep       = 96
	SizeSequence         = 1
	SizeMessageBody      = 238
	SizeEncryptedMessage = SizeSequence + SizeMessageBody + EncryptLenStep
	SizeOnionMessage     = SizeSequence + SizeEncryptedMessage + EncryptLenStep
	RoundDelay           = 800 * time.Millisecond
)

type Doctrine struct {
	PublicKey []byte
	Signature []byte
}

func main() {
	u, err := user.Current()
	if err != nil {
		fmt.Printf("get user home error: %s\n", err)
		return
	}
	doctrineHome := filepath.Join(u.HomeDir, ".vuvuzela_client")
	_, err = os.Stat(doctrineHome)
	if os.IsNotExist(err) {
		err := os.Mkdir(doctrineHome, 0700)
		if err == nil {
			fmt.Printf("Created directory %s\n", doctrineHome)
		} else if !os.IsExist(err) {
			fmt.Printf("Init Server Error: %s\n", err)
		}
		writeNewDoctrine(doctrineHome)
	}
	//sm2.Read
	vuvuzelaPublicKey := getDestpublicKey("101.200.37.186:2718")
	remotePublicKey := getDestpublicKey("101.200.37.186:3456")
	message := []byte("你是一只傻狗")
	var messageBuf [SizeMessageBody]byte
	copy(messageBuf[:], message)
	remoteOnion, err := remotePublicKey.Encrypt(append([]byte{1}, messageBuf[:]...))
	if err != nil {
		fmt.Println("remote publickey encrypt err: ", err)
		return
	}
	vuvuzelaOnion, err := vuvuzelaPublicKey.Encrypt(append([]byte{1}, remoteOnion...))
	if err != nil {
		fmt.Println("vuvuzela publickey encrypt err: ", err)
		return
	}

	privateKey, err := sm2.ReadPrivateKeyFromPem(filepath.Join(doctrineHome, "priv.pem"), nil) // 读取密钥
	if err != nil {
		fmt.Printf("read key pair error: %s\n", err)
		return
	}

	publicKey := &privateKey.PublicKey
	der, err := sm2.MarshalSm2PublicKey(publicKey)
	if err != nil {
		fmt.Printf("malshal publickey error: %s\n", err)
		return
	}
	var dialbuf [SizeEncryptedMessage]byte
	copy(dialbuf[:], der)
	dialOnion, err := vuvuzelaPublicKey.Encrypt(append([]byte{0}, dialbuf[:]...))
	if err != nil {
		fmt.Println("vuvuzela publickey encrypt err: ", err)
		return
	}

	conn, err := net.Dial("tcp", "101.200.37.186:2719")
	if err != nil {
		fmt.Printf("dial error: %s\n", err)
		return
	}
	defer conn.Close()
	n, err := conn.Write(dialOnion)
	if err != nil {
		fmt.Printf("write error: %s\n", err)
		return
	}
	if n != SizeOnionMessage {
		fmt.Printf("write num error: %d\n", n)
		return
	}
	time.Sleep(800 * time.Millisecond)

	n, err = conn.Write(vuvuzelaOnion)
	if err != nil {
		fmt.Printf("write error: %s\n", err)
		return
	}
	if n != SizeOnionMessage {
		fmt.Printf("write num error: %d\n", n)
		return
	}
	time.Sleep(800 * time.Millisecond)
	n, err = conn.Write(vuvuzelaOnion)
	if err != nil {
		fmt.Printf("write error: %s\n", err)
		return
	}
	if n != SizeOnionMessage {
		fmt.Printf("write num error: %d\n", n)
		return
	}
	time.Sleep(5 * time.Second)
	n, err = conn.Write(vuvuzelaOnion)
	if err != nil {
		fmt.Printf("write error: %s\n", err)
		return
	}
	if n != SizeOnionMessage {
		fmt.Printf("write num error: %d\n", n)
		return
	}
	// ticker := time.NewTicker(RoundDelay).C
	// for {
	// 	select {
	// 	case <-ticker:
	// 		go func(conn net.Conn, vuvuzelaOnion []byte) {
	// 			n, err := conn.Write(vuvuzelaOnion)
	// 			if err != nil {
	// 				fmt.Printf("write error: %s\n", err)
	// 				return
	// 			}
	// 			if n != SizeOnionMessage {
	// 				fmt.Printf("write num error: %d\n", n)
	// 				return
	// 			}
	// 		}(conn, vuvuzelaOnion)
	// 	}

	// }
}

func writeNewDoctrine(doctrineHome string) {
	keypair, err := sm2.GenerateKey()
	if err != nil {
		fmt.Printf("generate key error: %s\n", err)
	}

	// 生成密钥文件
	ok, err := sm2.WritePrivateKeytoPem(filepath.Join(doctrineHome, "priv.pem"), keypair, nil)
	if ok != true {
		fmt.Printf("generate key file error: %s\n", err)
		return
	}
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

func parseDoctrine(doctrineBuf []byte) (*Doctrine, error) {
	doctrine := new(Doctrine)
	err := json.Unmarshal(doctrineBuf, doctrine)
	return doctrine, err
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
