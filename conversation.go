package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/tjfoc/gmsm/sm2"
)

const (
	EncryptLenStep       = 96
	SizeSequence         = 4
	SizeMessageBody      = 240
	SizeEncryptedMessage = SizeSequence + SizeMessageBody + EncryptLenStep
	SizeOnionMessage     = SizeEncryptedMessage + EncryptLenStep
	RoundDelay           = 800 * time.Millisecond
	MsgPoolNum           = 10
)

var (
	roundnum    = -1
	msgpoolpool = make([]chan []byte, MsgPoolNum)
	noise       = &Laplace{
		Mu: 100,
		B:  3.0,
	}
)

func dealConn(buf *[]byte, privatekey *sm2.PrivateKey) {
	msg, err := privatekey.Decrypt(*buf)
	if err != nil {
		log.Println("decrypt msg error:", err)
		return
	}
	msgpool := msgpoolpool[roundnum%MsgPoolNum]
	msgpool <- msg
}

func roundstart() {
	go roundend()
	roundnum++
	msgpool := make(chan []byte)
	msgpoolpool[roundnum%MsgPoolNum] = msgpool
	noisenum := noise.Uint32()
	for noisenum != 1 {
		noisenum--
		generatenoise()
	}
	generatenoise()
}

func generatenoise() {
	noisebuf := make([]byte, SizeSequence+SizeMessageBody)
	newnoise, err := destPublickey.Encrypt(noisebuf)
	if err != nil {
		fmt.Printf("encrypt noise error: %s\n", err)
	}
	msgpool := msgpoolpool[roundnum%MsgPoolNum]
	msgpool <- newnoise
}

func roundend() {
	msgpool := msgpoolpool[roundnum%MsgPoolNum]
	for msg := range msgpool {
		conn, err := net.Dial("tcp", "101.200.37.186:20006")
		//conn, err := net.Dial("tcp", "211.159.187.82:20006")
		if err != nil {
			fmt.Printf("send msg error: %s\n", err)
		}
		conn.Write(msg)
		conn.Close()
	}
}
