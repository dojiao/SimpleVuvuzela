package main

import (
	"fmt"
	"io"
	"net"
	"time"

	"github.com/tjfoc/gmsm/sm2"
)

type TellWordsError struct {
	number int
}

const (
	heartbeatingDeadline time.Duration = 4 * time.Second
)

var (
	connMap = make(map[net.Conn]*sm2.PublicKey)
	//connPool []net.Conn
)

func (err TellWordsError) Error() string {
	return "sent bytes number: " + string(err.number)
}

func inConn(conn net.Conn) {
	msg, err := readMessageFromConn(conn)
	if err != nil {
		return
	}
	if msg[0] != 0 {
		return
	}
	publicKey, err := sm2.ParseSm2PublicKey(msg[1 : PublicKeyLength+1])
	if err != nil {
		fmt.Println("parse publickey err: ", err)
		return
	}
	connMap[conn] = publicKey
	// index := len(connPool)
	// connPool = append(connPool, conn)

	for {
		msg, err := readMessageFromConn(conn)
		if err != nil {
			removeConn(conn)
			return
		}
		go divertMessage(msg, conn)
	}
}

func readMessageFromConn(conn net.Conn) ([]byte, error) {
	buf := make([]byte, SizeOnionMessage)
	err := conn.SetReadDeadline(time.Now().Add(heartbeatingDeadline))
	if err != nil {
		fmt.Println("set deadline err: ", err)
		return nil, err
	}
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		if hearterr, ok := err.(net.Error); ok && hearterr.Timeout() {
			fmt.Println("conn's heart stopped")
		} else {
			fmt.Println("conn read error:", err)
		}
		return nil, err
	}
	if n != SizeOnionMessage {
		fmt.Printf("read conn msg length error: expected %d bytes, received %d bytes\n", SizeOnionMessage, n)
		return nil, err
	}
	msg, err := privateKey.Decrypt(buf)
	if err != nil {
		fmt.Println("decrypt msg error:", err)
		return nil, err
	}
	return msg, nil
}

func divertMessage(msg []byte, conn net.Conn) {
	seq := msg[0]
	switch seq {
	case 0:
		publicKey, err := sm2.ParseSm2PublicKey(msg[1 : PublicKeyLength+1])
		if err != nil {
			fmt.Println("parse publickey err: ", err)
			removeConn(conn)
			return
		}
		connMap[conn] = publicKey
	default:
		fmt.Printf("receive msg: %v\n", msg[1:])
		dealMessage(msg[1:])
	}
}

func removeConn(conn net.Conn) {
	delete(connMap, conn)
	//connPool = append(connPool[:index], connPool[index+1:]...)
}

func broadcast(msg []byte) {
	for conn, publicKey := range connMap {
		go func(conn net.Conn, publicKey *sm2.PublicKey) {
			decryptedMessage, err := publicKey.Encrypt(msg)
			if err != nil {
				fmt.Printf("encrypt error: %s\n", err)
				return
			}
			tell(conn, decryptedMessage)
		}(conn, publicKey)
	}
}

func tell(conn net.Conn, msg []byte) error {
	n, err := conn.Write(msg)
	if n != SizeOnionMessage {
		return TellWordsError{n}
	}
	return err
}

/*func heartbeat(conn net.Conn) {
	for conn, publicKey := range connMap {
		err := conn.SetReadDeadline(time.Now().Add(heartbeatingDeadline))
		if err != nil {
			fmt.Println("set deadline err: ", err)
		}
		heartbeatingbuf := make([]byte, SizeSequence+SizeMessageBody)
		heartbeatingbuf[0] = 1
		heartbeatingPackage, err := publicKey.Encrypt(heartbeatingbuf)
		if err != nil {
			fmt.Println("encrypt heartbeating package err :", err)
		}
		conn.Write(heartbeatingPackage)

	}
}*/
