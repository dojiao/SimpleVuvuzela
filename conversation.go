package SimpleVuvuzela

import (
	"time"
	"net"
	"github.com/tjfoc/gmsm/sm2"
	"log"
)

const (
	EncryptLenStep			 = 96
	SizeSequence			 = 4
	SizeMessageBody          = 240
	SizeEncryptedMessage	 = SizeSequence + SizeMessageBody + EncryptLenStep
	SizeOnionMessage		 = SizeEncryptedMessage + EncryptLenStep
	MsgLenExcepted 		     = SizeOnionMessage
	RoundDelay				 = 800 * time.Millisecond
)

func dealConn(c net.Conn, privatekey sm2.PrivateKey){
	buf := make([]byte, MsgLenExcepted)
	n, err := c.Read(buf)
	if err != nil {
		log.Println("conn read error:", err)
		return
	}
	if n != MsgLenExcepted {
		log.Printf("read conn msg length error: expected %d bytes, received %d bytes\n", MsgLenExcepted, n)
		return
	}
	seq := buf[:4]

}
