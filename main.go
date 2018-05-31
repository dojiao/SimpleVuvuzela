package SimpleVuvuzela

import (
	"flag"
	"text/template"
	"vuvuzela.io/alpenhorn/encoding/toml"
	"github.com/tjfoc/gmsm/sm2"
	"os/user"
	"fmt"
	"path/filepath"
	"os"
	"bytes"
	"io/ioutil"
	"crypto/rand"
	"net"
	"log"
)

var (
	doinit = flag.Bool("init", false, "create config file")

	funcMap = template.FuncMap{
		"base32": toml.EncodeBytes,
	}

	noise = &Laplace{
		Mu: 100,
		B:  3.0,
	}
)

const doctrineTemplate = `# Vuvuzela server doctrine
publicKey  = {{.PublicKey | base32 | printf "%q"}}
Signature  = {{.Signature | base32 | printf "%q"}}
`

type Doctrine struct {
	PublicKey  []byte
	Signature  []byte
}

func initServer(){
	u, err := user.Current()
	if err != nil {
		fmt.Errorf("Init Server Error: %s\n", err)
	}
	doctrineHome := filepath.Join(u.HomeDir, ".vuvuzela")

	err = os.Mkdir(doctrineHome, 0700)
	if err == nil {
		fmt.Printf("Created directory %s\n", doctrineHome)
	} else if !os.IsExist(err) {
		fmt.Errorf("Init Server Error: %s\n", err)
	}

	fmt.Printf("--> Generating server key pair and doctrine.\n")
	doctrinePath := filepath.Join(doctrineHome)
	if overwrite(doctrinePath) {
		writeNewDoctrine(doctrinePath)
		fmt.Printf("--> Done.\n")
	}
}


func writeNewDoctrine(doctrineHome string) {
	keypair, err := sm2.GenerateKey()
	if err != nil {
		panic(err)
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
		PublicKey:  der,
		Signature:  signature,
	}

	tmpl := template.Must(template.New("doctrine").Funcs(funcMap).Parse(doctrineTemplate))

	buf := new(bytes.Buffer)
	err = tmpl.Execute(buf, doctrine)
	if err != nil {
		fmt.Printf("template error: %s\n", err)
		return
	}

	err = ioutil.WriteFile(filepath.Join(doctrineHome, "doctrine.json"), buf.Bytes(), 0600)
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

func main(){
	flag.Parse()

	if *doinit {
		initServer()
		return
	}

	u, err := user.Current()
	if err != nil {
		fmt.Printf("write file error: %s\n", err)
		return
	}
	doctrineHome := filepath.Join(u.HomeDir, ".vuvuzela")

	doctrinePath := filepath.Join(doctrineHome, "doctrine.json")
	data, err := ioutil.ReadFile(doctrinePath)
	if err != nil {
		fmt.Printf("read doctrine error: %s\n", err)
		return
	}
	doctrine := new(Doctrine)
	err = toml.Unmarshal(data, doctrine)
	if err != nil {
		fmt.Printf("parse doctrine error: %s\n", err)
		return
	}

	privateKey, err := sm2.ReadPrivateKeyFromPem(filepath.Join(doctrineHome, "priv.pem"), nil) // 读取密钥
	if err != nil {
		fmt.Printf("read key pair error: %s\n", err)
		return
	}

	l, err := net.Listen("tcp", ":8888")
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