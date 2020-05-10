package scanner

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func Test_ulimit(t *testing.T) {
	limit := ulimit()
	t.Logf("Limit is %d", limit)
}

func Test_scanPort_open(t *testing.T) {
	port := 5959

	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			t.Log(err)
			return
		}
		defer conn.Close()
		time.Sleep(10 * time.Second)
	}()

	result := scanPort(DefaultDialer, "127.0.0.1", port, DefaultTimeoutPerPort)
	if !result.Open {
		t.Fatalf("Expected port %d to be open", port)
	}
}

func Test_scanPort_closed(t *testing.T) {
	port := 5858

	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	listener.Close()

	result := scanPort(DefaultDialer, "127.0.0.1", port, DefaultTimeoutPerPort)
	if result.Open {
		t.Fatalf("Expected port %d to be closed", port)
	}
}

func Test_scanPort_Run(t *testing.T) {
	port := 5959

	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			t.Log(err)
			return
		}
		defer conn.Close()
		time.Sleep(10 * time.Second)
	}()

	for result := range Run(DefaultDialer, "127.0.0.1", 5000, 6000, DefaultTimeoutPerPort) {
		if result.Port == port {
			if !result.Open {
				t.Fatalf("Expected open port %d to be open, but was closed", port)
			}
		} else {
			if result.Open {
				t.Errorf("Unexpected open port %d", port)
			}
		}
	}
}

func Test_scanPort_Run_sameFromAndToPort(t *testing.T) {
	port := 5959

	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			t.Log(err)
			return
		}
		defer conn.Close()
		time.Sleep(10 * time.Second)
	}()

	for result := range Run(DefaultDialer, "127.0.0.1", 5959, 5959, DefaultTimeoutPerPort) {
		if result.Port == port {
			if !result.Open {
				t.Fatalf("Expected open port %d to be open, but was closed", port)
			}
		} else {
			if result.Open {
				t.Errorf("Unexpected open port %d", port)
			}
		}
	}
}

func Test_scanPort_Run_withSSHBastion(t *testing.T) {
	// setp fake service on localhost
	serviceReady := make(chan bool, 1)

	port := 5959

	go func() {
		listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			panic(err)
		}
		defer listener.Close()
		serviceReady <- true
		conn, err := listener.Accept()
		if err != nil {
			t.Log(err)
			return
		}
		defer conn.Close()
		time.Sleep(10 * time.Second)
	}()

	// setup test SSH server on localhost:2222

	serverReady := make(chan bool, 1)

	go func() {
		private, err := genRSASSHHostKey()
		if err != nil {
			panic(err)
		}

		config := &ssh.ServerConfig{
			PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
				if conn.User() != "root" {
					return nil, fmt.Errorf("not root user")
				}
				if subtle.ConstantTimeCompare([]byte("password"), password) != 1 {
					return nil, fmt.Errorf("bad password")
				}
				return nil, nil
			},
		}

		config.AddHostKey(private)

		log.Println("Starting test SSH server")
		listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:2222"))
		if err != nil {
			panic(err)
		}
		defer listener.Close()

		log.Println("Accepting SSH connection")
		serverReady <- true
		conn, err := listener.Accept()
		log.Println("Accepted SSH connection")

		log.Println("Performing SSH handshake")
		sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
		if err != nil {
			panic(err)
		}
		if err != nil {
			panic(err)
		}
		defer sshConn.Close()

		go ssh.DiscardRequests(reqs)

		log.Println("Serving SSH channel reqs")
		for newChan := range chans {
			if newChan.ChannelType() != "direct-tcpip" {
				log.Printf("New direct-tcpip chan req %#+v", newChan)
				panic(fmt.Sprintf("Expected new chan req to be 'direct-tcpip', got %q", newChan.ChannelType()))
			}

			msg := channelOpenDirectMsg{}

			err := ssh.Unmarshal(newChan.ExtraData(), &msg)
			if err != nil {
				panic(err)
			}

			log.Printf("channelOpenDirectMsg %#+v", msg)

			// spot check

			// the request remote addr to connect to should be localhost
			if msg.Raddr != "127.0.0.1" {
				panic(fmt.Sprintf("Unexpect remote address request: %#+v", msg.Raddr))
			}

			// the request remote port to connect to should be 5959
			if int(msg.Rport) != 5959 {
				panic(fmt.Sprintf("Unexpect remote port request: %#+v", msg.Rport))
			}

			// perform connection
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", msg.Raddr, int(msg.Rport)), time.Second*10)
			if err != nil {
				panic(err)
			}
			conn.Close()

			// Accepting the channel is enough to pass the test!
			acceptedChan, chanReqs, err := newChan.Accept()
			if err != nil {
				panic(err)
			}
			defer acceptedChan.Close()

			for req := range chanReqs {
				log.Printf("New direct-tcpip nested chan req %#+v", req)
			}
		}

		time.Sleep(10 * time.Second)

		log.Println("Closing SSH server")
	}()

	<-serverReady
	<-serviceReady

	sshBastionDialer, err := NewSSHBastionScanner("127.0.0.1:2222", &ssh.ClientConfig{
		User:            "root",
		Auth:            []ssh.AuthMethod{ssh.Password("password")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sshBastionDialer.Close()

	for result := range Run(sshBastionDialer, "127.0.0.1", 5959, 5959, DefaultTimeoutPerPort) {
		if result.Port == port {
			if !result.Open {
				t.Fatalf("Expected open port %d to be open, but was closed", port)
			}
		} else {
			if result.Open {
				t.Errorf("Unexpected open port %d", port)
			}
		}
	}
}

// RFC 4254 7.2
type channelOpenDirectMsg struct {
	Raddr string
	Rport uint32
	Laddr string
	Lport uint32
}

func genRSASSHHostKey() (ssh.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}

	privKeyPEMBuffer := new(bytes.Buffer)
	err = pem.Encode(privKeyPEMBuffer, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b,
	})

	private, err := ssh.ParsePrivateKey(privKeyPEMBuffer.Bytes())
	if err != nil {
		log.Fatal("Failed to parse private key: ", err)
	}

	return private, nil
}
