package scanner

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
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

	scanPort(context.Background(), "127.0.0.1", port, DefaultTimeoutPerPort)
}

func Test_scanPort_closed(t *testing.T) {
	port := 5858

	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	listener.Close()

	scanPort(context.Background(), "127.0.0.1", port, DefaultTimeoutPerPort)
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

	for result := range Run(context.Background(), "127.0.0.1", 5000, 6000, DefaultTimeoutPerPort) {
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

	for result := range Run(context.Background(), "127.0.0.1", 5959, 5959, DefaultTimeoutPerPort) {
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
