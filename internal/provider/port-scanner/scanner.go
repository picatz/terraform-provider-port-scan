package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sync/semaphore"
)

// Dialer implents an interface to allow for multiple network connection types
type Dialer interface {
	DialTimeout(network, address string, timeout time.Duration) (net.Conn, error)
	Close() error
}

// PortScanResult is the type returned by the Run func result chan
type PortScanResult struct {
	IP    string
	Port  int
	Open  bool
	Error error
}

// DefaultTimeoutPerPort is the default timeout per-port for Run
var DefaultTimeoutPerPort = time.Second * 5

type defaultDialer struct {
	net.Dialer
	ctx            context.Context
	cancel         context.CancelFunc
	timeOutPerPort time.Duration
}

func (d *defaultDialer) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(d.ctx, timeout)
	defer cancel()
	return d.Dialer.DialContext(ctx, network, address)
}

func (d *defaultDialer) Close() error {
	d.cancel()
	return nil
}

// DefaultDialer is the default dialer.
var DefaultDialer *defaultDialer

func init() {
	ctx, cancel := context.WithCancel(context.Background())
	DefaultDialer = &defaultDialer{
		ctx:            ctx,
		cancel:         cancel,
		timeOutPerPort: DefaultTimeoutPerPort,
	}
}

var lock *semaphore.Weighted = semaphore.NewWeighted(ulimit())

func ulimit() int64 {
	var rLimit syscall.Rlimit
	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		// default to 256
		return int64(256)
	}
	return int64(rLimit.Cur)
}

func scanPort(d Dialer, ip string, port int, timeout time.Duration) (result PortScanResult) {
	if timeout == 0 {
		timeout = DefaultTimeoutPerPort
	}

	result.IP = ip
	result.Port = port

	target := fmt.Sprintf("%s:%d", ip, port)

	conn, err := d.DialTimeout("tcp", target, timeout)
	if err != nil {
		if strings.Contains(err.Error(), "too many open files") {
			time.Sleep(timeout)
			scanPort(d, ip, port, timeout)
		} else {
			result.Error = err
		}
		return
	}
	conn.Close()
	result.Open = true
	return
}

// Run will perform a port scan for the given IP, starting at the firstPort to the lastPort
func Run(d Dialer, ip string, firstPort, lastPort int, timeoutPerPort time.Duration) <-chan PortScanResult {
	results := make(chan PortScanResult)

	go func() {
		defer close(results)

		wg := sync.WaitGroup{}

		for port := firstPort; port <= lastPort; port++ {
			lock.Acquire(context.Background(), 1)
			wg.Add(1)
			go func(port int) {
				defer lock.Release(1)
				defer wg.Done()
				results <- scanPort(d, ip, port, timeoutPerPort)
			}(port)
		}

		wg.Wait()
	}()

	return results
}
