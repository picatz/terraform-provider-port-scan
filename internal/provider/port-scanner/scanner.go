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

// PortScanResult is the type returned by the Run func result chan
type PortScanResult struct {
	IP    string
	Port  int
	Open  bool
	Error error
}

// DefaultTimeoutPerPort is the default timeout per-port for Run
var DefaultTimeoutPerPort = time.Second * 5

var d net.Dialer

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

func scanPort(ctx context.Context, ip string, port int, timeout time.Duration) (result PortScanResult) {
	if timeout == 0 {
		timeout = DefaultTimeoutPerPort
	}

	result.IP = ip
	result.Port = port

	target := fmt.Sprintf("%s:%d", ip, port)

	ctxForPort, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := d.DialContext(ctxForPort, "tcp", target)
	if err != nil {
		if strings.Contains(err.Error(), "too many open files") {
			time.Sleep(timeout)
			scanPort(ctxForPort, ip, port, timeout)
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
func Run(ctx context.Context, ip string, firstPort, lastPort int, timeoutPerPort time.Duration) <-chan PortScanResult {
	results := make(chan PortScanResult)

	go func() {
		defer close(results)

		wg := sync.WaitGroup{}

		for port := firstPort; port <= lastPort; port++ {
			lock.Acquire(ctx, 1)
			wg.Add(1)
			go func(port int) {
				defer lock.Release(1)
				defer wg.Done()
				results <- scanPort(ctx, ip, port, timeoutPerPort)
			}(port)
		}

		wg.Wait()
	}()

	return results
}
