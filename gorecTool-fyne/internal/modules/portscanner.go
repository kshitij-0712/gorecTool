package modules

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	// Import your engine package
	// You might need to adjust this path based on your go.mod name
	"gorecTool/internal/engine"
)

type PortScanner struct {
	Brain *engine.DecisionEngine
}

func NewPortScanner(brain *engine.DecisionEngine) *PortScanner {
	return &PortScanner{
		Brain: brain,
	}
}

// ScanTarget is the entry point. It scans common ports on a single target.
func (ps *PortScanner) ScanTarget(target string, deep bool, globalSem chan struct{}, onProgress func(int)) {

	// A list of "Top 20" critical ports to keep it fast for the "Scout" phase
	var ports []int
	if deep {
		fmt.Printf("[Scanner] Starting DEEP scan on %s (1-65535)...\n", target)
		// Generate full range
		for i := 1; i <= 65535; i++ {
			ports = append(ports, i)
		}
	} else {
		fmt.Printf("[Scanner] Starting QUICK scan on %s (Top 20)...\n", target)
		// Your existing Top 20 list
		ports = []int{21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
			143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080}
	}

	var wg sync.WaitGroup
	// We use a local atomic counter to batch updates safely from threads
	var localProgress int32 = 0

	for i, port := range ports {
		wg.Add(1)

		// 1. Acquire Token
		globalSem <- struct{}{}

		go func(p int) {
			defer wg.Done()
			defer func() { <-globalSem }() // Release Token

			if ps.isOpen(target, p) {
				go func() {
					ps.Brain.Publish(engine.Event{
						Type:    engine.EventPortOpen,
						Target:  target,
						Payload: fmt.Sprintf("%d", p),
					})
				}()
			}

			// Update Progress safely
			current := atomic.AddInt32(&localProgress, 1)
			if current%50 == 0 {
				onProgress(50)
			}
		}(port)

		// 2. THE FIX: Micro-Sleep every 100 ports
		// This gives Windows time to recycle "TIME_WAIT" sockets
		if i%100 == 0 {
			time.Sleep(10 * time.Millisecond)
		}
	}

	wg.Wait()
	// Flush any remaining progress count (e.g., last 34 ports)
	rem := atomic.LoadInt32(&localProgress) % 50
	if rem > 0 {
		onProgress(int(rem))
	}

	ps.Brain.Log(fmt.Sprintf("[Scanner] Finished %s.", target))
	fmt.Printf("[Scanner] Finished scanning %s.\n", target)
}

// isOpen tries to connect to the port
func (ps *PortScanner) isOpen(target string, port int) bool {
	// address := fmt.Sprintf("%s:%d", target, port)
	address := net.JoinHostPort(target, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp4", address, 1*time.Second) // 1s timeout

	// 3. THE FIX: Use "tcp4" instead of "tcp"
	// This prevents Go from trying IPv6, cutting socket usage in half.
	// Increased timeout to 3 seconds to reduce "dialParallel" strain.

	if err != nil {
		return false
	}
	conn.Close()
	return true
}
