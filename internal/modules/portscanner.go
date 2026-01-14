package modules

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	// Import your engine package
	// You might need to adjust this path based on your go.mod name
	"gorecon/internal/engine"
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
func (ps *PortScanner) ScanTarget(target string, deep bool) {

	// A list of "Top 20" critical ports to keep it fast for the "Scout" phase
	var ports []int
	var concurrency int
	if deep {
		fmt.Printf("[Scanner] Starting DEEP scan on %s (1-65535)...\n", target)
		// Generate full range
		for i := 1; i <= 65535; i++ {
			ports = append(ports, i)
		}
		concurrency = 2000
	} else {
		fmt.Printf("[Scanner] Starting QUICK scan on %s (Top 20)...\n", target)
		// Your existing Top 20 list
		ports = []int{21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
			143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080}
		concurrency = 100
	}

	var wg sync.WaitGroup

	// Semaphore to control concurrency (limit to 10 threads at once)
	// This prevents your OS from running out of file descriptors
	sem := make(chan struct{}, concurrency)

	for _, port := range ports {
		wg.Add(1)

		// Launch a goroutine for every port
		go func(p int) {
			defer wg.Done()

			// Acquire token (block if full)
			sem <- struct{}{}
			// We define a separate function for the scan so we can defer the release properly
			// This ensures 'sem' is released even if Publish blocks
			// defer func() { <-sem }() // Release token IMMEDIATELY when this inner func finishes

			open := ps.isOpen(target, p)

			// RELEASE TOKEN IMMEDIATELY
			<-sem
			if open {
				// CRITICAL: We don't just print, we tell the Brain!

				fmt.Printf("[+] Open: %d on %s \n", p, target)

				// Tell the Brain
				// CRITICAL FIX: Run Publish in a new goroutine.
				// This prevents the "Scanner" from waiting on the "Brain".
				// The scanner can now return, release the semaphore, and let the next port run.
				go func() {
					ps.Brain.Publish(engine.Event{
						Type:    engine.EventPortOpen,
						Target:  target,
						Payload: fmt.Sprintf("%d", p),
					})
				}()
			}
		}(port)
	}

	wg.Wait()
	fmt.Printf("[Scanner] Finished scanning %s.\n", target)
}

// isOpen tries to connect to the port
func (ps *PortScanner) isOpen(target string, port int) bool {
	// address := fmt.Sprintf("%s:%d", target, port)
	address := net.JoinHostPort(target, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, 1*time.Second) // 1s timeout
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
