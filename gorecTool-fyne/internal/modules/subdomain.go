package modules

import (
	"bufio"
	"fmt"
	"gorecTool/internal/engine"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type SubdomainModule struct {
	Brain *engine.DecisionEngine
}

func NewSubdomainModule(brain *engine.DecisionEngine) *SubdomainModule {
	return &SubdomainModule{Brain: brain}
}

func (s *SubdomainModule) Run(rootDomain string) []string {
	s.Brain.Log(fmt.Sprintf("Phase 1: Starting Passive Recon on %s...", rootDomain))

	// 1. Try Reliable Passive Source (HackerTarget)
	domains := s.fetchFromHackerTarget(rootDomain)

	// 2. If Passive failed or found nothing, switch to Active Brute Force
	if len(domains) == 0 {
		s.Brain.Log("Passive sources failed or found nothing. Switching to ACTIVE Brute Force...")
		domains = s.bruteForceSubdomains(rootDomain)
	} else {
		s.Brain.Log(fmt.Sprintf("Passive Recon success. Found %d candidates.", len(domains)))
	}

	// 3. Validation (DNS Check)
	// Even if we brute forced them, we double check they are actually alive
	return s.validateAndVerify(domains)
}

// SOURCE 1: HackerTarget (More reliable than CRT.sh)
func (s *SubdomainModule) fetchFromHackerTarget(domain string) []string {
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		s.Brain.Log(fmt.Sprintf("[!] Passive API Error: %v", err))
		return []string{}
	}
	defer resp.Body.Close()

	// HackerTarget returns CSV lines: "hostname,ip"
	// Example:
	// www.google.com,142.250.1.1
	// mail.google.com,142.250.1.2

	var results []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ",")
		if len(parts) >= 1 {
			// Clean up the domain part
			d := strings.TrimSpace(parts[0])
			if d != "" && strings.Contains(d, domain) {
				results = append(results, d)
			}
		}
	}

	if len(results) == 0 {
		s.Brain.Log("[!] HackerTarget returned empty list.")
	}
	return results
}

// SOURCE 2: Active Brute Force (The "Manual" Way)
func (s *SubdomainModule) bruteForceSubdomains(rootDomain string) []string {
	// A small, high-value wordlist for fallback
	// In a real tool, you might load this from a file
	commonSubs := []string{
		"www", "mail", "remote", "blog", "webmail", "server",
		"ns1", "ns2", "smtp", "secure", "vpn", "m", "shop",
		"ftp", "mail2", "test", "portal", "ns", "ww1", "host",
		"support", "dev", "web", "bbs", "ww42", "mx", "email",
		"cloud", "1", "mail1", "2", "forum", "owa", "www2",
		"gw", "admin", "store", "mx1", "cdn", "api", "exchange",
		"app", "gov", "2020", "gov", "news",
	}

	var found []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Limit concurrency to avoid getting banned by ISP DNS
	sem := make(chan struct{}, 20)

	for _, sub := range commonSubs {
		target := fmt.Sprintf("%s.%s", sub, rootDomain)

		wg.Add(1)
		go func(t string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Attempt to resolve
			_, err := net.LookupHost(t)
			if err == nil {
				// It exists!
				mu.Lock()
				found = append(found, t)
				mu.Unlock()
				s.Brain.Log(fmt.Sprintf("[Active] Discovered: %s", t))
			}
		}(target)
	}
	wg.Wait()
	return found
}

func (s *SubdomainModule) validateAndVerify(domains []string) []string {
	// Deduplicate first
	uniqueMap := make(map[string]bool)
	var clean []string
	for _, d := range domains {
		if _, exists := uniqueMap[d]; !exists {
			uniqueMap[d] = true
			clean = append(clean, d)
		}
	}

	s.Brain.Log(fmt.Sprintf("Validating %d unique subdomains...", len(clean)))

	// Validate (DNS Resolution)
	var alive []string
	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 50)

	for _, d := range clean {
		wg.Add(1)
		go func(subdomain string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if _, err := net.LookupHost(subdomain); err == nil {
				mu.Lock()
				alive = append(alive, subdomain)
				mu.Unlock()

				// Optional: Tell Brain immediately so UI updates
				// s.Brain.Publish(engine.Event{Type: engine.EventSubdomainFound, Target: subdomain, Payload: "Alive"})
			}
		}(d)
	}

	wg.Wait()
	return alive
}
