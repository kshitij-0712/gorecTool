package modules

import (
	"encoding/json"
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

// CrtShResult represents the JSON structure returned by crt.sh
type CrtShResult struct {
	NameValue string `json:"name_value"`
}

// Run is the main entry point for this module
func (s *SubdomainModule) Run(rootDomain string) []string {
	fmt.Printf("[Subdomain] 🔍 querying CRT.sh for %s (Passive)... \n", rootDomain)

	// 1. Fetch raw domains from API
	rawDomains := s.fetchFromCrtSh(rootDomain)
	fmt.Printf("[Subdomain] Found %d raw entries. Cleaning...\n", len(rawDomains))

	// 2. Clean and Deduplicate
	cleanDomains := s.cleanDomains(rawDomains, rootDomain)
	fmt.Printf("[Subdomain] %d unique subdomains found. Validating DNS...\n", len(cleanDomains))

	// 3. Validate (DNS Resolution) and Publish
	return s.validateAndPublish(cleanDomains)
}

func (s *SubdomainModule) fetchFromCrtSh(domain string) []string {
	// 1. Define the URL
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

	var results []CrtShResult

	// 2. Retry Logic (Try 3 times)
	maxRetries := 3
	for i := 0; i < maxRetries; i++ {

		client := &http.Client{Timeout: 20 * time.Second}
		req, _ := http.NewRequest("GET", url, nil)

		// Add a User-Agent (Sometimes helps avoid blocks)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

		resp, err := client.Do(req)

		// Network error? Wait and retry.
		if err != nil {
			fmt.Printf("[Error] Network failure: %v. Retrying (%d/%d)...\n", err, i+1, maxRetries)
			time.Sleep(3 * time.Second)
			continue
		}

		// 3. Handle Status Codes
		if resp.StatusCode == 429 || resp.StatusCode == 502 || resp.StatusCode == 503 {
			// Rate limited or Server overload
			resp.Body.Close() // Close before sleeping
			fmt.Printf("[!] CRT.sh is overloaded (Status %d). Sleeping 5s before retry (%d/%d)...\n", resp.StatusCode, i+1, maxRetries)
			time.Sleep(5 * time.Second) // Wait longer for 429s
			continue
		}

		if resp.StatusCode != 200 {
			// Some other permanent error (404, 403)
			fmt.Printf("[Error] CRT.sh returned unexpected status: %d\n", resp.StatusCode)
			resp.Body.Close()
			break
		}

		// 4. Decode JSON (Only if 200 OK)
		if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
			// Sometimes they send 200 OK but with broken HTML/JSON
			resp.Body.Close()
			// Only retry if it looks like a temporary glitch
			if i < maxRetries-1 {
				fmt.Println("[!] Failed to decode JSON. Retrying...")
				time.Sleep(2 * time.Second)
				continue
			}
		} else {
			// Success!
			resp.Body.Close()
			break
		}
	}

	// 5. Convert results to string slice
	var output []string
	for _, r := range results {
		output = append(output, r.NameValue)
	}
	return output
}

func (s *SubdomainModule) cleanDomains(raw []string, rootDomain string) []string {
	uniqueMap := make(map[string]bool)
	var clean []string
	// fmt.Println(raw, rootDomain)
	for _, domain := range raw {
		// Convert to lowercase
		d := strings.ToLower(domain)

		// Remove wildcards like "*.example.com"
		if strings.Contains(d, "*") {
			continue
		}

		// Ensure it actually belongs to our target (cleanup garbage data)
		if !strings.HasSuffix(d, rootDomain) {
			continue
		}

		// Deduplicate: If we haven't seen it yet, add it
		if _, exists := uniqueMap[d]; !exists {
			uniqueMap[d] = true
			clean = append(clean, d)
		}
	}
	return clean
}

func (s *SubdomainModule) validateAndPublish(domains []string) []string {
	fmt.Println(domains)
	var alive []string
	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 50)

	for _, d := range domains {
		wg.Add(1)
		go func(subdomain string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if ip, err := net.LookupHost(subdomain); err == nil {

				mu.Lock()
				alive = append(alive, subdomain) // Add to list
				mu.Unlock()

				fmt.Printf("   [+] Alive: %s at ip : %s\n", subdomain, ip)

				// We still publish for the log, but we won't use this event to trigger scans anymore
				s.Brain.Publish(engine.Event{
					Type:    engine.EventSubdomainFound,
					Target:  subdomain,
					Payload: "Passive-Source",
				})
			}
		}(d)
	}
	wg.Wait()

	return alive
}
