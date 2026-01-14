package modules

import (
	"encoding/json"
	"fmt"
	"gorecon/internal/engine"
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
	// We use the % wildcard to find subdomains
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println(err)
		return []string{}
	}

	// req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36")

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("[Error] Failed to connect to CRT.sh: %v\n", err)
		return []string{}
	}
	defer resp.Body.Close()

	var results []CrtShResult
	fmt.Printf("%v %T", resp, resp)
	// Decode JSON response
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		// Sometimes crt.sh returns 502 or HTML on overload
		fmt.Printf("[Error] Failed to parse CRT.sh response: %v\n", err)
		return []string{}
	}

	var output []string
	for _, r := range results {
		output = append(output, r.NameValue)
	}
	return output
}

func (s *SubdomainModule) cleanDomains(raw []string, rootDomain string) []string {
	uniqueMap := make(map[string]bool)
	var clean []string
	fmt.Println(raw, rootDomain)
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
