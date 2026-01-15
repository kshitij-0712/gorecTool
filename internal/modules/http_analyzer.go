package modules

import (
	"crypto/tls"
	"fmt"
	"gorecon/internal/engine"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type HttpAnalyzer struct {
	Brain *engine.DecisionEngine
}

func NewHttpAnalyzer(brain *engine.DecisionEngine) *HttpAnalyzer {
	return &HttpAnalyzer{Brain: brain}
}

// Analyze is triggered when a Web Port (80, 443, 8080) is found
func (h *HttpAnalyzer) Analyze(target string, port int) {
	// Construct the URL.
	// Simple logic: If 443, assume HTTPS. Else try HTTP first.
	protocol := "http"
	if port == 443 || port == 8443 {
		protocol = "https"
	}
	url := fmt.Sprintf("%s://%s:%d", protocol, target, port)

	fmt.Printf("    >>> [HTTP] Analyzing %s...\n", url)

	// 1. Setup Client (Ignore bad SSL certs)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   5 * time.Second,
	}

	// 2. Fetch the Page
	resp, err := client.Get(url)
	// fmt.Printf("here%v %v", resp, err)
	if err != nil {
		// If HTTP fails on port 80, maybe it redirects to HTTPS?
		// For now, we just log the error.
		return
	}
	defer resp.Body.Close()

	// 3. Read Body (First 4KB is usually enough for title/headers)

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	bodyStr := string(bodyBytes)
	// fmt.Println(bodyBytes, bodyStr)
	// 4. Extract Data
	title := extractTitle(bodyStr)
	server := resp.Header.Get("Server")
	tech := detectTech(resp.Header, bodyStr)
	fmt.Println(title, server, tech)
	// 5. Report Findings
	fmt.Printf("    >>> [HTTP] [%d] Title: %q | Server: %s | Tech: %s\n",
		resp.StatusCode, title, server, tech)

	// 6. Feed the Brain (For future exploits)
	h.Brain.Publish(engine.Event{
		Type:    engine.EventHttpService,
		Target:  target,
		Payload: fmt.Sprintf("%s|%s|%d", server, tech, port),
	})
}

// Helper: Extract <title>...</title>
func extractTitle(body string) string {
	re := regexp.MustCompile(`(?i)<title>(.*?)</title>`)
	matches := re.FindStringSubmatch(body)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return "No Title"
}

// Helper: Simple Technology Fingerprinting
func detectTech(headers http.Header, body string) string {
	var detected []string

	// Check Headers
	if strings.Contains(headers.Get("X-Powered-By"), "PHP") {
		detected = append(detected, "PHP")
	}
	if strings.Contains(headers.Get("Server"), "Apache") {
		detected = append(detected, "Apache")
	}
	if strings.Contains(headers.Get("Server"), "nginx") {
		detected = append(detected, "Nginx")
	}

	// Check Body (HTML Source)
	if strings.Contains(body, "wp-content") {
		detected = append(detected, "WordPress")
	}
	if strings.Contains(body, "react") || strings.Contains(body, "_next") {
		detected = append(detected, "React/Next.js")
	}

	if len(detected) == 0 {
		return "Unknown"
	}
	return strings.Join(detected, ", ")
}
