package modules

import (
	"fmt"
	"gorecon/internal/engine"
	"net/http"
	"strings"
	"time"
)

type FileHunter struct {
	Brain *engine.DecisionEngine
}

func NewFileHunter(brain *engine.DecisionEngine) *FileHunter {
	return &FileHunter{Brain: brain}
}

// Hunt picks the right wordlist based on the detected technology
func (f *FileHunter) Hunt(target string, port int, techStack string) {
	baseURL := fmt.Sprintf("http://%s:%d", target, port)
	if port == 443 || port == 8443 {
		baseURL = fmt.Sprintf("https://%s:%d", target, port)
	}

	fmt.Printf("    >>> [HUNTER] Starting context-scan on %s (Tech: %s)\n", baseURL, techStack)

	// 1. Define Context-Aware Wordlists
	// Always check these generic sensitive files
	files := []string{"robots.txt", ".env", ".git/HEAD", "sitemap.xml"}

	// If we detected specific tech, add specific checks
	if strings.Contains(techStack, "Apache") {
		files = append(files, ".htaccess", "server-status")
	}
	if strings.Contains(techStack, "WordPress") {
		files = append(files, "wp-config.php.bak", "wp-admin/admin-ajax.php")
	}
	if strings.Contains(techStack, "Nginx") {
		files = append(files, "nginx.conf")
	}

	// 2. Execute the Checks
	client := &http.Client{Timeout: 3 * time.Second}

	for _, file := range files {
		url := fmt.Sprintf("%s/%s", baseURL, file)
		resp, err := client.Get(url)

		if err != nil {
			continue
		}

		// 3. Analyze Response
		// We only care if it exists (200 OK) and isn't a fake custom 404 page
		if resp.StatusCode == 200 {
			fmt.Printf("    >>> [!] ALERT: Found Sensitive File: %s\n", url)

			// Feed back to Brain (Could trigger a downloader module)
			f.Brain.Publish(engine.Event{
				Type:    engine.EventVulnFound,
				Target:  target,
				Payload: fmt.Sprintf("Sensitive File: %s", file),
			})
		}
		resp.Body.Close()
	}
}
