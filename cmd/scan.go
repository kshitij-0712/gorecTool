package cmd

import (
	"bufio"
	"fmt"
	"os"

	// Import your internal packages
	"gorecon/internal/engine"
	"gorecon/internal/modules"
	"strconv"
	"strings"
	"sync"

	"github.com/spf13/cobra"
)

// Variables to store flag values
var targetDomain string
var isDeepScan bool

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Start a reconnaissance scan on a target",
	Long:  `Initiates the autonomous scanning engine on a specific domain.`,

	// Example: ./gorecon scan -d example.com
	Run: func(cmd *cobra.Command, args []string) {
		// 1. Setup Engine (Still needed for logging/logic)

		if targetDomain == "" {
			fmt.Println("Error: You must provide a domain using the -d flag.")
			return
		}
		if isDeepScan {
			fmt.Println("[*] Mode: DEEP SCAN (This will take longer requires user input)")
		} else {
			fmt.Println("[*] Mode: QUICK SCAN (Top 20 ports only)")
		}
		var engineWg sync.WaitGroup

		brain := engine.NewEngine(&engineWg)

		engineWg.Add(1)
		go brain.Start()
		var analysisWg sync.WaitGroup
		// 2. Setup Modules
		subEnum := modules.NewSubdomainModule(brain)
		portScanner := modules.NewPortScanner(brain)
		httpAnalyzer := modules.NewHttpAnalyzer(brain)
		portScanner.ScanTarget(targetDomain, isDeepScan)
		var scanWg sync.WaitGroup
		// 3. Add Rules (Ideally, move these to a separate 'rules' package later)
		// brain.AddRule(engine.Rule{
		// 	Name:      "Auto-Scan-Subdomain",
		// 	Condition: func(e engine.Event) bool { return e.Type == engine.EventSubdomainFound },
		// 	Action: func(e engine.Event) {
		// 		scanWg.Add(1)
		// 		go func() {
		// 			defer scanWg.Done()
		// 			portScanner.ScanTarget(e.Target, isDeepScan)
		// 		}()
		// 	},
		// })

		brain.AddRule(engine.Rule{
			Name: "Web-Discovery",
			Condition: func(e engine.Event) bool {
				return e.Type == engine.EventPortOpen &&
					(e.Payload == "80" || e.Payload == "443" || e.Payload == "8080" || e.Payload == "8443")
			},
			Action: func(e engine.Event) {
				fmt.Printf("    >>> [REPORT] Web Server Found on %s\n", e.Target)
				// Convert payload (port string) to int
				port, _ := strconv.Atoi(e.Payload)

				// CHANGE 2: Track the background task!
				// We increment BEFORE the goroutine starts to ensure we don't exit early
				analysisWg.Add(1)

				go func() {
					// Ensure we decrement when the analysis is done
					defer analysisWg.Done()
					httpAnalyzer.Analyze(e.Target, port)
				}()
			},
		})

		// 3. PHASE 1: Subdomain Enumeration
		fmt.Println("\n=== PHASE 1: Enumerating Subdomains ===")
		aliveSubdomains := subEnum.Run(targetDomain)

		if len(aliveSubdomains) == 0 {
			fmt.Println("[-] No subdomains found. Exiting.")
			return
		}

		// 4. INTERACTIVE PHASE: Ask the User
		fmt.Println("\n=== PHASE 2: Target Selection ===")
		fmt.Println("Found the following live subdomains:")
		for i, sub := range aliveSubdomains {
			fmt.Printf("[%d] %s\n", i+1, sub)
		}
		var choice string
		if isDeepScan {
			fmt.Println("\nSelect options:")
			fmt.Println("  'a'      -> Deep Scan ALL (Caution!)")
			fmt.Println("  '1,3,5'  -> Deep Scan specific numbers")
			fmt.Println("  'enter'  -> Quick Scan ALL (Default)")

			fmt.Print("\nYour Choice: ")
			reader := bufio.NewReader(os.Stdin)
			choice, _ = reader.ReadString('\n')
			choice = strings.TrimSpace(choice)
		}

		choice = ""
		// 5. PHASE 3: Execution
		var targetsToDeepScan []string
		var targetsToQuickScan []string

		// Logic to parse user input
		if choice == "a" {
			targetsToDeepScan = aliveSubdomains
		} else if choice == "" {
			targetsToQuickScan = aliveSubdomains
		} else {
			// Parse "1,3,5"
			indices := strings.Split(choice, ",")
			selectedMap := make(map[string]bool)

			for _, idx := range indices {
				i, err := strconv.Atoi(strings.TrimSpace(idx))
				if err == nil && i > 0 && i <= len(aliveSubdomains) {
					target := aliveSubdomains[i-1]
					targetsToDeepScan = append(targetsToDeepScan, target)
					selectedMap[target] = true
				}
			}

			// Add the rest to Quick Scan (Optional, or just ignore them)
			for _, sub := range aliveSubdomains {
				if !selectedMap[sub] {
					targetsToQuickScan = append(targetsToQuickScan, sub)
				}
			}
		}

		// 6. Launch Scans

		// Launch Deep Scans
		for _, t := range targetsToDeepScan {
			scanWg.Add(1)
			go func(target string) {
				defer scanWg.Done()
				// Run Deep Scan (True)
				portScanner.ScanTarget(target, true)
			}(t)
		}

		// Launch Quick Scans (Concurrent with Deep Scans? Maybe limit this)
		for _, t := range targetsToQuickScan {
			scanWg.Add(1)
			go func(target string) {
				defer scanWg.Done()
				// Run Quick Scan (False)
				portScanner.ScanTarget(target, false)
			}(t)
		}

		fmt.Println("\n=== PHASE 3: Scanning Started (Please Wait) ===")
		scanWg.Wait() // Wait for all scans to finish
		analysisWg.Wait()
		// Shutdown
		close(brain.Bus)

		engineWg.Wait()

		fmt.Println("[*] All operations complete.")

		// fmt.Printf("[*] Initializing Engine for Target: %s\n", targetDomain)
		// // --- THIS IS WHERE WE CONNECT YOUR LOGIC ---\

		// var engineWg sync.WaitGroup
		// engineWg.Add(1)

		// // 2. The WaitGroup for the SCANNERS (The "Arms & Legs")
		// var scannerWg sync.WaitGroup

		// // 1. Start the Brain
		// brain := engine.NewEngine(&engineWg)

		// // 2. Initialize Modules
		// subEnum := modules.NewSubdomainModule(brain)
		// portScanner := modules.NewPortScanner(brain)

		// fmt.Println(reflect.TypeOf(brain), reflect.TypeOf(portScanner))

		// // 3. Add Rules (Ideally, move these to a separate 'rules' package later)
		// brain.AddRule(engine.Rule{
		// 	Name:      "Auto-Scan-Subdomain",
		// 	Condition: func(e engine.Event) bool { return e.Type == engine.EventSubdomainFound },
		// 	Action: func(e engine.Event) {
		// 		scannerWg.Add(1)
		// 		go func() {
		// 			defer scannerWg.Done()
		// 			portScanner.ScanTarget(e.Target, isDeepScan)
		// 		}()
		// 	},
		// })

		// brain.AddRule(engine.Rule{
		// 	Name: "Web-Discovery",
		// 	Condition: func(e engine.Event) bool {
		// 		return e.Type == engine.EventPortOpen && (e.Payload == "80" || e.Payload == "443")
		// 	},
		// 	Action: func(e engine.Event) {
		// 		fmt.Printf("    >>> [REPORT] Web Server Found on %s\n", e.Target)
		// 	},
		// })

		// // 4. Ignite
		// // Start the Brain
		// go brain.Start()

		// // --- Start the Initial Job ---

		// fmt.Printf("[*] Starting Scan on %s...\n", targetDomain)

		// // Add 1 for the Subdomain Module (The Trigger)
		// scannerWg.Add(1)
		// go func() {
		// 	defer scannerWg.Done()
		// 	subEnum.Run(targetDomain)
		// }()

		// // --- The Graceful Shutdown Logic ---

		// // Block here until all scanners (Subdomain + PortScans) are done.
		// // As new events come in, scannerWg counter goes up and down.
		// scannerWg.Wait()
		// fmt.Println("[*] All scans finished. Shutting down Engine...")

		// // Now that no one is publishing events, close the bus.
		// // This causes the "range brain.Bus" loop in engine.go to break.
		// close(brain.Bus)

		// // Wait for the Engine to process remaining events and exit
		// engineWg.Wait()

		// fmt.Println("[*] Scan Complete. Goodbye.")
	},
}

func init() {
	// Register 'scan' as a sub-command of 'root'
	print("init")
	rootCmd.AddCommand(scanCmd)

	// Define flags
	// func VarP(p *Type, name, shorthand, usage, default)
	scanCmd.Flags().StringVarP(&targetDomain, "domain", "d", "", "The target domain to scan (e.g., example.com)")
	scanCmd.Flags().BoolVar(&isDeepScan, "deep", false, "Enable deep scanning (all ports, brute-force)")
	// Mark the flag as required if you want to force it
	scanCmd.MarkFlagRequired("domain")
}
