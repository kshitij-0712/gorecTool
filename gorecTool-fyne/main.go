package main

import (
	"fmt"
	"gorecTool/internal/engine"
	"gorecTool/internal/modules"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

func main() {
	myApp := app.New()
	myWindow := myApp.NewWindow("GoRecon - Autonomous Scanner")
	myWindow.Resize(fyne.NewSize(800, 600))

	// --- DATA BINDING (State) ---
	logs := binding.NewStringList()
	results := binding.NewStringList() // Simplified for demo (stores "Type | Target")

	// --- UI COMPONENTS ---

	// 1. Logs Area (Bottom)
	logList := widget.NewListWithData(logs,
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(i binding.DataItem, o fyne.CanvasObject) {
			o.(*widget.Label).Bind(i.(binding.String))
		},
	)
	logScroll := container.NewVScroll(logList)
	logScroll.SetMinSize(fyne.NewSize(0, 150))

	// 2. Results Area (Main Table-like view)
	resultList := widget.NewListWithData(results,
		func() fyne.CanvasObject { return widget.NewLabel("template") },
		func(i binding.DataItem, o fyne.CanvasObject) {
			o.(*widget.Label).Bind(i.(binding.String))
		},
	)

	// 3. Phase 1: Input
	inputEntry := widget.NewEntry()
	inputEntry.SetPlaceHolder("example.com")

	// Container for Phase 2 Checkboxes
	checkContainer := container.NewVBox()
	var selectedTargets []string

	// Layouts
	var content *fyne.Container

	// --- LOGIC FUNCTIONS ---

	// Helper to add log safely from background threads
	addLog := func(msg string) {
		logs.Append(msg)
		logList.ScrollToBottom()
	}

	// The Scan Logic
	startDeepScan := func(deep bool) {
		addLog(fmt.Sprintf("Starting Scan (Deep: %v)...", deep))

		// Switch UI to Result View
		content.Objects = []fyne.CanvasObject{resultList, logScroll}
		content.Refresh()

		go func() {
			var wg sync.WaitGroup
			wg.Add(1)

			// CALLBACK: Connects Engine to Fyne Data Binding
			updateUI := func(evtType string, data interface{}) {
				evt := data.(engine.Event)
				// Format: [PORT_OPEN] 192.168.1.1 (80)
				results.Prepend(fmt.Sprintf("[%s] %s -> %s", evtType, evt.Target, evt.Payload))
			}

			brain := engine.NewEngine(&wg, updateUI)

			// Init Modules
			portScanner := modules.NewPortScanner(brain)
			httpAnalyzer := modules.NewHttpAnalyzer(brain)

			// Add Logic Rule
			brain.AddRule(engine.Rule{
				Name: "Web-Discovery",
				Condition: func(e engine.Event) bool {
					return e.Type == engine.EventPortOpen && (e.Payload == "80" || e.Payload == "443")
				},
				Action: func(e engine.Event) {
					go httpAnalyzer.Analyze(e.Target, 80) // Simplified port parsing
				},
			})

			go brain.Start()

			// Launch Scans
			var scanWg sync.WaitGroup
			for _, t := range selectedTargets {
				scanWg.Add(1)
				go func(target string) {
					defer scanWg.Done()
					portScanner.ScanTarget(target, deep)
				}(t)
			}
			scanWg.Wait()
			close(brain.Bus)
			wg.Wait()
			addLog("Scan Complete.")
		}()
	}

	// Phase 1 -> Phase 2 Transition
	findSubdomains := func() {
		domain := inputEntry.Text
		if domain == "" {
			return
		}

		addLog("Enumerating subdomains for " + domain + "...")

		// Clear previous checkboxes
		checkContainer.Objects = nil
		selectedTargets = nil

		go func() {
			// Dummy engine just for the module
			brain := engine.NewEngine(&sync.WaitGroup{}, nil)
			subMod := modules.NewSubdomainModule(brain)
			subs := subMod.Run(domain)

			// Update UI on Main Thread
			// Fyne requires UI updates to happen on the main thread via checking 'subMod.Run' output
			// But since we are in a goroutine, we queue the update:

			// Populate Checkboxes
			for _, sub := range subs {
				// Capture variable
				s := sub
				check := widget.NewCheck(s, func(checked bool) {
					if checked {
						selectedTargets = append(selectedTargets, s)
					} else {
						// Remove from slice (simple filter)
						// In real code, handle removal logic better
					}
				})
				checkContainer.Add(check)
			}

			// Show Selection UI
			content.Objects = []fyne.CanvasObject{
				widget.NewLabel("Select Targets:"),
				container.NewVScroll(checkContainer),
				container.NewHBox(
					widget.NewButton("Quick Scan", func() { startDeepScan(false) }),
					widget.NewButton("Deep Scan", func() { startDeepScan(true) }),
				),
				logScroll,
			}
			content.Refresh()
			addLog(fmt.Sprintf("Found %d subdomains.", len(subs)))
		}()
	}

	// --- INITIAL LAYOUT ---

	startBtn := widget.NewButton("Find Subdomains", findSubdomains)

	// Master Container
	content = container.NewVBox(
		widget.NewLabel("Target Domain:"),
		inputEntry,
		startBtn,
		layout.NewSpacer(),
		logScroll,
	)

	myWindow.SetContent(content)
	myWindow.ShowAndRun()
}
