package main

import (
	"fmt"
	"gorecTool/internal/engine"
	"gorecTool/internal/modules"
	"image/color"
	"strings"
	"sync"
	"sync/atomic" // <--- NEEDED FOR PROGRESS BAR
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

func main() {
	myApp := app.New()
	myWindow := myApp.NewWindow("GoRecon - Autonomous Security Scanner")
	myWindow.Resize(fyne.NewSize(750, 500))

	// --- STATE ---
	logs := binding.NewStringList()
	results := binding.NewStringList()
	progress := binding.NewFloat()
	statusLabel := binding.NewString()
	statusLabel.Set("Ready")

	// --- UI COMPONENTS ---

	// 1. Log Console
	logList := widget.NewListWithData(logs,
		func() fyne.CanvasObject { return widget.NewLabel("template") },
		func(i binding.DataItem, o fyne.CanvasObject) {
			o.(*widget.Label).Bind(i.(binding.String))
			o.(*widget.Label).TextStyle = fyne.TextStyle{Monospace: true}
		},
	)
	logScroll := container.NewVScroll(logList)
	logScroll.SetMinSize(fyne.NewSize(0, 150))

	// 2. Results List (FIXED LAYOUT)
	resultList := widget.NewListWithData(results,
		func() fyne.CanvasObject {
			// TEMPLATE: Icon on Left, Text takes all remaining space
			icon := widget.NewIcon(theme.InfoIcon())
			label := widget.NewLabel("Content goes here...")
			label.Wrapping = fyne.TextTruncate // Ensure text doesn't push layout weirdly

			// Background for color coding
			bg := canvas.NewRectangle(color.Transparent)

			// Use Border layout: Icon is "Leading" (Left), Label is "Center" (Fills rest)
			content := container.NewBorder(nil, nil, icon, nil, label)

			return container.NewStack(bg, content)
		},
		func(i binding.DataItem, o fyne.CanvasObject) {
			raw, _ := i.(binding.String).Get()

			// Unwrap
			stack := o.(*fyne.Container)
			bg := stack.Objects[0].(*canvas.Rectangle)
			borderContainer := stack.Objects[1].(*fyne.Container)

			// Get widgets from Border layout
			// Objects[0] is usually the center (label), Objects[1] is leading (icon) in Fyne internal order
			// Safer to cast by checking types or knowing insertion order.
			// Fyne Border order: Top, Bottom, Left, Right, Center.
			// We only set Left (icon) and Center (label).
			// So Objects slice usually contains them. Let's find them by type to be safe.
			var icon *widget.Icon
			var label *widget.Label

			for _, obj := range borderContainer.Objects {
				if ic, ok := obj.(*widget.Icon); ok {
					icon = ic
				}
				if lbl, ok := obj.(*widget.Label); ok {
					label = lbl
				}
			}

			// Reset Style
			bg.FillColor = color.Transparent

			// Parse: "TYPE|TARGET|PAYLOAD"
			parts := strings.SplitN(raw, "|", 3)
			if len(parts) < 3 {
				label.SetText(raw) // Fallback
				return
			}

			msgType := parts[0]
			target := parts[1]
			payload := parts[2]

			// Format Readable Text
			switch msgType {
			case "VULN":
				icon.SetResource(theme.WarningIcon())
				label.SetText(fmt.Sprintf("CRITICAL: %s found on %s", payload, target))
				bg.FillColor = color.RGBA{R: 60, G: 0, B: 0, A: 255} // Dark Red
			case "PORT":
				icon.SetResource(theme.ConfirmIcon())
				label.SetText(fmt.Sprintf("Port Open: %s on %s", payload, target))
			case "HTTP":
				icon.SetResource(theme.SearchIcon())
				label.SetText(fmt.Sprintf("Web Tech: %s (%s)", payload, target))
			default:
				icon.SetResource(theme.InfoIcon())
				label.SetText(fmt.Sprintf("%s: %s", target, payload))
			}
		},
	)

	// 3. Progress Bar
	progressBar := widget.NewProgressBarWithData(progress)
	statusText := widget.NewLabelWithData(statusLabel)
	statusText.Alignment = fyne.TextAlignCenter

	// --- LOGIC ---
	addLog := func(msg string) {
		logs.Append(time.Now().Format("15:04:05") + " " + msg)
	}

	startScanning := func(targets []string, deep bool) {
		progress.Set(0.0)
		statusLabel.Set("Initializing...")

		// Switch View
		content := container.NewBorder(
			container.NewVBox(
				widget.NewLabelWithStyle("Live Results", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
				progressBar,
				statusText,
			),
			nil, nil, nil,
			resultList,
		)
		myWindow.SetContent(container.NewVSplit(content, logArea(logScroll)))

		go func() {
			var wg sync.WaitGroup
			wg.Add(1)
			// 1. Calculate TOTAL operations (Granular)
			// 1. Create the NEW BusyWg
			var busyWg sync.WaitGroup

			// 2. Keep the AnalysisWg
			var analysisWg sync.WaitGroup
			portsPerDomain := 20
			if deep {
				portsPerDomain = 65535
			}
			// We use int64 to avoid overflow if you scan massive lists
			totalOps := int64(len(targets) * portsPerDomain)
			var completedOps int64 = 0
			// CALLBACK
			updateUI := func(evtType string, data interface{}) {
				if evtType == "log" {
					addLog(data.(string))
					return
				}

				evt := data.(engine.Event)
				prefix := "INFO"
				switch evt.Type {
				case engine.EventVulnFound:
					prefix = "VULN"
				case engine.EventPortOpen:
					prefix = "PORT"
				case engine.EventHttpService:
					prefix = "HTTP"
				}
				// Format for the UI parser
				results.Prepend(fmt.Sprintf("%s|%s|%s", prefix, evt.Target, evt.Payload))
			}

			brain := engine.NewEngine(&wg, &busyWg, updateUI)

			// INIT MODULES
			portScanner := modules.NewPortScanner(brain)
			httpAnalyzer := modules.NewHttpAnalyzer(brain)
			fileHunter := modules.NewFileHunter(brain)

			// RULES
			brain.AddRule(engine.Rule{
				Name: "Web-Discovery",
				Condition: func(e engine.Event) bool {
					return e.Type == engine.EventPortOpen && (e.Payload == "80" || e.Payload == "443" || e.Payload == "8080")
				},
				Action: func(e engine.Event) {
					analysisWg.Add(1)
					go func() {
						defer analysisWg.Done() // Signal done when finished
						brain.Log(fmt.Sprintf("Analyzing Web Service on %s...", e.Target))
						httpAnalyzer.Analyze(e.Target, 80)
					}()
				},
			})
			brain.AddRule(engine.Rule{
				Name:      "Context-Fuzzer",
				Condition: func(e engine.Event) bool { return e.Type == engine.EventHttpService },
				Action: func(e engine.Event) {
					analysisWg.Add(1)
					go func() {
						defer analysisWg.Done() // Signal done when finished
						brain.Log(fmt.Sprintf("Hunting files on %s...", e.Target))
						fileHunter.Hunt(e.Target, 80, "Apache")
					}()
				},
			})

			go brain.Start()
			// GLOBAL THROTTLING (HIGH PERFORMANCE)
			// 1500 is roughly the limit for a standard Windows Desktop
			// before you hit ephemeral port exhaustion (TIME_WAIT issues).
			// If this crashes, lower to 1000. If it works, try 2000.
			globalSem := make(chan struct{}, 1000)
			var scanWg sync.WaitGroup

			for i, t := range targets {
				statusLabel.Set(fmt.Sprintf("Queuing %s (%d/%d)...", t, i+1, len(targets)))

				scanWg.Add(1)
				go func(target string) {
					defer scanWg.Done()

					// Define the Callback
					progressCallback := func(scannedCount int) {
						// Add the batch (e.g., +50) to the total atomically
						current := atomic.AddInt64(&completedOps, int64(scannedCount))

						// Update UI Bar
						progress.Set(float64(current) / float64(totalOps))
					}

					// Run Scan with Granular Progress
					portScanner.ScanTarget(target, deep, globalSem, progressCallback)

					// UPDATE PROGRESS SAFELY
					current := atomic.AddInt64(&completedOps, 1)
					progress.Set(float64(current) / float64(totalOps))
				}(t)
			}

			scanWg.Wait()
			statusLabel.Set("Port Scan Complete. Running Deep Analysis...")
			progressBar.SetValue(1.0) // Force bar to full

			// LAYER 1: Wait for PortOpen events to be processed
			busyWg.Wait()

			// LAYER 2: Wait for HTTP Analyzers to finish (They might Publish events!)
			analysisWg.Wait()

			// LAYER 3: Wait for those new HTTP events to be processed
			busyWg.Wait()

			// LAYER 4: Wait for FileHunters (triggered by HTTP events)
			analysisWg.Wait()
			close(brain.Bus)
			wg.Wait()

			statusLabel.Set("Complete")
			progress.Set(1.0)
			addLog("--- FINISHED ---")
		}()
	}

	// --- PHASE 2: SELECTION ---
	showSelection := func(subs []string) {
		addLog(fmt.Sprintf("Enumeration complete. Found %d subdomains.", len(subs)))

		checkContainer := container.NewVBox()
		var selected []string

		for _, s := range subs {
			target := s
			check := widget.NewCheck(target, func(b bool) {
				if b {
					selected = append(selected, target)
				}
			})
			checkContainer.Add(check)
		}

		quickBtn := widget.NewButton("Quick Scan", func() { startScanning(selected, false) })
		deepBtn := widget.NewButton("Deep Scan", func() { startScanning(selected, true) })
		deepBtn.Importance = widget.HighImportance

		content := container.NewBorder(
			widget.NewLabelWithStyle("Select Targets", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
			container.NewHBox(quickBtn, deepBtn),
			nil, nil,
			container.NewVScroll(checkContainer),
		)
		myWindow.SetContent(container.NewVSplit(content, logArea(logScroll)))
	}

	// --- PHASE 1: INPUT ---
	input := widget.NewEntry()
	input.SetPlaceHolder("example.com")

	startBtn := widget.NewButtonWithIcon("Start Enumeration", theme.SearchIcon(), func() {
		if input.Text == "" {
			return
		}
		input.Disable()

		cb := func(t string, d interface{}) {
			if t == "log" {
				addLog(d.(string))
			}
		}

		go func() {
			dummyWg := &sync.WaitGroup{}
			dummyWg.Add(1)
			dummyBusyWg := &sync.WaitGroup{}
			brain := engine.NewEngine(dummyWg, dummyBusyWg, cb)
			subMod := modules.NewSubdomainModule(brain)

			subs := subMod.Run(input.Text)
			showSelection(subs)
		}()
	})

	inputContent := container.NewVBox(
		layout.NewSpacer(),
		widget.NewLabelWithStyle("Target Domain", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		input,
		startBtn,
		layout.NewSpacer(),
	)

	myWindow.SetContent(container.NewVSplit(inputContent, logArea(logScroll)))
	myWindow.ShowAndRun()
}

func logArea(content fyne.CanvasObject) fyne.CanvasObject {
	return container.NewBorder(
		widget.NewLabelWithStyle("System Logs", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		nil, nil, nil,
		content,
	)
}
