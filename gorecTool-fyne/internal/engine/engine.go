package engine

import (
	"fmt"
	"sync"
)

// Define a callback function type
type UIUpdateFunc func(eventType string, data interface{})

// 1. The Event (The basic unit of information)
type EventType string

const (
	EventPortOpen       EventType = "PORT_OPEN"
	EventHttpService    EventType = "HTTP_SERVICE"
	EventVulnFound      EventType = "VULN_FOUND"
	EventSubdomainFound EventType = "SUBDOMAIN_FOUND"
)

type Event struct {
	Type    EventType
	Target  string // IP or Domain
	Payload string // Extra info (e.g., "80", "Apache 2.4")
}

// 2. The Rule (The Logic)
// A Rule checks an event and decides if it should trigger an Action
type Rule struct {
	Name      string
	Condition func(e Event) bool
	Action    func(e Event) // In reality, this would enqueue a new Job
}

// 3. The Brain (The Engine)
type DecisionEngine struct {
	Rules    []Rule
	Bus      chan Event
	wg       *sync.WaitGroup
	Callback UIUpdateFunc
}

func NewEngine(wg *sync.WaitGroup, cb UIUpdateFunc) *DecisionEngine {
	return &DecisionEngine{
		Rules:    []Rule{},
		Bus:      make(chan Event, 1000), // Buffered channel
		wg:       wg,
		Callback: cb,
	}
}

// AddRule registers a new logic pattern
func (de *DecisionEngine) AddRule(r Rule) {
	de.Rules = append(de.Rules, r)
}

// Start begins the listening loop
func (de *DecisionEngine) Start() {
	defer de.wg.Done()
	fmt.Println("[Engine] Decision Engine Started. Listening for events...")

	for event := range de.Bus {
		// Log every event

		// Send data to UI immediately
		if de.Callback != nil {
			de.Callback(string(event.Type), event)
		}
		fmt.Printf("[Log] Received Event: %s on %s (%s)\n", event.Type, event.Target, event.Payload)

		// Check against ALL rules (The Logic)
		for _, rule := range de.Rules {
			if rule.Condition(event) {
				fmt.Printf("[Logic] Rule '%s' Triggered! Executing Action.\n", rule.Name)
				// Run the action (usually distinct from the engine in real code)
				go rule.Action(event)
			}
		}
	}
}

// Helper to log simple text to the UI
func (de *DecisionEngine) Log(message string) {
	if de.Callback != nil {
		de.Callback("log", message)
	}
}

// Publish is used by modules to send data to the brain
func (de *DecisionEngine) Publish(e Event) {
	de.Bus <- e
}
