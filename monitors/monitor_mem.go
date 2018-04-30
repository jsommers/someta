package someta

import (
	"encoding/json"
	"fmt"
	"github.com/shirou/gopsutil/mem"
	"log"
	"sync"
	"time"
)

func init() {
	registerMonitor("mem", NewMemoryMonitor)
}

// MemoryMetadata encapsulates what it says
type MemoryMetadata struct {
	Timestamp   time.Time `json:"timestamp"`
	UsedPercent float64   `json:"usedPercent"`
}

// NewMemoryMonitor creates and returns a new MemoryMonitor
func NewMemoryMonitor() MetadataGenerator {
	return new(MemoryMonitor)
}

// MemoryMonitor collects memory usage metadata
type MemoryMonitor struct {
	stop     chan struct{}
	metadata []MemoryMetadata
	name     string
	verbose  bool
	mutex    sync.Mutex
	interval time.Duration
}

// Init initialize a MemoryMonitor
func (m *MemoryMonitor) Init(name string, verbose bool, defaultInterval time.Duration, config map[string]string) error {
	m.name = name
	m.verbose = verbose
	m.interval = defaultInterval
	m.stop = make(chan struct{})

	intstr, ok := config["interval"]
	if ok {
		interval, err := time.ParseDuration(intstr)
		if err != nil {
			log.Fatalf("%s monitor: interval specification bad: %v\n", name, err)
		}
		m.interval = interval
		delete(config, "interval")
	}
	if len(config) > 0 {
		return fmt.Errorf("%s monitor: invalid configuration items present %v", name, config)
	}
	return nil
}

// Run runs the memory monitor; this should be invoked in a goroutine
func (m *MemoryMonitor) Run() error {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	for {
		select {
		case <-m.stop:
			if m.verbose {
				fmt.Printf("%s stopping\n", m.name)
			}
			return nil
		case t := <-ticker.C:
			memval, err := mem.VirtualMemory()
			if err != nil {
				log.Printf("%s: %v\n", m.name, err)
			} else {
				m.mutex.Lock()
				m.metadata = append(m.metadata, MemoryMetadata{t, memval.UsedPercent})
				m.mutex.Unlock()
			}
		}
	}
}

// Stop will (eventually) stop the MemoryMonitor
func (m *MemoryMonitor) Stop() {
	close(m.stop)
}

// Flush will write any current metadata to the writer
func (m *MemoryMonitor) Flush(encoder *json.Encoder) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	var md = MonitorMetadata{Name: m.name, Type: "monitor", Data: m.metadata}
	err := encoder.Encode(md)
	m.metadata = nil
	if err != nil {
		return err
	}
	return nil
}
