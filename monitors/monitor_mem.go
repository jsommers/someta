package someta

import (
	"encoding/json"
	"fmt"
	"github.com/shirou/gopsutil/mem"
	"log"
	"time"
)

func init() {
	registerMonitor("mem", NewMemoryMonitor)
}

// MemoryMetadata encapsulates what it says
type MemoryMetadata struct {
	Timestamp   time.Time `json:"timestamp"`
	UsedPercent float64   `json:"percent_used"`
}

// NewMemoryMonitor creates and returns a new MemoryMonitor
func NewMemoryMonitor() MetadataGenerator {
	return new(MemoryMonitor)
}

// MemoryMonitor collects memory usage metadata
type MemoryMonitor struct {
	Monitor
	Data []MemoryMetadata `json:"data"`
}

// Init initialize a MemoryMonitor
func (m *MemoryMonitor) Init(name string, verbose bool, defaultInterval time.Duration, config map[string]string) error {
	m.baseInit(name, verbose, defaultInterval)

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
				fmt.Printf("%s stopping\n", m.Name)
			}
			return nil
		case t := <-ticker.C:
			memval, err := mem.VirtualMemory()
			if err != nil {
				log.Printf("%s: %v\n", m.Name, err)
			} else {
				m.mutex.Lock()
				m.Data = append(m.Data, MemoryMetadata{t, memval.UsedPercent})
				m.mutex.Unlock()
			}
		}
	}
}

// Flush will write any current metadata to the writer
func (m *MemoryMonitor) Flush(encoder *json.Encoder) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	err := encoder.Encode(m)
	m.Data = nil
	return err
}
