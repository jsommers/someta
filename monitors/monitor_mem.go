package someta

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/shirou/gopsutil/mem"
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

// DefaultConfig returns a default config or nil if no default
func (m *MemoryMonitor) DefaultConfig() *MonitorConf {
	conf := &MonitorConf{Kind: "mem",
		Interval: 1 * time.Second}
	return conf
}

// CheckConfig does some basic sanity checking on the configuration
func (m *MemoryMonitor) CheckConfig(name string, conf MonitorConf) {
	if conf.Interval < time.Second*1 {
		log.Fatalf("%s: interval %v too short", name, conf.Interval)
	}
	if len(conf.Device) > 0 {
		log.Fatalf("%s: device config inappropriate", name)
	}
}

// Init initialize a MemoryMonitor
func (m *MemoryMonitor) Init(name string, verbose bool, defaultInterval time.Duration, config MonitorConf) error {
	m.CheckConfig(name, config)
	m.baseInit(name, verbose, defaultInterval)
	return nil
}

// Run runs the memory monitor; this should be invoked in a goroutine
func (m *MemoryMonitor) Run(ctx context.Context) error {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
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
