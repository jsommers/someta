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
	monitorRegistry["mem"] = &MemoryMonitor{}
}

type memoryMetadata struct {
	timestamp time.Time
	memory    *mem.VirtualMemoryStat
}

// MemoryMonitor collects memory usage metadata
type MemoryMonitor struct {
	stop     chan struct{}
	metadata []memoryMetadata
	name     string
	verbose  bool
	debug    bool
	mutex    sync.Mutex
}

// Init initialize a MemoryMonitor
func (m *MemoryMonitor) Init(name string, verbose bool, debug bool, config map[string]string) error {
	m.name = name
	m.verbose = verbose
	m.debug = debug
	m.stop = make(chan struct{})
	if len(config) > 0 {
		return fmt.Errorf("%s monitor: no configuration is expected", name)
	}
	return nil
}

// Run runs the memory monitor; this should be invoked in a goroutine
func (m *MemoryMonitor) Run(interval time.Duration) error {
	ticker := time.NewTicker(interval)
	for {
		select {
		case <-m.stop:
			fmt.Printf("%s stopping\n", m.name)
			break
		case t := <-ticker.C:
			memval, err := mem.VirtualMemory()
			if err != nil {
				log.Printf("%s: %v\n", m.name, err)
			} else {
				if m.debug || m.verbose {
					log.Printf("%s: %v\n", m.name, memval)
				}
				m.mutex.Lock()
				m.metadata = append(m.metadata, memoryMetadata{t, memval})
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
func (m *MemoryMonitor) Flush(encoder json.Encoder) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	err := encoder.Encode(m.metadata)
	if err != nil {
		return err
	}
	return nil
}
