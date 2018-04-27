package someta

import (
	"encoding/json"
	"fmt"
	"github.com/shirou/gopsutil/cpu"
	"log"
	"sync"
	"time"
)

func init() {
	registerMonitor("cpu", &CPUMonitor{})
}

// CPUMetadata encapsulates what it says
type CPUMetadata struct {
	Timestamp time.Time `json:"timestamp"`
	CPU       []float64 `json:"cpuidle"`
}

// CPUMonitor collects cpu usage metadata
type CPUMonitor struct {
	stop     chan struct{}
	metadata []CPUMetadata
	name     string
	verbose  bool
	mutex    sync.Mutex
}

// Init initializes a CPUMonitor
func (c *CPUMonitor) Init(name string, verbose bool, config map[string]string) error {
	c.name = name
	c.verbose = verbose
	c.stop = make(chan struct{})
	if len(config) > 0 {
		return fmt.Errorf("%s monitor: no configuration is expected", name)
	}
	return nil
}

// Run runs the cpu monitor; this should be invoked in a goroutine
func (c *CPUMonitor) Run(interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stop:
			if c.verbose {
				fmt.Printf("%s stopping\n", c.name)
			}
			return nil
		case t := <-ticker.C:
			cpuval, err := cpu.Percent(0, true)
			if err != nil {
				log.Printf("%s: %v\n", c.name, err)
			} else {
				if c.verbose {
					log.Printf("%s: %v\n", c.name, cpuval)
				}
				// turn values into idles
				for i := range cpuval {
					cpuval[i] = 100 - cpuval[i]
				}
				c.mutex.Lock()
				c.metadata = append(c.metadata, CPUMetadata{t, cpuval})
				c.mutex.Unlock()
			}
		}
	}
}

// Stop will (eventually) stop the CPUMonitor
func (c *CPUMonitor) Stop() {
	close(c.stop)
}

// Flush will write any current metadata to the writer
func (c *CPUMonitor) Flush(encoder *json.Encoder) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	var md = MonitorMetadata{Name: c.name, Type: "monitor", Data: c.metadata}
	err := encoder.Encode(md)
	c.metadata = nil
	if err != nil {
		return err
	}
	return nil
}