package someta

import (
	"encoding/json"
	"fmt"
	"github.com/shirou/gopsutil/cpu"
	"log"
	"time"
)

func init() {
	registerMonitor("cpu", NewCPUMonitor)
}

// CPUMetadata encapsulates what it says
type CPUMetadata struct {
	Timestamp time.Time          `json:"timestamp"`
	CPU       map[string]float64 `json:"cpuidle"`
}

// NewCPUMonitor creates and returns a new CPUMonitor
func NewCPUMonitor() MetadataGenerator {
	return new(CPUMonitor)
}

// CPUMonitor collects cpu usage metadata
type CPUMonitor struct {
	Monitor
	metadata []CPUMetadata
}

// Init initializes a CPUMonitor
func (c *CPUMonitor) Init(name string, verbose bool, defaultInterval time.Duration, config map[string]string) error {
	c.baseInit(name, verbose, defaultInterval)
	intstr, ok := config["interval"]
	if ok {
		interval, err := time.ParseDuration(intstr)
		if err != nil {
			log.Fatalf("%s monitor: interval specification bad: %v\n", name, err)
		}
		c.interval = interval
		delete(config, "interval")
	}
	if len(config) > 0 {
		return fmt.Errorf("%s monitor: invalid configuration items present %v", name, config)
	}
	return nil
}

// Run runs the cpu monitor; this should be invoked in a goroutine
func (c *CPUMonitor) Run() error {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stop:
			if c.verbose {
				fmt.Printf("%s stopping\n", c.Name)
			}
			return nil
		case t := <-ticker.C:
			cpuval, err := cpu.Percent(0, true)
			if err != nil {
				log.Printf("%s: %v\n", c.Name, err)
			} else {
				if c.verbose {
					log.Printf("%s: %v\n", c.Name, cpuval)
				}
				cpuidle := make(map[string]float64)
				for i, pval := range cpuval {
					cpuidle[fmt.Sprintf("cpu%d_idle", i)] = 100.0 - pval
				}
				c.mutex.Lock()
				c.metadata = append(c.metadata, CPUMetadata{t, cpuidle})
				c.mutex.Unlock()
			}
		}
	}
}

// Flush will write any current metadata to the writer
func (c *CPUMonitor) Flush(encoder *json.Encoder) error {
	c.Data = c.metadata
	err := c.baseFlush(encoder)
	c.metadata = nil
	return err
}
