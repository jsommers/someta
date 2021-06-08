package someta

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/shirou/gopsutil/cpu"
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
	Data []CPUMetadata `json:"data"`
}

// CheckConfig does some basic sanity checking on the configuration
func (c *CPUMonitor) CheckConfig(name string, conf MonitorConf) {
	if conf.Interval == 0 {
		conf.Interval = time.Second * 1
	}
	if conf.Interval < time.Second*1 {
		log.Fatalf("%s: interval %v too short", name, conf.Interval)
	}
	if len(conf.Device) > 0 {
		log.Fatalf("%s: device config inappropriate", name)
	}
}

// Init initializes a CPUMonitor
func (c *CPUMonitor) Init(name string, verbose bool, defaultInterval time.Duration, config MonitorConf) error {
	c.CheckConfig(name, config)
	c.baseInit(name, verbose, defaultInterval)
	return nil
}

// Run runs the cpu monitor; this should be invoked in a goroutine
func (c *CPUMonitor) Run(ctx context.Context) error {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
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
				c.Data = append(c.Data, CPUMetadata{t, cpuidle})
				c.mutex.Unlock()
			}
		}
	}
}

// Flush will write any current metadata to the writer
func (c *CPUMonitor) Flush(encoder *json.Encoder) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	err := encoder.Encode(c)
	c.Data = nil
	return err
}
