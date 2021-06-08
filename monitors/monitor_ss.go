// +build linux

package someta

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"time"
)

func init() {
	registerMonitor("ss", NewSsMonitor)
}

// SsMetadata encapsulates what it says
type SsMetadata struct {
	Timestamp time.Time `json:"timestamp"`
	Ss        string    `json:"info"`
}

// NewSsMonitor creates and returns a new NetstatMonitor
func NewSsMonitor() MetadataGenerator {
	return new(SsMonitor)
}

// SsMonitor collects metadata from the linux ss tool
type SsMonitor struct {
	Monitor
	Data []SsMetadata `json:"data"`
}

// CheckConfig does some basic sanity checking on the configuration
func (c *CPUMonitor) CheckConfig(name string, conf MonitorConf) {
	if conf.Interval < time.Millisecond*1 {
		log.Fatalf("%s: interval %v too short", name, conf.Interval)
	}
	_, err := exec.LookPath("/bin/ss")
	if err != nil {
		log.Fatalf("%s monitor: /bin/ss command does not exist", name)
	}
}

// Init initializes an SsMonitor
func (n *SsMonitor) Init(name string, verbose bool, defaultInterval time.Duration, config MonitorConf) error {
	s.baseInit(name, verbose, defaultInterval)
	if err := s.CheckConfig(name, config); err != nil {
		return err
	}
	if s.verbose {
		log.Printf("%s monitor: monitoring ss\n", name)
	}
	return nil
}

// Run runs the netstat monitor; this should be invoked in a goroutine
func (n *SsMonitor) Run(ctx context.Context) error {
	ticker := time.NewTicker(n.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			if n.verbose {
				fmt.Printf("%s stopping\n", n.Name)
			}
			return nil
		case t := <-ticker.C:
			out, err := exec.Command("ss", "-i", "-e", "-m", "-p", "-t", "-b").Output()
			if err != nil {
				log.Printf("%s: %v\n", n.Name, err)
			} else {
				n.mutex.Lock()
				n.Data = append(n.Data, SsMetadata{t, string(out)})
				n.mutex.Unlock()

			}
		}
	}
}

// Flush will write any current metadata to the writer
func (n *SsMonitor) Flush(encoder *json.Encoder) error {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	err := encoder.Encode(n)
	n.Data = nil
	return err
}
