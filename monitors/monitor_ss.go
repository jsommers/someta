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
	SsOptions string       `json:"ssoptions"`
	Data      []SsMetadata `json:"data"`
}

// CheckConfig does some basic sanity checking on the configuration
func (s *SsMonitor) CheckConfig(name string, conf MonitorConf) {
	if conf.Interval < time.Millisecond*1 {
		log.Fatalf("%s: interval %v too short", name, conf.Interval)
	}
	_, err := exec.LookPath("/bin/ss")
	if err != nil {
		log.Fatalf("%s monitor: /bin/ss command does not exist", name)
	}
}

// Init initializes an SsMonitor
func (s *SsMonitor) Init(name string, verbose bool, defaultInterval time.Duration, config MonitorConf) error {
	s.baseInit(name, verbose, defaultInterval)
	s.CheckConfig(name, config)
	if s.verbose {
		log.Printf("%s monitor: monitoring ss\n", name)
	}
	if config.CmdOpts[0] != "" {
		s.SsOptions = config.CmdOpts[0]
	} else {
		s.SsOptions = "-iemptb" // same as original behavior
	}
	return nil
}

// Run runs the netstat monitor; this should be invoked in a goroutine
func (s *SsMonitor) Run(ctx context.Context) error {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			if s.verbose {
				fmt.Printf("%s stopping\n", s.Name)
			}
			return nil
		case t := <-ticker.C:
			out, err := exec.Command("ss", s.SsOptions).Output()
			if err != nil {
				log.Printf("%s: %v\n", s.Name, err)
			} else {
				s.mutex.Lock()
				s.Data = append(s.Data, SsMetadata{t, string(out)})
				s.mutex.Unlock()

			}
		}
	}
}

// Flush will write any current metadata to the writer
func (s *SsMonitor) Flush(encoder *json.Encoder) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	err := encoder.Encode(s)
	s.Data = nil
	return err
}
