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
	registerMonitor("cmdlinetool", NewCmdLineToolMonitor)
}

// CmdLineToolMetadata encapsulates what it says
type CmdLineToolMetadata struct {
	Timestamp  time.Time `json:"timestamp"`
	ToolOutput string    `json:"tooloutput"`
}

// NewCmdLineToolMonitor creates and returns a new NetstatMonitor
func NewCmdLineToolMonitor() MetadataGenerator {
	return new(CmdLineToolMonitor)
}

// CmdLineToolMonitor collects metadata from the linux ss tool
type CmdLineToolMonitor struct {
	Monitor
	CmdLineToolOptions []string              `json:"cmdlineoptions"`
	Data               []CmdLineToolMetadata `json:"data"`
}

// DefaultConfig returns a default config or nil if no default
func (c *CmdLineToolMonitor) DefaultConfig() *MonitorConf {
	return nil
}

// CheckConfig does some basic sanity checking on the configuration
func (c *CmdLineToolMonitor) CheckConfig(name string, conf MonitorConf) {
	if conf.Interval < time.Millisecond*1 {
		log.Fatalf("%s: interval %v too short", name, conf.Interval)
	}
	_, err := exec.LookPath(conf.CmdOpts[0])
	if err != nil {
		log.Fatalf("%s monitor: %s command does not exist", name, conf.CmdOpts[0])
	}
}

// Init initializes an CmdLineToolMonitor
func (c *CmdLineToolMonitor) Init(name string, verbose bool, defaultInterval time.Duration, config MonitorConf) error {
	c.baseInit(name, verbose, defaultInterval)
	c.CheckConfig(name, config)
	c.CmdLineToolOptions = config.CmdOpts
	if c.verbose {
		log.Printf("%s monitor: monitoring %v\n", name, c.CmdLineToolOptions)
	}
	return nil
}

// Run runs the netstat monitor; this should be invoked in a goroutine
func (c *CmdLineToolMonitor) Run(ctx context.Context) error {
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
			out, err := exec.CommandContext(ctx, c.CmdLineToolOptions[0], c.CmdLineToolOptions[1:]...).Output()
			if err != nil {
				log.Printf("%s: %v\n", c.Name, err)
			} else {
				c.mutex.Lock()
				c.Data = append(c.Data, CmdLineToolMetadata{t, string(out)})
				c.mutex.Unlock()

			}
		}
	}
}

// Flush will write any current metadata to the writer
func (c *CmdLineToolMonitor) Flush(encoder *json.Encoder) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	err := encoder.Encode(c)
	c.Data = nil
	return err
}
