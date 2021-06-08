package someta

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/shirou/gopsutil/net"
)

func init() {
	registerMonitor("netstat", NewNetstatMonitor)
}

// NetstatMetadata encapsulates what it says
type NetstatMetadata struct {
	Timestamp time.Time                     `json:"timestamp"`
	Netstat   map[string]net.IOCountersStat `json:"netstat"`
}

// NewNetstatMonitor creates and returns a new NetstatMonitor
func NewNetstatMonitor() MetadataGenerator {
	return new(NetstatMonitor)
}

// NetstatMonitor collects network interface counters metadata
type NetstatMonitor struct {
	Monitor
	Data            []NetstatMetadata `json:"data"`
	ifacesMonitored []string
}

// CheckConfig does some basic sanity checking on the configuration
func (n *NetstatMonitor) CheckConfig(name string, conf MonitorConf) {
	if conf.Interval < time.Second*1 {
		log.Fatalf("%s: interval %v too short", name, conf.Interval)
	}

	for _, devname := range conf.Device {
		if !intfNames.isValid(devname) {
			log.Fatalf("%s monitor: device %s doesn't exist; valid devices: %s", name, devname, strings.Join(intfNames.all(), ","))
		}
	}
}

// Init initializes a NetstatMonitor
func (n *NetstatMonitor) Init(name string, verbose bool, defaultInterval time.Duration, config MonitorConf) error {
	n.CheckConfig(name, config)
	n.baseInit(name, verbose, defaultInterval)

	// no device names specified; monitor all devices
	if len(config.Device) == 0 {
		config.Device = intfNames.all()
	}
	n.ifacesMonitored = config.Device

	if n.verbose {
		plural := ""
		if len(n.ifacesMonitored) > 1 {
			plural = "s"
		}
		log.Printf("%s monitor: monitoring device%s %s\n", name, plural, strings.Join(n.ifacesMonitored, ","))
	}
	return nil
}

// Run runs the netstat monitor; this should be invoked in a goroutine
func (n *NetstatMonitor) Run(ctx context.Context) error {
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
			netstats, err := net.IOCounters(true)
			countermap := make(map[string]net.IOCountersStat)
			for _, ioc := range netstats {
				idx := sort.SearchStrings(n.ifacesMonitored, ioc.Name)
				if idx < len(n.ifacesMonitored) && n.ifacesMonitored[idx] == ioc.Name {
					countermap[ioc.Name] = ioc
				}
			}
			if err != nil {
				log.Printf("%s: %v\n", n.Name, err)
			} else {
				n.mutex.Lock()
				n.Data = append(n.Data, NetstatMetadata{t, countermap})
				n.mutex.Unlock()
			}
		}
	}
}

// Flush will write any current metadata to the writer
func (n *NetstatMonitor) Flush(encoder *json.Encoder) error {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	err := encoder.Encode(n)
	n.Data = nil
	return err
}
