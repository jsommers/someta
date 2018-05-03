package someta

import (
	"encoding/json"
	"fmt"
	"github.com/shirou/gopsutil/net"
	"log"
	"sort"
	"strings"
	"time"
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

// Init initializes a NetstatMonitor
func (n *NetstatMonitor) Init(name string, verbose bool, defaultInterval time.Duration, config map[string]string) error {
	n.baseInit(name, verbose, defaultInterval)
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatal(err)
	}
	var allintf []string
	for _, netdev := range ifaces {
		allintf = append(allintf, netdev.Name)
	}
	sort.Strings(allintf)

	intstr, ok := config["interval"]
	if ok {
		interval, err := time.ParseDuration(intstr)
		if err != nil {
			log.Fatalf("%s monitor: interval specification bad: %v\n", name, err)
		}
		n.interval = interval
		delete(config, "interval")
	}

	for devname := range config {
		idx := sort.SearchStrings(allintf, devname)
		if idx == len(allintf) || allintf[idx] != devname {
			return fmt.Errorf("%s monitor: device %s doesn't exist; valid devices: %s", name, devname, strings.Join(allintf, ","))
		}
		n.ifacesMonitored = append(n.ifacesMonitored, devname)
	}
	// no device names specified; monitor all devices
	if len(config) == 0 {
		for _, intf := range ifaces {
			n.ifacesMonitored = append(n.ifacesMonitored, intf.Name)

		}
	}
	sort.Strings(n.ifacesMonitored)
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
func (n *NetstatMonitor) Run() error {
	ticker := time.NewTicker(n.interval)
	defer ticker.Stop()
	for {
		select {
		case <-n.stop:
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
