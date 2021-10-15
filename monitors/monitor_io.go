package someta

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/shirou/gopsutil/disk"
)

func init() {
	registerMonitor("io", NewIOMonitor)
}

// IOMetadata encapsulates what it says
type IOMetadata struct {
	Timestamp time.Time                      `json:"timestamp"`
	Counters  map[string]disk.IOCountersStat `json:"counters"`
}

// NewIOMonitor creates and returns a new IOMonitor
func NewIOMonitor() MetadataGenerator {
	return new(IOMonitor)
}

// IOMonitor collects io/disk usage metadata
type IOMonitor struct {
	Monitor
	Data           []IOMetadata `json:"data"`
	disksMonitored []string
}

// DefaultConfig returns a default config or nil if no default
func (i *IOMonitor) DefaultConfig() *MonitorConf {
	var disks []string
	statmap, _ := disk.IOCounters()
	for name := range statmap {
		disks = append(disks, name)
	}
	conf := &MonitorConf{Kind: "io",
		Interval: 1 * time.Second,
		Device:   disks,
	}
	return conf
}

// CheckConfig does some basic sanity checking on the configuration
func (i *IOMonitor) CheckConfig(name string, conf MonitorConf) {
	if conf.Interval < time.Second*1 {
		log.Fatalf("%s: interval %v too short", name, conf.Interval)
	}

	// get a list of valid device names
	cmap, err := disk.IOCounters()
	if err != nil {
		log.Fatal(err)
	}

	var allDisks []string
	for devname := range cmap {
		allDisks = append(allDisks, devname)
	}

	for _, devname := range conf.Device {
		_, ok := cmap[devname]
		if !ok {
			log.Fatalf("%s monitor: device %s doesn't exist (valid disks: %s)", name, devname, strings.Join(allDisks, ","))
		}
		conf.Device = append(conf.Device, devname)
	}
}

// Init initializes an IOMonitor
func (i *IOMonitor) Init(name string, verbose bool, defaultInterval time.Duration, config MonitorConf) error {
	i.CheckConfig(name, config)
	i.baseInit(name, verbose, defaultInterval)

	if len(config.Device) == 0 {
		cmap, err := disk.IOCounters()
		if err != nil {
			log.Fatal(err)
		}
		for devname := range cmap {
			config.Device = append(config.Device, devname)
		}
	}
	i.disksMonitored = config.Device

	if i.verbose {
		plural := ""
		if len(i.disksMonitored) > 1 {
			plural = "s"
		}
		log.Printf("%s monitor: monitoring device%s %s\n", name, plural, strings.Join(i.disksMonitored, ","))
	}
	return nil
}

// Run runs the memory monitor; this should be invoked in a goroutine
func (i *IOMonitor) Run(ctx context.Context) error {
	ticker := time.NewTicker(i.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			if i.verbose {
				fmt.Printf("%s stopping\n", i.Name)
			}
			return nil
		case t := <-ticker.C:
			iocounters, err := disk.IOCounters(i.disksMonitored...)
			if err != nil {
				log.Printf("%s: %v\n", i.Name, err)
			} else {
				i.mutex.Lock()
				var currCounters = make(map[string]disk.IOCountersStat)
				for _, devname := range i.disksMonitored {
					currCounters[devname] = iocounters[devname]
				}
				i.Data = append(i.Data, IOMetadata{t, currCounters})
				i.mutex.Unlock()
			}
		}
	}
}

// Flush will write any current metadata to the writer
func (i *IOMonitor) Flush(encoder *json.Encoder) error {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	err := encoder.Encode(i)
	i.Data = nil
	return err
}
