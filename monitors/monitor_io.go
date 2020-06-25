package someta

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/shirou/gopsutil/disk"
	"log"
	"strings"
	"time"
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

// Init initializes an IOMonitor
func (i *IOMonitor) Init(name string, verbose bool, defaultInterval time.Duration, config map[string]string) error {
	i.baseInit(name, verbose, defaultInterval)
	cmap, err := disk.IOCounters()
	if err != nil {
		log.Fatal(err)
	}
	var alldevs []string
	for devname := range cmap {
		alldevs = append(alldevs, devname)
	}

	intstr, ok := config["interval"]
	if ok {
		interval, err := time.ParseDuration(intstr)
		if err != nil {
			log.Fatalf("%s monitor: interval specification bad: %v\n", name, err)
		}
		i.interval = interval
		delete(config, "interval")
	}

	for devname := range config {
		_, ok := cmap[devname]
		if !ok {
			return fmt.Errorf("%s monitor: device %s doesn't exist; valid devices: %s", name, devname, strings.Join(alldevs, ","))
		}
		i.disksMonitored = append(i.disksMonitored, devname)
	}
	if len(config) == 0 {
		for devname := range cmap {
			i.disksMonitored = append(i.disksMonitored, devname)
		}
	}
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
