package someta

import (
	"encoding/json"
	"fmt"
	"github.com/shirou/gopsutil/disk"
	"log"
	"strings"
	"sync"
	"time"
)

func init() {
	registerMonitor("io", &IOMonitor{})
}

// IOMetadata encapsulates what it says
type IOMetadata struct {
	Timestamp time.Time                      `json:"timestamp"`
	Counters  map[string]disk.IOCountersStat `json:"counters"`
}

// IOMonitor collects io/disk usage metadata
type IOMonitor struct {
	stop           chan struct{}
	metadata       []IOMetadata
	name           string
	verbose        bool
	mutex          sync.Mutex
	disksMonitored []string
}

// Init initializes an IOMonitor
func (i *IOMonitor) Init(name string, verbose bool, config map[string]string) error {
	i.name = name
	i.verbose = verbose
	i.stop = make(chan struct{})
	cmap, err := disk.IOCounters()
	if err != nil {
		log.Fatal(err)
	}
	var alldevs []string
	for devname := range cmap {
		alldevs = append(alldevs, devname)
	}

	for devname := range config {
		_, ok := cmap[devname]
		if !ok {
			return fmt.Errorf("%s monitor: device %s doesn't exist; valid devices: %s", i.name, devname, strings.Join(alldevs, ","))
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
		log.Printf("%s monitor: monitoring device%s %s\n", i.name, plural, strings.Join(i.disksMonitored, ","))
	}
	return nil
}

// Run runs the memory monitor; this should be invoked in a goroutine
func (i *IOMonitor) Run(interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-i.stop:
			if i.verbose {
				fmt.Printf("%s stopping\n", i.name)
			}
			return nil
		case t := <-ticker.C:
			iocounters, err := disk.IOCounters(i.disksMonitored...)
			if err != nil {
				log.Printf("%s: %v\n", i.name, err)
			} else {
				i.mutex.Lock()
				var currCounters = make(map[string]disk.IOCountersStat)
				for _, devname := range i.disksMonitored {
					currCounters[devname] = iocounters[devname]
				}
				i.metadata = append(i.metadata, IOMetadata{t, currCounters})
				i.mutex.Unlock()
			}
		}
	}
}

// Stop will (eventually) stop the IOMonitor
func (i *IOMonitor) Stop() {
	close(i.stop)
}

// Flush will write any current metadata to the writer
func (i *IOMonitor) Flush(encoder *json.Encoder) error {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	var md = MonitorMetadata{Name: i.name, Type: "monitor", Data: i.metadata}
	err := encoder.Encode(md)
	i.metadata = nil
	if err != nil {
		return err
	}
	return nil
}
