package someta

import (
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"time"
)

func init() {
	registerMonitor("ss", NewSsMonitor)
}

// NetstatMetadata encapsulates what it says
type SsMetadata struct {
	Timestamp time.Time `json:"timestamp"`
	Ss        string    `json:"info"`
}

// NewNetstatMonitor creates and returns a new NetstatMonitor
func NewSsMonitor() MetadataGenerator {
	return new(SsMonitor)
}

// NetstatMonitor collects network interface counters metadata
type SsMonitor struct {
	Monitor
	Data []SsMetadata `json:"data"`
	//	ifacesMonitored []string
}

// Init initializes a NetstatMonitor
func (n *SsMonitor) Init(name string, verbose bool, defaultInterval time.Duration, config map[string]string) error {
	n.baseInit(name, verbose, defaultInterval)

	intstr, ok := config["interval"]
	if ok {
		interval, err := time.ParseDuration(intstr)
		if err != nil {
			log.Fatalf("%s monitor: interval specification bad: %v\n", name, err)
		}
		n.interval = interval
		delete(config, "interval")
	}
	_, err := exec.LookPath("/bin/ss")
	if err != nil {
		return fmt.Errorf("%s monitor: ss command does not exist")
	}
	/*
		for devname := range config {
			if !intfNames.isValid(devname) {
				return fmt.Errorf("%s monitor: device %s doesn't exist; valid devices: %s", name, devname, strings.Join(intfNames.all(), ","))
			}
			n.ifacesMonitored = append(n.ifacesMonitored, devname)
		}

		// no device names specified; monitor all devices
		if len(config) == 0 {
			n.ifacesMonitored = intfNames.all()
		}
	*/
	if n.verbose {
		log.Printf("%s monitor: monitoring ss\n", name)
	}
	return nil
}

// Run runs the netstat monitor; this should be invoked in a goroutine
func (n *SsMonitor) Run() error {
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
