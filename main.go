package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	someta "github.com/jsommers/someta/monitors"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/mem"
	"github.com/shirou/gopsutil/net"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

const sometaVersion = "2018.04"

var verboseOutput = false
var quietOutput = false
var logfileOutput = false
var monitorRegex = regexp.MustCompile(`^([a-z]+)(,.+)*`)
var debugOutput = false

type monitorConfig struct {
	cfg map[string]([]map[string]string)
}

func (m *monitorConfig) String() string {
	return fmt.Sprintf("%v", m.cfg)
}

func (m *monitorConfig) Set(val string) error {
	configvals := monitorRegex.FindStringSubmatch(val)
	if configvals == nil || len(configvals) <= 1 {
		return fmt.Errorf("no monitor name match with %s; expected monname or monname:cfg", val)
	}
	if !someta.IsValidMonitor(configvals[1]) {
		return fmt.Errorf("%s is not a valid monitor name", configvals[0])
	}

	var name = configvals[1]
	var mc = make(map[string]string)
	for _, kvstr := range strings.Split(strings.Trim(configvals[2], " "), ",") {
		kvitem := strings.Split(kvstr, "=")
		if len(kvitem) < 1 || len(kvitem) > 2 {
			log.Fatalf("Configuration key/val %s for %s formed incorrectly\n", kvstr, name)
		}
		key := strings.Trim(kvitem[0], " ")
		if len(key) == 0 {
			continue
		}
		val = ""
		if len(kvitem) == 2 {
			val = kvitem[1]
		}
		mc[kvitem[0]] = val
	}
	m.cfg[name] = append(m.cfg[name], mc)
	return nil
}

var outfileBase = "metadata"
var commandLine = ""
var statusInterval = 5 * time.Second
var monitorInterval = 1 * time.Second
var warmCool = 1 * time.Second
var cpuAffinity = -1
var monCfg = &monitorConfig{}
var monitors map[string]someta.MetadataGenerator
var waiter = &sync.WaitGroup{}
var fileFlushInterval = 10 * time.Minute
var fileRolloverInterval = 1 * time.Hour

func init() {
	monCfg.cfg = make(map[string]([]map[string]string))
	monitors = make(map[string]someta.MetadataGenerator)

	flag.StringVar(&commandLine, "c", "", "Command line for external measurement program")
	flag.BoolVar(&verboseOutput, "v", false, "Verbose output")
	flag.BoolVar(&quietOutput, "q", false, "Quiet output")
	flag.BoolVar(&debugOutput, "d", false, "Debug output (metadata is written to stdout)")
	flag.BoolVar(&logfileOutput, "l", false, "Send logging messages to a file (by default, they go to stdout)")
	flag.StringVar(&outfileBase, "f", "metadata", "Output file basename; current date/time is included as part of the filename")
	flag.DurationVar(&statusInterval, "u", 5*time.Second, "Time interval on which to show periodic status while running")
	flag.DurationVar(&monitorInterval, "m", 1*time.Second, "Time interval on which to gather metadata from monitors")
	flag.DurationVar(&warmCool, "w", 1*time.Second, "Wait time before starting external tool, and wait time after external tool stops, during which metadata are collected")
	flag.IntVar(&cpuAffinity, "C", -1, "Set CPU affinity (default is not to set affinity)")
	flag.Var(monCfg, "M", fmt.Sprintf("Select monitors to include. Default=None. Valid monitors=%s", strings.Join(someta.Monitors(), ",")))
	flag.DurationVar(&fileFlushInterval, "F", 10*time.Minute, "Time period after which in-memory metadata will be flushed to file")
	flag.DurationVar(&fileRolloverInterval, "R", 1*time.Hour, "Time period after which metadata output will rollover to a new file")
}

func configureMonitors() {
	for mName, mCfgSlice := range monCfg.cfg {
		for idx, mCfg := range mCfgSlice {
			var instanceName = mName
			if len(mCfgSlice) > 1 {
				instanceName = fmt.Sprintf("%s%d", mName, idx)
			}
			mon := someta.GetMonitor(mName)
			err := mon.Init(instanceName, verboseOutput, monitorInterval, mCfg)
			if err != nil {
				log.Fatal(err)
			}
			monitors[instanceName] = mon
		}
	}
}

func startMonitors() {
	for mName, mon := range monitors {
		var monitor = mon
		if verboseOutput {
			log.Printf("Starting monitor %s\n", mName)
		}
		go func() {
			waiter.Add(1)
			monitor.Run()
			waiter.Done()
		}()
	}
}

func stopMonitors() {
	for mName, mon := range monitors {
		if verboseOutput {
			log.Printf("Stopping monitor %s\n", mName)
		}
		mon.Stop()
	}
}

func flushMonitorMetadata(encoder *json.Encoder) {
	for mName, mon := range monitors {
		if verboseOutput {
			log.Printf("Flushing monitor %s\n", mName)
		}
		mon.Flush(encoder)
	}
}

func fileBase() string {
	tstr := time.Now().Format(time.RFC3339)
	return outfileBase + "_" + tstr
}

// SystemMetadata captures OS and hardware config information
type SystemMetadata struct {
	someta.Monitor
	SystemInfo    map[string]interface{} `json:"sysinfo"`
	CommandOutput string                 `json:"command_output"`

	logfile        *os.File
	metadataOutput *os.File
	encoder        *json.Encoder
}

func (s *SystemMetadata) init() {
	s.Name = "someta"
	s.Type = "system"
	s.SystemInfo = make(map[string]interface{})
	sysdescription, _ := host.Info()
	s.SystemInfo["someta"], _ = os.Executable()
	s.SystemInfo["sysinfo"] = sysdescription
	s.SystemInfo["command"] = commandLine
	s.SystemInfo["version"] = sometaVersion
	s.SystemInfo["start"] = time.Now()
	cpuinfo, _ := cpu.Info()
	s.SystemInfo["syscpu"] = cpuinfo
	meminfo, _ := mem.VirtualMemory()
	s.SystemInfo["sysmem"] = meminfo
	netinfo, _ := net.Interfaces()
	s.SystemInfo["sysnet"] = netinfo

	if logfileOutput {
		var err error
		s.logfile, err = os.OpenFile(fileBase()+".log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal(err)
		}
		log.SetOutput(s.logfile)
	}
}

func (s *SystemMetadata) cleanup() {
	s.logfile.Close()
	if !debugOutput {
		s.metadataOutput.Close()
	}
}

func (s *SystemMetadata) rolloverMetadata() {
	// open metadata output
	if !debugOutput {
		if s.metadataOutput != nil {
			s.metadataOutput.Close()
		}

		var err error
		s.metadataOutput, err = os.OpenFile(fileBase()+".json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal(err)
		}
		s.encoder = json.NewEncoder(s.metadataOutput)
	} else {
		s.encoder = json.NewEncoder(os.Stdout)
		s.encoder.SetIndent("", "  ")
	}
	s.encoder.Encode(s) // put system metadata at the head of metadata file
}

func main() {
	flag.Parse()
	rand.Seed(time.Now().UnixNano())

	start := time.Now()
	md := &SystemMetadata{}
	md.init()
	defer md.cleanup()

	if len(commandLine) == 0 {
		log.Fatalln("No command specified; exiting.")
	}

	configureMonitors() // side effect: modify monitors map
	if len(monitors) == 0 {
		log.Fatalln("No monitors configured; exiting.")
	}

	md.rolloverMetadata()

	log.Printf("Starting someta with verbose %v and command <%s>\n", verboseOutput, commandLine)
	if debugOutput {
		log.Printf("Not writing metadata to file (writing to stdout)")
	}

	startMonitors() // side effect: each monitor started in its own goroutine

	time.Sleep(warmCool)

	// start the main command
	cmdOutput := make(chan string)
	go func() {
		cmdarr := strings.Split(commandLine, " ")
		cmd := exec.Command(cmdarr[0], cmdarr[1:]...)
		var outbuf bytes.Buffer
		cmd.Stdout = &outbuf
		err := cmd.Run()
		if err != nil {
			log.Fatal(err)
		}
		if verboseOutput {
			log.Printf("Command <%s> completed\n", commandLine)
		}
		cmdOutput <- outbuf.String()
	}()

	// set up the main thread's loop
	statusTicker := time.NewTicker(statusInterval)
	defer statusTicker.Stop()
	rolloverTicker := time.NewTicker(fileRolloverInterval)
	defer rolloverTicker.Stop()
	fileFlushTicker := time.NewTicker(fileFlushInterval)
	defer fileFlushTicker.Stop()

	done := false
	for !done {
		select {
		case output := <-cmdOutput:
			md.CommandOutput = output
			done = true
		case t := <-statusTicker.C:
			if !quietOutput {
				cpupct, _ := cpu.Percent(0, false)
				diff := t.Sub(start)
				log.Printf("after %v cpu idle %3.2f%%\n", diff.Round(time.Second), 100-cpupct[0])
			}
		case <-rolloverTicker.C:
			log.Println("Metadata file rollover")
			md.rolloverMetadata()
		case <-fileFlushTicker.C:
			flushMonitorMetadata(md.encoder)
		}
	}

	time.Sleep(warmCool)

	// shut down monitors
	stopMonitors()
	log.Println("Waiting for monitors to stop")
	waiter.Wait()

	// write out metadata
	flushMonitorMetadata(md.encoder)
	if verboseOutput {
		log.Println("done")
	}
}
