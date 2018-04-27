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
var monitorRegex = regexp.MustCompile(`^([a-z]+)(:.+)*`)
var debugOutput = false

type monitorConfig struct {
	cfg map[string](map[string]string)
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
	for _, kvstr := range strings.Split(strings.Trim(configvals[2], " "), ":") {
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
	m.cfg[name] = mc
	return nil
}

var outfileBase = "metadata"
var commandLine = ""
var statusInterval = 5 * time.Second
var warmCool = 1 * time.Second
var cpuAffinity = -1
var monCfg = &monitorConfig{}
var monitors map[string](*someta.MetadataGenerator)
var waiter = &sync.WaitGroup{}

func init() {
	monCfg.cfg = make(map[string](map[string]string))
	flag.StringVar(&commandLine, "c", "", "Command line for external measurement program")
	flag.BoolVar(&verboseOutput, "v", false, "Verbose output")
	flag.BoolVar(&quietOutput, "q", false, "Quiet output")
	flag.BoolVar(&debugOutput, "d", false, "Debug output (metadata is written to stdout)")
	flag.BoolVar(&logfileOutput, "l", false, "Send logging messages to a file (by default, they go to stdout)")
	flag.StringVar(&outfileBase, "f", "metadata", "Output file basename; current date/time is included as part of the filename")
	flag.DurationVar(&statusInterval, "u", 5*time.Second, "Time interval on which to show periodic status while running")
	flag.DurationVar(&warmCool, "w", 1*time.Second, "Wait time before starting external tool, and wait time after external tool stops, during which metadata are collected")
	flag.IntVar(&cpuAffinity, "C", -1, "Set CPU affinity (default is not to set affinity)")
	flag.Var(monCfg, "M", fmt.Sprintf("Select monitors to include. Default=None. Valid monitors=%s", strings.Join(someta.Monitors(), ",")))
	monitors = make(map[string](*someta.MetadataGenerator))
}

func startMonitors() {
	for mName, mon := range monitors {
		var monitor = mon
		if verboseOutput {
			log.Printf("Starting monitor %s\n", mName)
		}
		go func() {
			waiter.Add(1)
			(*monitor).Run(time.Second)
			waiter.Done()
		}()
	}
}

func stopMonitors() {
	for mName, mon := range monitors {
		if verboseOutput {
			log.Printf("Stopping monitor %s\n", mName)
		}
		(*mon).Stop()
	}
}

func flushMonitorMetadata(encoder *json.Encoder) {
	for mName, mon := range monitors {
		if verboseOutput {
			log.Printf("Flushing monitor %s\n", mName)
		}
		(*mon).Flush(encoder)
	}
}

func fileBase() string {
	tstr := time.Now().Format(time.RFC3339)
	return outfileBase + "_" + tstr
}

func main() {
	flag.Parse()
	if logfileOutput {
		logfile, err := os.OpenFile(fileBase()+".log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal(err)
		}
		log.SetOutput(logfile)
		defer logfile.Close()
	}

	if len(commandLine) == 0 {
		log.Fatalln("No command specified; exiting.")
	}

	for mName, mCfg := range monCfg.cfg {
		mon := someta.GetMonitor(mName)
		(*mon).Init(mName, verboseOutput, mCfg)
		monitors[mName] = mon
	}

	if len(monitors) == 0 {
		log.Fatalln("No monitors configured; exiting.")
	}

	log.Printf("Starting metadata measurement with verbose %v and command <%s>\n", verboseOutput, commandLine)

	// open metadata output
	var encoder *json.Encoder
	if !debugOutput {
		metaOut, err := os.OpenFile(fileBase()+".json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal(err)
		}
		defer metaOut.Close()
		encoder = json.NewEncoder(metaOut)
	} else {
		encoder = json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
	}

	sysinfo := make(map[string]interface{})
	sysdescription, _ := host.Info()
	sysinfo["sysinfo"] = sysdescription
	sysinfo["command"] = commandLine
	sysinfo["version"] = sometaVersion
	var start = time.Now()
	sysinfo["start"] = start
	cpuinfo, _ := cpu.Info()
	sysinfo["syscpu"] = cpuinfo
	meminfo, _ := mem.VirtualMemory()
	sysinfo["sysmem"] = meminfo
	netinfo, _ := net.Interfaces()
	sysinfo["sysnet"] = netinfo
	md := someta.MonitorMetadata{Name: "someta", Type: "system", Data: sysinfo}

	// start monitors
	startMonitors()

	time.Sleep(warmCool)

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

	statusTicker := time.NewTicker(statusInterval)
	defer statusTicker.Stop()
	done := false
	for !done {
		select {
		case output := <-cmdOutput:
			sysinfo["command_output"] = output
			done = true
		case t := <-statusTicker.C:
			if !quietOutput {
				cpupct, _ := cpu.Percent(0, false)
				diff := t.Sub(start)
				log.Printf("after %v cpu idle %3.2f%%\n", diff.Round(time.Second), 100-cpupct[0])
			}
		}
	}

	time.Sleep(warmCool)

	// shut down monitors
	stopMonitors()
	log.Println("Waiting for monitors to stop")
	waiter.Wait()

	// write out metadata
	sysinfo["end"] = time.Now()
	encoder.Encode(md)
	flushMonitorMetadata(encoder)
	if verboseOutput {
		log.Println("done")
	}
}
