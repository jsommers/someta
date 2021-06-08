package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	someta "github.com/jsommers/someta/monitors"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/mem"
	"github.com/shirou/gopsutil/net"
	"gopkg.in/yaml.v2"
)

const sometaVersion = "1.3.0"

var verboseOutput = false
var quietOutput = false
var logfileOutput = false
var monitorRegex = regexp.MustCompile(`^([a-z]+)([:,].+)*$`)
var debugOutput = false

func usage() {
	fmt.Printf("Usage of %s:\n", os.Args[0])
	flag.PrintDefaults()
	fmt.Println("\nMonitors available:")
	for _, name := range someta.Monitors() {
		fmt.Printf("\t%s\n", name)
	}
}

type monitorConfig struct {
	cfg map[string]([]someta.MonitorConf)
}

func (m *monitorConfig) String() string {
	return fmt.Sprintf("%v", m.cfg)
}

func (m *monitorConfig) Set(val string) error {
	configvals := monitorRegex.FindStringSubmatch(val)
	if configvals == nil || len(configvals) <= 1 {
		return fmt.Errorf("no monitor name match with %s; expected monname or monname,key1=val1,key2=val2", val)
	}
	if !someta.IsValidMonitor(configvals[1]) {
		return fmt.Errorf("%s is not a valid monitor name", configvals[0])
	}
	name := configvals[1]

	var mc = make(map[string]string)
	if len(configvals) == 3 && len(configvals[2]) > 0 {
		var separator = configvals[2][:1]
		var cfgstr = configvals[2][1:]

		for _, kvstr := range strings.Split(strings.Trim(cfgstr, " "), separator) {
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
	}

	var thiscfg someta.MonitorConf
	var err error
	if thiscfg, err = someta.MonitorConfFromStringMap(configvals[1], mc); err != nil {
		return err
	}
	m.cfg[name] = append(m.cfg[name], thiscfg)
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
var configFile = ""
var checkConfig = false

func init() {
	monCfg.cfg = make(map[string]([]someta.MonitorConf))
	monitors = make(map[string]someta.MetadataGenerator)
	flag.Usage = usage

	flag.StringVar(&configFile, "y", "", "Name of YAML configuration file")
	flag.BoolVar(&checkConfig, "Y", false, "Check config file but don't start metadata collection")
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

// SometaConf defines a someta system configuration
type SometaConf struct {
	Someta struct {
		Command              string
		Outfilebase          string
		Verbose              bool
		Quiet                bool
		Debug                bool
		UseLogfile           bool
		StatusInterval       time.Duration
		MonitorInterval      time.Duration
		MetaFlushInterval    time.Duration
		FileRolloverInterval time.Duration
		WarmCoolTime         time.Duration
		CPUAffinity          int
	}
	Readme     string `yaml:"readme"`
	StaticMeta struct {
		ExtFiles []string
	}
	Monitors []someta.MonitorConf
}

func configFileUpdate(exitFatal bool) {
	contents, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Fatal(err)
	}
	var smConf SometaConf
	err = yaml.Unmarshal(contents, &smConf)
	if err != nil {
		if exitFatal {
			log.Fatal(err)
		} else {
			log.Println(err)
		}
	}

	commandLine = smConf.Someta.Command
	outfileBase = smConf.Someta.Outfilebase
	verboseOutput = smConf.Someta.Verbose
	quietOutput = smConf.Someta.Quiet
	debugOutput = smConf.Someta.Debug
	logfileOutput = smConf.Someta.UseLogfile
	statusInterval = smConf.Someta.StatusInterval
	monitorInterval = smConf.Someta.MonitorInterval
	fileFlushInterval = smConf.Someta.MetaFlushInterval
	fileRolloverInterval = smConf.Someta.FileRolloverInterval
	warmCool = smConf.Someta.WarmCoolTime
	cpuAffinity = smConf.Someta.CPUAffinity

	for _, mCfg := range smConf.Monitors {
		if !someta.IsValidMonitor(mCfg.Kind) {
			log.Fatalf("%s is not a valid monitor name", mCfg.Kind)
		}
		monCfg.cfg[mCfg.Kind] = append(monCfg.cfg[mCfg.Kind], mCfg)
	}
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

func startMonitors(ctx context.Context) {
	for mName, mon := range monitors {
		var monitor = mon
		if verboseOutput {
			log.Printf("Starting monitor %s\n", mName)
		}
		waiter.Add(1)
		go func() {
			monitor.Run(ctx)
			waiter.Done()
		}()
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
	s.Kind = "system"
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
}

func (s *SystemMetadata) writeMetadata() {
	s.encoder.Encode(s)
}

func main() {
	flag.Parse()
	if configFile != "" {
		configFileUpdate(true)
	}
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
	if checkConfig {
		log.Println("Exiting after checking configuration")
		if verboseOutput {
			log.Println("Configured monitors: ")
			for _, mCfgList := range monCfg.cfg {
				for _, c := range mCfgList {
					log.Println(c.String())
				}
			}
		} else {
			log.Println("Use -v to show monitor configuration")
		}
		return
	}

	md.rolloverMetadata()

	log.Printf("Starting someta with verbose %v and command <%s>\n", verboseOutput, commandLine)
	if debugOutput {
		log.Printf("Not writing metadata to file (writing to stdout)")
	}

	ctx, stopMonitors := context.WithCancel(context.Background())
	startMonitors(ctx) // side effect: each monitor started in its own goroutine

	time.Sleep(warmCool)

	// start the main command
	cmdOutput := make(chan string)
	go func() {
		path, err := exec.LookPath("sh")
		if err != nil {
			log.Fatalf("sh doesn't exist to run external command: %v; ensure PATH includes sh executable\n", err)
		}
		cmd := exec.Command(path, "-c", commandLine)
		stdoutStderr, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("Command <%s> exited with error: %v\n", commandLine, err)
		}
		if verboseOutput {
			log.Printf("Command <%s> completed\n", commandLine)
			log.Printf("Command output: %s\n", stdoutStderr)
		}
		cmdOutput <- string(stdoutStderr)
	}()

	// set up the main thread's loop
	statusTicker := time.NewTicker(statusInterval)
	defer statusTicker.Stop()
	rolloverTicker := time.NewTicker(fileRolloverInterval)
	defer rolloverTicker.Stop()
	fileFlushTicker := time.NewTicker(fileFlushInterval)
	defer fileFlushTicker.Stop()

	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, os.Interrupt)
	signal.Notify(sigchan, syscall.SIGHUP)

	done := false
	for !done {
		select {
		case output := <-cmdOutput:
			log.Println("cmd output outside:", output)
			md.CommandOutput = output
			done = true
		case s := <-sigchan:
			log.Println("Got signal: ", s)
			flushMonitorMetadata(md.encoder)
			if s == syscall.SIGINT {
				signal.Ignore()
				done = true
			} else {
				// FIXME
				configFileUpdate(false) // don't exit with fatal error when re-reading config
				fmt.Println("SIGHUP reset metadata collection")
			}
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
	if verboseOutput {
		log.Println("Stopping monitors")
	}
	stopMonitors()
	log.Println("Waiting for monitors to stop")
	waiter.Wait()

	md.writeMetadata() // write out system metadata
	flushMonitorMetadata(md.encoder)
	if verboseOutput {
		log.Println("done")
	}
}
