package someta

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"math/rand"
	"strconv"
	"strings"
	"sync"
	"time"
)

// MonitorConf defines a configuration for a monitor
type MonitorConf struct {
	Kind     string        // all monitors
	Interval time.Duration // all monitors
	Device   []string      // netstat, io, rtt
	RttType  string        // rtt
	Dest     string        // rtt
	MaxTTL   int           // rtt
	AllHops  bool          // rtt
	CmdOpts  []string      // ss, cmdlinetool
}

// String method - a slightly nicer repr of MonitorConf
func (m *MonitorConf) String() string {
	outstr := fmt.Sprintf("cfg %s: interval: %v", m.Kind, m.Interval)
	if m.Kind == "rtt" {
		outstr += fmt.Sprintf("; %s to %s; maxttl %d", m.RttType, m.Dest, m.MaxTTL)
		if m.RttType == "hoplimited" {
			outstr += fmt.Sprintf("; allhops? %v", m.AllHops)
		}
	}
	if m.Kind == "io" || m.Kind == "netstat" { // ugly...
		outstr += fmt.Sprintf("; devices: %s", strings.Join(m.Device, ", "))
	}
	return outstr
}

// MonitorConfFromStringMap constructs a MonitorConf from a str map from command line
func MonitorConfFromStringMap(kind string, strconfig map[string]string) (MonitorConf, error) {
	var conf = MonitorConf{}
	conf.Kind = kind

	intstr, ok := strconfig["interval"]
	if ok {
		interval, err := time.ParseDuration(intstr)
		if err != nil {
			return conf, err
		}
		conf.Interval = interval
		delete(strconfig, "interval")
	}

	val, ok := strconfig["dest"]
	if ok {
		conf.Dest = val
	}
	delete(strconfig, "dest")

	val, ok = strconfig["type"]
	if ok {
		conf.RttType = val
		delete(strconfig, "type")
	}

	val, ok = strconfig["device"]
	if ok {
		conf.Device = append(conf.Device, val)
		delete(strconfig, "device")
	}

	val, ok = strconfig["interface"]
	if ok {
		conf.Device = append(conf.Device, val)
		delete(strconfig, "interface")
	}

	val, ok = strconfig["maxttl"]
	if ok {
		var err error
		conf.MaxTTL, err = strconv.Atoi(val)
		if err != nil {
			log.Fatalf("%s monitor: parsing maxttl: %v", kind, err)
		}
		delete(strconfig, "maxttl")
	}

	conf.AllHops = true
	val, ok = strconfig["allhops"]
	if ok {
		if conf.RttType == "ping" {
			log.Fatalf("%s monitor: allhops is incompatible with type=ping\n", kind)
		}
		var err error
		conf.AllHops, err = strconv.ParseBool(val)
		if err != nil {
			log.Fatalf("%s monitor: can't parse allhops config: %s : %v\n", kind, val, err)
		}
		delete(strconfig, "allhops")
	}

	val, ok = strconfig["rate"]
	if ok {
		rate, err := strconv.ParseFloat(val, 64)
		if err != nil {
			log.Fatalf("%s monitor: error with rate value: %v\n", kind, err)
		}
		conf.Interval = time.Duration(time.Duration(1000.0/rate) * time.Millisecond)
		delete(strconfig, "rate")
	}

	for devname := range strconfig {
		conf.Device = append(conf.Device, devname)
	}
	return conf, nil
}

// MetadataGenerator is the interface that all metadata sources must adhere to
type MetadataGenerator interface {
	Init(string, bool, time.Duration, MonitorConf) error
	Run(context.Context) error
	Flush(*json.Encoder) error
	CheckConfig(string, MonitorConf)
	DefaultConfig() *MonitorConf
}

// Monitor encapsulates elements common to all monitors
type Monitor struct {
	Name string `json:"name"`
	Kind string `json:"type"` // v1.3 change external name to Kind; keep json as type for back compat

	verbose  bool
	mutex    sync.Mutex
	interval time.Duration
}

func (m *Monitor) baseInit(name string, verbose bool, defaultInterval time.Duration) {
	m.Name = name
	m.Kind = "monitor"
	m.interval = defaultInterval
}

var monitorRegistry map[string](func() MetadataGenerator)

// InitRegistry initializes the monitor registry; must be called by someta main
func registerMonitor(name string, gen func() MetadataGenerator) {
	if monitorRegistry == nil {
		monitorRegistry = make(map[string](func() MetadataGenerator))
	}
	monitorRegistry[name] = gen
}

// Monitors returns a slice of monitor names
func Monitors() []string {
	var monNames []string
	for name := range monitorRegistry {
		monNames = append(monNames, name)
	}
	return monNames
}

// GetMonitor returns a pointer to a MetadataGenerator given a name, or nil if no such monitor exists
func GetMonitor(name string) MetadataGenerator {
	mGen, ok := monitorRegistry[name]
	if ok {
		return mGen()
	}
	return nil
}

// IsValidMonitor returns a bool indicating whether the string is the name of a valid monitor
func IsValidMonitor(name string) bool {
	_, ok := monitorRegistry[name]
	return ok
}

var intfNames = &interfaceNames{}

func init() {
	intfNames.buildIntfNameMap()
}

// code adapted from Python standard library Lib/random.py
func _gammavariate(alpha, beta float64) float64 {
	if alpha <= 0.0 || beta <= 0.0 {
		log.Fatal("gammavariate: alpha and beta must be > 0.0")
	}

	if alpha <= 1 {
		log.Fatal("gammavariate: algorithm not intended to handle alpha <= 1")
	}

	MagicConst := 1.0 + math.Log(4.5)
	Log4 := math.Log(4.0)
	const LowVal = 1e-7

	ainv := math.Sqrt(2.0*alpha - 1.0)
	bbb := alpha - Log4
	ccc := alpha + ainv

	for {
		u1 := rand.Float64()

		if !(LowVal < u1 && u1 < .9999999) {
			continue
		}
		u2 := 1.0 - rand.Float64()
		v := math.Log(u1/(1.0-u1)) / ainv
		x := alpha * math.Exp(v)
		z := u1 * u1 * u2
		r := bbb + ccc*v - x
		if r+MagicConst-4.5*z >= 0.0 || r >= math.Log(z) {
			return x * beta
		}
	}
}

func gammaInterval(interval time.Duration) time.Duration {
	rate := 1.0 / interval.Seconds()
	shape := 4.0 //  fixed integral shape 4-16; see SIGCOMM 06 and IMC 07 papers
	mean := 1 / rate
	scale := 1 / (shape / mean)
	// convert to nanos
	gv := _gammavariate(shape, scale) * 1000000000
	return time.Duration(int64(gv))
}
