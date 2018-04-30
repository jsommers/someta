package someta

import (
	"encoding/json"
	"log"
	"math"
	"math/rand"
	"time"
)

// MetadataGenerator is the interface that all metadata sources must adhere to
type MetadataGenerator interface {
	Init(string, bool, time.Duration, map[string]string) error
	Run() error
	Stop()
	Flush(*json.Encoder) error
}

// MonitorMetadata encapsulates metadata collected by a specific monitor
type MonitorMetadata struct {
	Name string      `json:"name"`
	Type string      `json:"type"`
	Data interface{} `json:"data"`
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

func gammaInterval(rate float64) float64 {
	shape := 4.0 //  fixed integral shape 4-16; see SIGCOMM 06 and IMC 07 papers
	mean := 1 / rate
	scale := 1 / (shape / mean)
	return _gammavariate(shape, scale)
}
