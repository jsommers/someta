package someta

import (
	"encoding/json"
	"time"
)

// MetadataGenerator is the interface that all metadata sources must adhere to
type MetadataGenerator interface {
	Init(string, bool, map[string]string) error
	Run(time.Duration) error
	Stop()
	Flush(*json.Encoder) error
}

// MonitorMetadata encapsulates metadata collected by a specific monitor
type MonitorMetadata struct {
	Name string      `json:"name"`
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

var monitorRegistry map[string]MetadataGenerator

func init() {
	monitorRegistry = make(map[string]MetadataGenerator)
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
func GetMonitor(name string) *MetadataGenerator {
	mGen, ok := monitorRegistry[name]
	if ok {
		return &mGen
	}
	return nil
}

// IsValidMonitor returns a bool indicating whether the string is the name of a valid monitor
func IsValidMonitor(name string) bool {
	_, ok := monitorRegistry[name]
	return ok
}
