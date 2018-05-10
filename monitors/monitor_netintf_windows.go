// +build windows

package someta

import (
	"bytes"
	"encoding/csv"
	"log"
	"os/exec"
)

/*
 a simple struct to build a map of interface names so that when
 any monitor is being configured with an interface name, we can
 easily check whether the name is valid.

 on windows systems, this is unfortunately not straightforward.  golang
 net package has a different (but "normal") notion of an interface
 name, but pcap shows either the guid or an unuseful description.  hence
 our callout to getmac and building a map to make this easier.
*/

type interfaceNames struct {
	names map[string]string
}

func (i interfaceNames) isValid(name string) {
	_, ok := i.names[name]
	return ok
}

func (i interfaceNames) pcapName(name string) {
	return i.names[name]
}

func (i interfaceNames) buildIntfNameMap() {
	cmd := exec.Command("getmac", "/fo", "csv", "/nh", "/v")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Fatal(err)
	}
	i.names = make(map[string]string)
	csv := csv.NewReader(bytes.NewReader(out.Bytes()))
	for {
		fields, err := csv.Read()
		if err != nil {
			if err == io.EOF {
				break
			} else {
				log.Fatal(err)
			}
		}
		if len(fields) == 0 {
			continue
		}
		i.names[fields[0]] = fields[3]
	}
}

func (i interfaceNames) all() []string {
	var names []string
	for n := range i.names {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
