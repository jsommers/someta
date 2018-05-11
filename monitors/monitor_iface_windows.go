// +build windows

package someta

import (
	"bytes"
	"encoding/csv"
        // "fmt"
        "github.com/google/gopacket/pcap"
	"io"
	"log"
	"os/exec"
	"sort"
        "strings"
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
        pcapDevs []string
}

func (i *interfaceNames) isValid(name string) bool {
	_, ok := i.names[name]
	return ok
}

func (i *interfaceNames) pcapName(name string) string {
        // need to translate "\Tcpip_" -> "\NPF_"
        // fmt.Println("pcapdevs", i.pcapDevs)

	return strings.Replace(i.names[name], "Tcpip_", "NPF_", 1)
}

func (i *interfaceNames) buildIntfNameMap() {
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

        pcaps, err := pcap.FindAllDevs()
        if err != nil {
            log.Fatal(err)
        }
        for _, p := range pcaps {
            i.pcapDevs = append(i.pcapDevs, p.Name)
        }
}

func (i *interfaceNames) all() []string {
	var names []string
	for n := range i.names {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
