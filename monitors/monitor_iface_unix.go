// +build !windows

package someta

import (
	"log"
	"net"
	"sort"
)

/*
 a simple struct to build a map of interface names so that when
 any monitor is being configured with an interface name, we can
 easily check whether the name is valid.

 on UN*X systems, this is pretty straightforward/easy, especially
 since there's a consistent notion of what the "name" of an interface
 is, no matter what library we're using, e.g., golang net, pcap, etc.
*/

type interfaceNames struct {
	names map[string]string
}

func (i *interfaceNames) isValid(name string) bool {
	_, ok := i.names[name]
	return ok
}

func (i *interfaceNames) pcapName(name string) string {
	return i.names[name]
}

func (i *interfaceNames) buildIntfNameMap() {
	i.names = make(map[string]string)
	intfs, err := net.Interfaces()
	if err != nil {
		log.Fatal(err)
	}
	for _, n := range intfs {
		i.names[n.Name] = n.Name
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
