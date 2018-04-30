package someta

import (
	"encoding/json"
	"fmt"
	pkt "github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"time"
)

type probe struct {
	Source   net.IP    `json:"src"`
	Dest     net.IP    `json:"dst"`
	Sequence int       `json:"seq"`
	SendTime time.Time `json:"sendtime"`
	WireSend time.Time `json:"wiresend"`
	WireRecv time.Time `json:"wirerecv"`
	OutTTL   int       `json:"outttl"`
	RecvTTL  int       `json:"recvttl"`
}

func (p *probe) String() string {
	return fmt.Sprintf("%v->%v %d rtt %v", p.Source, p.Dest, p.Sequence, p.WireRecv.Sub(p.WireSend))
}

// RTTMetadata is a slice of probe samples.  It implements sort.Interface
type RTTMetadata struct {
	Probes []probe `json:"probes"`
}

// Len returns the number of probe samples
func (r *RTTMetadata) Len() int {
	return len(r.Probes)
}

// Less returns true if probe sample i has a send time < probe sample j
func (r *RTTMetadata) Less(i, j int) bool {
	return r.Probes[i].SendTime.Before(r.Probes[j].SendTime)
}

// Swap swaps two probe samples in the slice
func (r *RTTMetadata) Swap(i, j int) {
	r.Probes[i], r.Probes[j] = r.Probes[j], r.Probes[i]
}

// Append appends a probe record to the metadata
func (r *RTTMetadata) Append(p *probe) {
	r.Probes = append(r.Probes, *p)
}

/*
protocol, probetype, dest, total_probes_emitted, total_probes_received
maxttl probe_all_hops (t/f)
for each; rtt, wirerecv, usersend, wiresend, recvttl seq
*/

// RTTMonitor collects RTT samples using ICMP
type RTTMonitor struct {
	stop     chan struct{}
	metadata *RTTMetadata
	name     string
	verbose  bool
	mutex    sync.Mutex

	proto    string
	ipDest   string
	ipDestIP *net.IPAddr
	useV4    bool
	netDev   string

	probeMap    map[int](map[int]*probe) //map from ident to seq/probe
	probeIdents []int                    // ICMP Ids for probes
	initialTTLs []int                    // Initial TTLs for probes
	localAddrs  map[string]net.IP

	maxTTL       int
	hopLimited   bool
	nextSequence int
	allHops      bool

	interval time.Duration

	pcapHandle *pcap.Handle
	v4Listener net.PacketConn
	v4PktConn  *ipv4.PacketConn
}

var nameRegex *regexp.Regexp

// Init initializes an RTT monitor
func (r *RTTMonitor) Init(name string, verbose bool, defaultInterval time.Duration, config map[string]string) error {
	r.name = name
	r.verbose = verbose
	r.stop = make(chan struct{})
	md := &RTTMetadata{}
	r.metadata = md
	r.interval = defaultInterval

	r.proto = "ip:1" // default
	val, ok := config["dest"]
	if !ok {
		log.Fatalf(`%s monitor: Need "dest" in RTT monitor configuration`, name)
	}
	r.ipDest = val
	delete(config, "dest")

	var err error
	r.ipDestIP, err = net.ResolveIPAddr("ip", r.ipDest)
	if err != nil {
		log.Fatalf("%s monitor: couldn't parse destination IP address %s: %v\n", name, r.ipDest, err)
	}

	r.hopLimited = false
	val, ok = config["hoplimited"]
	if ok {
		b, err := strconv.ParseBool(val)
		if err != nil {
			log.Fatalf("%s monitor: hoplimited probe parameter: %v", name, err)
		}
		r.hopLimited = b
	} else {
		if verbose {
			log.Printf("%s monitor defaulting to ping mode\n", name)
		}
	}
	if r.hopLimited {
		log.Fatalf("%s monitor hop limited isn't tested yet\n", name)
	}

	if ip4 := r.ipDestIP.IP.To4(); ip4 != nil {
		r.useV4 = true
	} else {
		r.useV4 = false
		log.Fatalf("%s monitor: IPv6 probing is not implemented yet", name)
	}

	val, ok = config["interface"]
	if !ok {
		log.Fatalf(`%s monitor: need "interface" in RTT monitor configuration`, name)
	}
	r.netDev = val
	delete(config, "interface")

	r.maxTTL = 64
	val, ok = config["maxttl"]
	if ok {
		var err error
		r.maxTTL, err = strconv.Atoi(val)
		if err != nil {
			log.Fatalf("%s monitor: parsing maxttl: %v\n", name, err)
		}
		if r.maxTTL <= 0 || r.maxTTL > 255 {
			log.Fatalf("%s monitor: invalid value %d for hopcount\n", name, r.maxTTL)
		}
		if r.hopLimited && r.maxTTL > 32 {
			log.Fatalf("%s monitor: maxTTL too big for hop-limited probe", name)
		}
	}
	delete(config, "maxttl")

	r.allHops = true
	val, ok = config["allhops"]
	if ok {
		var err error
		r.allHops, err = strconv.ParseBool(val)
		if err != nil {
			log.Fatalf("%s monitor: can't parse allhops config: %s : %v\n", name, val, err)
		}
	}
	delete(config, "allhops")

	val, ok = config["rate"]
	if ok {
		rate, err := strconv.ParseFloat(val, 64)
		if err != nil {
			log.Fatalf("%s monitor: error with probe rate: %v\n", name, err)
		}
		r.interval = time.Duration(time.Duration(1000.0/rate) * time.Millisecond)
	}
	val, ok = config["interval"]
	if ok {
		ival, err := time.ParseDuration(val)
		if err != nil {
			log.Fatalf("%s monitor: error with probe rate: %v\n", name, err)
		}
		r.interval = ival
	}
	delete(config, "rate")
	delete(config, "interval")

	if len(config) > 0 {
		log.Fatalf("%s monitor: unhandled configuration: %v\n", name, config)
	}

	r.nextSequence = 1

	r.localAddrs = make(map[string]net.IP)
	r.getLocalAddrs(r.netDev)
	if len(r.localAddrs) == 0 {
		log.Fatalf("%s monitor: no IP addresses assigned to monitor device", name)
	}

	var baseIdent = os.Getpid() % 65535
	r.probeMap = make(map[int](map[int]*probe))
	namematch := nameRegex.FindStringSubmatch(name)
	if len(namematch) == 2 {
		i, _ := strconv.Atoi(namematch[1])
		// offset of 32 to accommodate multiple probers
		// that may be doing hop-limited probing (for which
		// separate probeIdents are used)
		baseIdent = (baseIdent + (i * 32)) % 65535
	}
	r.probeMap[baseIdent] = make(map[int]*probe)
	r.probeIdents = append(r.probeIdents, baseIdent)
	r.initialTTLs = append(r.initialTTLs, r.maxTTL)
	if r.hopLimited && r.allHops {
		// for hop-limited:
		//    maxttl = baseIdent
		//    maxttl-1 = baseIdent+1
		//    ...
		//    maxttl-k = baseIdent+k
		var mttl int
		for mttl = r.maxTTL - 1; mttl > 0; mttl-- {
			r.probeMap[baseIdent+1] = make(map[int]*probe)
			r.probeIdents = append(r.probeIdents, baseIdent+1)
			r.initialTTLs = append(r.initialTTLs, mttl)
		}
	}

	r.pcapSetup() // setup pcap listener (for both v4 and v6)
	r.v4Listener, r.v4PktConn = v4SenderSetup()

	return nil
}

// Stop will (eventually) stop the RTTMonitor
func (r *RTTMonitor) Stop() {
	close(r.stop)
}

func (r *RTTMonitor) shutdown() {
	r.pcapHandle.Close()
	r.v4Listener.Close()
	r.v4PktConn.Close()
}

// Flush will write any current metadata to the writer
func (r *RTTMonitor) Flush(encoder *json.Encoder) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	// FIXME: Data should be map[string]interface{}
	// FIXME: including some common things, as well as an embedded slice
	// of all the probe samples
	var md = MonitorMetadata{Name: r.name, Type: "monitor", Data: r.metadata}
	sort.Sort(r.metadata)
	err := encoder.Encode(md)
	r.metadata = nil
	if err != nil {
		return err
	}
	return nil
}

func (r *RTTMonitor) pcapReader() {
	packetSource := pkt.NewPacketSource(r.pcapHandle,
		r.pcapHandle.LinkType())
	packetSource.DecodeOptions.NoCopy = true
	packetSource.Lazy = true

	for {
		packet, err := packetSource.NextPacket()
		if err == io.EOF {
			fmt.Println("Done in pktreader")
			return
		} else if err != nil {
			continue
		}
		ts := packet.Metadata().Timestamp

		ip4 := packet.Layer(layers.LayerTypeIPv4)
		icmp4 := packet.Layer(layers.LayerTypeICMPv4)
		if ip4 != nil && icmp4 != nil {
			iphdr, _ := ip4.(*layers.IPv4)
			icmphdr, _ := icmp4.(*layers.ICMPv4)
			r.handleV4(ts, iphdr, icmphdr)
			continue
		}

		ip6 := packet.Layer(layers.LayerTypeIPv4)
		icmp6 := packet.Layer(layers.LayerTypeICMPv6)
		if ip6 != nil && icmp6 != nil {
			iphdr, _ := ip6.(*layers.IPv6)
			icmphdr, _ := icmp6.(*layers.ICMPv6)
			r.handleV6(ts, iphdr, icmphdr)
		}
	}
}

func (r *RTTMonitor) isMyICMPId(id int) bool {
	for _, val := range r.probeIdents {
		if val == id {
			return true
		}
	}
	return false
}

func (r *RTTMonitor) isMyIPAddr(addr net.IP) bool {
	_, ok := r.localAddrs[addr.String()]
	return ok
}

func (r *RTTMonitor) handleV4(ts time.Time, ip *layers.IPv4, icmp *layers.ICMPv4) {
	icmpid := int(icmp.Id)
	icmpseq := int(icmp.Seq)
	if !r.isMyICMPId(icmpid) {
		return
	}
	icmptype := icmp.TypeCode.Type()
	// icmpcode := icmp.TypeCode.Code()

	r.mutex.Lock()
	defer r.mutex.Unlock()
	proberec, ok := r.probeMap[icmpid][icmpseq]
	if !ok {
		return
	}

	if r.isMyIPAddr(ip.SrcIP) && icmptype == layers.ICMPv4TypeEchoRequest {
		// outgoing probe
		proberec.WireSend = ts
		proberec.Source = ip.SrcIP
	} else if r.isMyIPAddr(ip.DstIP) && icmptype == layers.ICMPv4TypeEchoReply {
		// incoming probe
		proberec.WireRecv = ts
		proberec.RecvTTL = int(ip.TTL)
		delete(r.probeMap[icmpid], icmpseq)
		if r.verbose {
			log.Printf("Probe %d rtt %v\n", icmpseq, proberec.WireRecv.Sub(proberec.WireSend))
		}
		r.metadata.Append(proberec)
	}

	/*
		if icmptype == layers.ICMPv4TypeEchoRequest || icmptype == layers.ICMPv4TypeEchoReply {
			// FIXME: need to deal with probeIdents as offsets for hop-limited probing
			if int(icmphdr.Id) != probeIdent {
				continue // not for us
			}
			fmt.Println("Probe is for us")
		} else if icmptype == layers.ICMPv4TypeTimeExceeded && icmpcode == layers.ICMPv4CodeTTLExceeded {
			payload := icmp4.LayerPayload()
			fmt.Println("ttl exceeded", payload)
			var nestedv4 layers.IPv4
			var nestedicmpv4 layers.ICMPv4
			parser := pkt.NewDecodingLayerParser(layers.LayerTypeIPv4, &nestedv4, &nestedicmpv4)
			decoded := make([]pkt.LayerType, 2, 2)
			parser.DecodeLayers(payload, &decoded)
			if nestedv4.Protocol == layers.IPProtocolICMPv4 {
				if int(nestedicmpv4.Id) != probeIdent {
					fmt.Println("carcass is for us")

				}

			}
		}
		prec, direction := getProbeRec(iphdr.SrcIP, iphdr.DstIP, icmphdr.Seq)
		if prec != nil {
			if direction == outgoing {
				prec.sendTime = ts
			} else {
				prec.recvTime = ts
				delete(probeMap, int(icmphdr.Seq))
				completeProbes = append(completeProbes, prec)
			}
		}
		log.Println(ts, iphdr.SrcIP, iphdr.DstIP, icmphdr.TypeCode, icmphdr.Id, icmphdr.Seq, icmphdr.Payload)
		log.Println(icmphdr)
	*/
}

func (r *RTTMonitor) handleV6(ts time.Time, ip *layers.IPv6, icmp *layers.ICMPv6) {
	log.Println("v6 packet receive isn't handled yet")
}

func (r *RTTMonitor) sweepProbes(all bool) {
	if r.verbose {
		log.Println("tacluso'r probiau")
	}
	var now = time.Now()
	r.mutex.Lock()
	for _, seqmap := range r.probeMap {
		for seq, prec := range seqmap {
			if prec.SendTime.Sub(now) > 2*time.Second {
				r.metadata.Append(prec)
				delete(seqmap, seq)
			}
		}
	}
	r.mutex.Unlock()
}

func (r *RTTMonitor) probeSweeper() {
	// every 2 seconds, sweep through and remove "old" probes
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			r.sweepProbes(false)
		case <-r.stop:
			return
		}
	}
}

// Run runs the RTT monitor; this should be invoked in a goroutine
func (r *RTTMonitor) Run() error {
	go r.pcapReader()
	go r.probeSweeper()
	defer r.shutdown()

	timer := time.NewTimer(r.interval)
	for {
		select {
		case <-timer.C:
			if r.verbose {
				log.Printf("Sending probe %d\n", r.nextSequence)
			}
			r.sendv4Probe()
			timer.Reset(r.interval)

		case <-r.stop:
			timer.Stop()
			time.Sleep(1 * time.Second)
			r.sweepProbes(true)
			return nil
		}
	}
}

func (r *RTTMonitor) sendv4Probe() {
	// emit probes for each hop being probed
	for i, ident := range r.probeIdents {
		ttl := r.initialTTLs[i]

		payloadVal := 65535 - (r.nextSequence % 65535)
		wm := icmp.Message{
			Type: ipv4.ICMPTypeEcho, Code: 0,
			Body: &icmp.Echo{
				ID: ident,
				Data: []byte{byte(payloadVal >> 8),
					byte(payloadVal), 0, 0},
			},
		}

		wm.Body.(*icmp.Echo).Seq = r.nextSequence
		wb, err := wm.Marshal(nil)
		if err != nil {
			log.Fatal(err)
		}

		if err := r.v4PktConn.SetTTL(ttl); err != nil {
			log.Fatal(err)
		}

		if _, err := r.v4PktConn.WriteTo(wb, nil, r.ipDestIP); err != nil {
			log.Fatal(err)
		}

		var probe = &probe{
			Dest:     r.ipDestIP.IP,
			Sequence: r.nextSequence,
			SendTime: time.Now(),
			OutTTL:   ttl,
		}
		r.mutex.Lock()
		r.probeMap[ident][r.nextSequence] = probe
		r.mutex.Unlock()
	}
	r.nextSequence = (r.nextSequence + 1) % 65535
}

// NewRTTMonitor creates and returns a new RTTMonitor
func NewRTTMonitor() MetadataGenerator {
	return new(RTTMonitor)
}

func init() {
	registerMonitor("rtt", NewRTTMonitor)
	nameRegex = regexp.MustCompile(`^rtt(\d*)$`)
}

func (r *RTTMonitor) getLocalAddrs(netDev string) {
	iface, err := net.InterfaceByName(netDev)
	if err != nil {
		log.Fatalf("device %s doesn't exist: %v", netDev, err)
	}

	addrs, err := iface.Addrs()
	for _, a := range addrs {
		ip, _, _ := net.ParseCIDR(a.String())
		if !ip.IsLoopback() {
			r.localAddrs[ip.String()] = ip
		}
	}
}

func (r *RTTMonitor) pcapSetup() {
	// no return value, because if there are any problems
	// below, we just log.Fatal and stop the show

	inactive, err := pcap.NewInactiveHandle(r.netDev)
	if err != nil {
		log.Fatal(err)
	}
	defer inactive.CleanUp()

	var tmo = time.Millisecond
	if runtime.GOOS == "linux" {
		tmo *= 10
	} else if runtime.GOOS == "darwin" {
		tmo *= 1
	}
	if r.verbose {
		log.Printf("RTTMonitor setting pcap timeout to %v\n", tmo)
	}
	if err = inactive.SetTimeout(tmo); err != nil {
		log.Printf("couldn't set timeout to %v on read: %v", tmo, err)
	}

	if err = inactive.SetSnapLen(128); err != nil {
		log.Fatal(err)
	}

	if err = inactive.SetPromisc(true); err != nil {
		log.Fatal(err)
	}

	tssources := inactive.SupportedTimestamps()
	if r.verbose {
		log.Printf("RTTMonitor supported timestamps: %v\n", tssources)
	}
	handle, err := inactive.Activate() // after this, inactive is no longer valid
	if err != nil {
		log.Fatalf("%v: %v", err, inactive.Error())
	}

	r.pcapHandle = handle
	if err = r.pcapHandle.SetBPFFilter("icmp or icmp6"); err != nil {
		log.Fatal(err)
	}
}

func v4SenderSetup() (net.PacketConn, *ipv4.PacketConn) {
	listener, err := net.ListenPacket("ip4:1", "0.0.0.0")
	if err != nil {
		log.Fatal(err)
	}
	netlayer := ipv4.NewPacketConn(listener)
	return listener, netlayer
}
