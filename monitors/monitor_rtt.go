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

	interval float64

	pcapHandle *pcap.Handle
	v4Listener net.PacketConn
	v4PktConn  *ipv4.PacketConn
}

var nameRegex *regexp.Regexp

// Init initializes an RTT monitor
func (r *RTTMonitor) Init(name string, verbose bool, config map[string]string) error {
	r.name = name
	r.verbose = verbose
	r.stop = make(chan struct{})
	md := &RTTMetadata{}
	r.metadata = md

	r.proto = "ip:1" // default
	val, ok := config["dest"]
	if !ok {
		log.Fatal(`Need "dest" in RTT monitor configuration`)
	}
	r.ipDest = val
	delete(config, "dest")

	var err error
	r.ipDestIP, err = net.ResolveIPAddr("ip", r.ipDest)
	if err != nil {
		log.Fatalf("couldn't parse destination IP address %s: %v\n", r.ipDest, err)
	}

	r.hopLimited = false
	val, ok = config["hoplimited"]
	if ok {
		b, err := strconv.ParseBool(val)
		if err != nil {
			log.Fatalf("hoplimited probe parameter: %v", err)
		}
		r.hopLimited = b
	} else {
		if verbose {
			log.Printf("RTTMonitor %s defaulting to ping mode\n", name)
		}
	}
	if r.hopLimited {
		log.Fatal("hop limited isn't tested yet")
	}

	if ip4 := r.ipDestIP.IP.To4(); ip4 != nil {
		r.useV4 = true
	} else {
		r.useV4 = false
		log.Fatal("Warning: IPv6 probing is not implemented yet")
	}

	val, ok = config["interface"]
	if !ok {
		log.Fatal(`Need "interface" in RTT monitor configuration`)
	}
	r.netDev = val
	delete(config, "interface")

	r.maxTTL = 64
	val, ok = config["maxttl"]
	if ok {
		var err error
		r.maxTTL, err = strconv.Atoi(val)
		if err != nil {
			log.Fatalf("parsing maxttl: %v\n", err)
		}
		if r.maxTTL <= 0 || r.maxTTL > 255 {
			log.Fatalf("invalid value %d for hopcount\n", r.maxTTL)
		}
		if r.hopLimited && r.maxTTL > 32 {
			log.Fatalf("maxTTL too big for hop-limited probe")
		}
	}
	delete(config, "maxttl")

	r.allHops = true
	val, ok = config["allhops"]
	if ok {
		var err error
		r.allHops, err = strconv.ParseBool(val)
		if err != nil {
			log.Fatalf("can't parse allhops config: %s : %v\n", val, err)
		}
	}
	delete(config, "allhops")

	r.interval = 1.0
	val, ok = config["rate"]
	if ok {
		rate, err := strconv.ParseFloat(val, 64)
		if err != nil {
			log.Fatalf("error with probe rate: %v\n", err)
		}
		r.interval = 1.0 / rate
	}
	val, ok = config["interval"]
	if ok {
		var err error
		r.interval, err = strconv.ParseFloat(val, 32)
		if err != nil {
			log.Fatalf("error with probe rate: %v\n", err)
		}
	}
	delete(config, "rate")
	delete(config, "interval")

	if len(config) > 0 {
		log.Fatalf("Unhandled RTTMonitor configuration: %v\n", config)
	}

	r.nextSequence = 1

	r.localAddrs = make(map[string]net.IP)
	r.getLocalAddrs(r.netDev)
	if len(r.localAddrs) == 0 {
		log.Fatal("No IP addresses assigned to monitor device")
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
		r.mutex.Lock()
		r.metadata.Append(proberec)
		r.mutex.Unlock()
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

// Run runs the RTT monitor; this should be invoked in a goroutine
func (r *RTTMonitor) Run(interval time.Duration) error {
	go r.pcapReader()
	defer r.shutdown()

	// FIXME: should do this with gamma probing, not uniform
	// FIXME: should stay in this loop until we see that
	// the probeMap is drained (or close to drained)

	// FIXME: need to add a sweeper for the probemap to clean out
	// probes that don't have a recv (are lost)
	tick := time.NewTicker(interval)
	defer tick.Stop()

	for {
		select {
		case <-tick.C:
			if r.verbose {
				log.Printf("Sending probe %d\n", r.nextSequence)
			}
			r.sendv4Probe()

		case <-r.stop:
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
		r.probeMap[ident][r.nextSequence] = probe
	}
	r.nextSequence = (r.nextSequence + 1) % 65535
}

type probeDirection int

const (
	notMyProbe probeDirection = iota
	outgoing
	incoming
)

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

/*
func main() {
	flag.Parse()
	mon := &RTTMonitor{}
	cfg := make(map[string]string)
	cfg["dest"] = "149.43.80.25"
	cfg["interface"] = "en0"
	cfg["maxttl"] = "32"

	if err := mon.Init("rtt", true, cfg); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Running on", runtime.GOOS)

	go func() {
		mon.Run(time.Second * 1)
	}()
	fmt.Println("Sleeping")
	time.Sleep(10 * time.Second)
	fmt.Println("Woke up; stopping")
	mon.Stop()

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")

	mon.Flush(encoder)
}
*/

func (r *RTTMonitor) pcapSetup() {
	// no return value, because if there are any problems
	// below, we just log.Fatal and stop the show

	inactive, err := pcap.NewInactiveHandle(r.netDev)
	if err != nil {
		log.Fatal(err)
	}
	defer inactive.CleanUp()

	// works best on darwin
        var tmo time.Duration = time.Millisecond
        if runtime.GOOS == "linux" {
            tmo *= 100
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
	listener, err := net.ListenPacket("ip4:1", "0.0.0.0") // this must be ip4 for later sockopts to work correctly
	if err != nil {
		log.Fatal(err)
	}
	netlayer := ipv4.NewPacketConn(listener)
	if err := netlayer.SetControlMessage(ipv4.FlagTTL|ipv4.FlagSrc|ipv4.FlagDst|ipv4.FlagInterface, true); err != nil {
		log.Fatal(err)
	}
	return listener, netlayer
}
