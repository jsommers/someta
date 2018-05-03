package someta

import (
	"encoding/json"
	"fmt"
	pkt "github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"time"
)

type probe struct {
	Source    net.IP    `json:"src"`
	Dest      net.IP    `json:"dst"`
	Responder net.IP    `json:"responder"`
	Sequence  int       `json:"seq"`
	SendTime  time.Time `json:"sendtime"`
	WireSend  time.Time `json:"wiresend"`
	WireRecv  time.Time `json:"wirerecv"`
	OutTTL    int       `json:"outttl"`
	RecvTTL   int       `json:"recvttl"`
}

func (p *probe) String() string {
	return fmt.Sprintf("%v->%v %d rtt %v", p.Source, p.Dest, p.Sequence, p.WireRecv.Sub(p.WireSend))
}

// RTTMetadata is a slice of probe samples.  It implements sort.Interface
type RTTMetadata struct {
	Probes        []probe     `json:"probes"`
	PcapStats     *pcap.Stats `json:"libpcap_stats"`
	Protocol      string      `json:"protocol"`
	Probetype     string      `json:"probetype"`
	TotalEmitted  int64       `json:"total_probes_emitted"`
	TotalReceived int64       `json:"total_probes_received"`
	ProbeAllHops  bool        `json:"probe_all_hops"`
	MaxTTL        int         `json:"maxttl"`
	IPDest        string      `json:"dest"`
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

// RTTMonitor collects RTT samples using ICMP
type RTTMonitor struct {
	Monitor
	RTTMetadata

	destIPAddr *net.IPAddr
	useV4      bool
	netDev     string

	probeMap    map[int](map[int]*probe) //map from ident to seq/probe
	probeIdents []int                    // ICMP Ids for probes
	initialTTLs []int                    // Initial TTLs for probes
	localAddrs  map[string]net.IP

	nextSequence int

	pcapStats  *pcap.Stats
	pcapHandle *pcap.Handle
	v4Listener net.PacketConn
	v4PktConn  *ipv4.PacketConn
	v6Listener net.PacketConn
	v6PktConn  *ipv6.PacketConn
}

var nameRegex *regexp.Regexp

// Init initializes an RTT monitor
func (r *RTTMonitor) Init(name string, verbose bool, defaultInterval time.Duration, config map[string]string) error {
	r.baseInit(name, verbose, defaultInterval)

	val, ok := config["dest"]
	if !ok {
		log.Fatalf(`%s monitor: Need "dest" in RTT monitor configuration`, name)
	}
	r.IPDest = val
	delete(config, "dest")

	var err error
	r.destIPAddr, err = net.ResolveIPAddr("ip", val)
	if err != nil {
		log.Fatalf("%s monitor: couldn't parse destination IP address %s: %v\n", name, val, err)
	}

	hopLimited := false
	val, ok = config["type"]
	if ok {
		if val == "hoplimited" {
			hopLimited = true
		} else if val != "ping" {
			log.Fatalf("%s monitor unrecognized probe type %s\n", name, val)
		}
		delete(config, "type")
	}

	if ip4 := r.destIPAddr.IP.To4(); ip4 != nil {
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

	r.MaxTTL = 64
	val, ok = config["maxttl"]
	if ok {
		if !hopLimited {
			log.Printf("%s monitor: warning: specifying maxttl for type=ping\n", name)
		}
		var err error
		r.MaxTTL, err = strconv.Atoi(val)
		if err != nil {
			log.Fatalf("%s monitor: parsing maxttl: %v\n", name, err)
		}
		if r.MaxTTL <= 0 || r.MaxTTL > 255 {
			log.Fatalf("%s monitor: invalid value %d for hopcount\n", name, r.MaxTTL)
		}
		if hopLimited && r.MaxTTL > 32 {
			log.Fatalf("%s monitor: maxTTL too big for hop-limited probe", name)
		}
	}
	delete(config, "maxttl")

	r.ProbeAllHops = true
	val, ok = config["allhops"]
	if ok {
		if !hopLimited {
			log.Fatalf("%s monitor: allhops is incompatible with type=ping\n", name)
		}
		var err error
		r.ProbeAllHops, err = strconv.ParseBool(val)
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
	r.initialTTLs = append(r.initialTTLs, r.MaxTTL)
	if hopLimited && r.ProbeAllHops {
		// for hop-limited:
		//    maxttl = baseIdent
		//    maxttl-1 = baseIdent+1
		//    ...
		//    maxttl-k = baseIdent+k
		var mttl int
		var i = 1
		for mttl = r.MaxTTL - 1; mttl > 0; mttl-- {
			r.probeMap[baseIdent+i] = make(map[int]*probe)
			r.probeIdents = append(r.probeIdents, baseIdent+i)
			r.initialTTLs = append(r.initialTTLs, mttl)
			i++
		}
	}
	r.PcapStats = r.pcapStats
	r.Protocol = "icmp"
	if hopLimited {
		r.Probetype = "hoplimited"
	} else {
		r.Probetype = "ping"
	}

	r.pcapSetup() // setup pcap listener (for both v4 and v6)
	if r.useV4 {
		r.v4Listener, r.v4PktConn = v4SenderSetup()
	} else {
		r.v6Listener, r.v6PktConn = v6SenderSetup()
	}

	return nil
}

func (r *RTTMonitor) shutdown() {
	stats, err := r.pcapHandle.Stats()
	if err != nil {
		log.Printf("%s monitor: error getting pcap stats: %v\n", r.Name, err)
	} else {
		r.pcapStats = stats
	}
	r.pcapHandle.Close()
	r.pcapHandle = nil
	if r.useV4 {
		r.v4Listener.Close()
		r.v4PktConn.Close()
	} else {
		r.v6Listener.Close()
		r.v6PktConn.Close()
	}
}

// Flush will write any current metadata to the writer
func (r *RTTMonitor) Flush(encoder *json.Encoder) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if r.pcapHandle != nil {
		stats, _ := r.pcapHandle.Stats()
		r.pcapStats = stats
	}

	sort.Sort(r)
	err := encoder.Encode(r)
	r.Probes = nil
	return err
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

func (r *RTTMonitor) updateOutgoingProbe(icmpid int, icmpseq int, ts time.Time, ipaddr net.IP) {
	// outgoing probe
	r.mutex.Lock()
	defer r.mutex.Unlock()
	proberec, ok := r.probeMap[icmpid][icmpseq]
	if ok {
		proberec.WireSend = ts
		proberec.Source = ipaddr
	}
}

func (r *RTTMonitor) updateIncomingProbe(icmpid int, icmpseq int, ts time.Time, ttl int, responder net.IP) {
	// incoming probe
	r.mutex.Lock()
	defer r.mutex.Unlock()
	proberec, ok := r.probeMap[icmpid][icmpseq]
	if !ok {
		return
	}
	proberec.WireRecv = ts
	proberec.RecvTTL = ttl
	proberec.Responder = responder
	delete(r.probeMap[icmpid], icmpseq)
	if r.verbose {
		log.Printf("Probe %d rtt %v\n", icmpseq, proberec.WireRecv.Sub(proberec.WireSend))
	}
	r.Append(proberec)
	r.TotalReceived++
}

func (r *RTTMonitor) handleV4(ts time.Time, ip *layers.IPv4, icmp *layers.ICMPv4) {
	if !(r.isMyIPAddr(ip.SrcIP) || r.isMyIPAddr(ip.DstIP)) {
		return
	}

	icmpid := int(icmp.Id)
	icmpseq := int(icmp.Seq)
	icmptype := icmp.TypeCode.Type()
	icmpcode := icmp.TypeCode.Code()

	if icmptype == layers.ICMPv4TypeEchoRequest && r.isMyICMPId(icmpid) {
		r.updateOutgoingProbe(icmpid, icmpseq, ts, ip.SrcIP)
	} else if icmptype == layers.ICMPv4TypeEchoReply && r.isMyICMPId(icmpid) {
		r.updateIncomingProbe(icmpid, icmpseq, ts, int(ip.TTL), ip.SrcIP)
	} else if icmptype == layers.ICMPv4TypeTimeExceeded && icmpcode == layers.ICMPv4CodeTTLExceeded {
		// incoming TTL exceeded; maybe with a packaged probe
		payload := icmp.LayerPayload()
		var nestedv4 layers.IPv4
		var nestedicmpv4 layers.ICMPv4
		parser := pkt.NewDecodingLayerParser(layers.LayerTypeIPv4, &nestedv4, &nestedicmpv4)
		decoded := make([]pkt.LayerType, 2, 2)
		parser.DecodeLayers(payload, &decoded)
		if nestedv4.Protocol == layers.IPProtocolICMPv4 {
			nestedID := int(nestedicmpv4.Id)
			if r.isMyICMPId(nestedID) {
				nestedSeq := int(nestedicmpv4.Seq)
				r.updateIncomingProbe(nestedID, nestedSeq, ts, int(ip.TTL), ip.SrcIP)
			}
		}
	}
}

func (r *RTTMonitor) handleV6(ts time.Time, ip *layers.IPv6, icmp *layers.ICMPv6) {
	log.Println("v6 packet receive isn't handled yet", ts, ip, icmp)
}

func (r *RTTMonitor) sweepProbes(all bool) {
	if r.verbose {
		log.Println("tacluso'r probiau")
	}
	var now = time.Now()
	r.mutex.Lock()
	for _, seqmap := range r.probeMap {
		for seq, prec := range seqmap {
			if all || prec.SendTime.Sub(now) >= 10*time.Second {
				r.Append(prec)
				delete(seqmap, seq)
			}
		}
	}
	r.mutex.Unlock()
}

func (r *RTTMonitor) probeSweeper() {
	// every 2 seconds, sweep through and remove "old" probes
	t := time.NewTicker(30 * time.Second)
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

	timer := time.NewTimer(gammaInterval(r.interval))
	now := time.Now()
	for {
		select {
		case t := <-timer.C:
			if r.verbose {
				log.Printf("Sending probe %d (gap %v)\n", r.nextSequence, t.Sub(now))
			}
			now = time.Now()
			r.sendProbe()
			timer.Reset(gammaInterval(r.interval))

		case <-r.stop:
			timer.Stop()
			time.Sleep(1 * time.Second)
			r.sweepProbes(true)
			return nil
		}
	}
}

func (r *RTTMonitor) sendProbe() {
	// emit probes for each hop being probed
	for i, ident := range r.probeIdents {
		ttl := r.initialTTLs[i]

		// keep constant the checksum to deal with load balancers
		// aka tokyo ping
		payloadVal := 65535 - ((r.nextSequence + ident) % 65535)

		now := time.Now()
		if r.useV4 {
			r.sendv4Probe(ident, ttl, payloadVal)
		} else {
			r.sendv6Probe(ident, ttl, payloadVal)
		}
		r.TotalEmitted++

		var probe = &probe{
			Dest:     r.destIPAddr.IP,
			Sequence: r.nextSequence,
			SendTime: now,
			OutTTL:   ttl,
		}
		r.mutex.Lock()
		r.probeMap[ident][r.nextSequence] = probe
		r.mutex.Unlock()
	}
	r.nextSequence = (r.nextSequence + 1) % 65535

}

func (r *RTTMonitor) sendv4Probe(ident, ttl, payload int) {
	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: ident,
			Data: []byte{byte(payload >> 8),
				byte(payload), 0, 0},
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

	if _, err := r.v4PktConn.WriteTo(wb, nil, r.destIPAddr); err != nil {
		log.Fatal(err)
	}
}

func (r *RTTMonitor) sendv6Probe(ident, ttl, payload int) {
	wm := icmp.Message{
		Type: ipv6.ICMPTypeEchoRequest, Code: 0,
		Body: &icmp.Echo{
			ID: ident,
			Data: []byte{byte(payload >> 8),
				byte(payload), 0, 0},
		},
	}

	wm.Body.(*icmp.Echo).Seq = r.nextSequence
	wb, err := wm.Marshal(nil)
	if err != nil {
		log.Fatal(err)
	}

	if err := r.v6PktConn.SetHopLimit(ttl); err != nil {
		log.Fatal(err)
	}

	if _, err := r.v6PktConn.WriteTo(wb, nil, r.destIPAddr); err != nil {
		log.Fatal(err)
	}
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
	filterstr := "icmp"
	if !r.useV4 {
		filterstr += "6"
	}
	if err = r.pcapHandle.SetBPFFilter(filterstr); err != nil {
		log.Fatal(err)
	}
}

func v4SenderSetup() (net.PacketConn, *ipv4.PacketConn) {
	listener, err := net.ListenPacket("ip4:1", net.IPv4zero.String())
	if err != nil {
		log.Fatal(err)
	}
	netlayer := ipv4.NewPacketConn(listener)
	return listener, netlayer
}

func v6SenderSetup() (net.PacketConn, *ipv6.PacketConn) {
	listener, err := net.ListenPacket("ip6:58", net.IPv6zero.String())
	if err != nil {
		log.Fatal(err)
	}
	netlayer := ipv6.NewPacketConn(listener)
	return listener, netlayer
}
