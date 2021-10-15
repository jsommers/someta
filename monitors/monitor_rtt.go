package someta

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	pkt "github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
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
	Probes        []probe    `json:"probes"`
	PcapStats     pcap.Stats `json:"libpcap_stats"`
	Protocol      string     `json:"protocol"`
	Probetype     string     `json:"probetype"`
	TotalEmitted  int64      `json:"total_probes_emitted"`
	TotalReceived int64      `json:"total_probes_received"`
	ProbeAllHops  bool       `json:"probe_all_hops"`
	MaxTTL        int        `json:"maxttl"`
	IPDest        string     `json:"dest"`
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

	pcapHandle *pcap.Handle
	v4Listener net.PacketConn
	v4PktConn  *ipv4.PacketConn
	v6Listener net.PacketConn
	v6PktConn  *ipv6.PacketConn
}

var nameRegex *regexp.Regexp

// DefaultConfig returns a default config or nil if no default
func (r *RTTMonitor) DefaultConfig() *MonitorConf {
	var ifnames []string
	ifstatslice, _ := net.Interfaces()
	for _, ifstat := range ifstatslice {
		ifnames = append(ifnames, ifstat.Name)
	}
	conf := &MonitorConf{Kind: "rtt",
		Interval: 1 * time.Second,
		Device:   ifnames,
		RttType:  "ping/hoplimited",
		Dest:     "0.0.0.0",
		MaxTTL:   64,
		AllHops:  true,
	}
	return conf
}

// CheckConfig does some basic sanity checking on the configuration
func (r *RTTMonitor) CheckConfig(name string, conf MonitorConf) {
	var err error
	_, err = net.ResolveIPAddr("ip", conf.Dest)
	if err != nil {
		log.Fatalf("%s monitor: couldn't parse destination IP address %s: %v\n", name, conf.Dest, err)
	}

	if len(conf.Device) != 1 {
		log.Fatalf("%s monitor: must have exactly 1 device configured but got %d (%s)", name, len(conf.Device), strings.Join(conf.Device, ", "))
	}

	if !intfNames.isValid(conf.Device[0]) {
		log.Fatalf(`%s monitor: invalid "interface" name %s; valid names: %s`, name, conf.Device[0], strings.Join(intfNames.all(), ","))
	}

	if !(conf.RttType == "hoplimited" || conf.RttType == "ping") {
		log.Fatalf("%s monitor unrecognized probe type %s\n", name, conf.RttType)
	}

	if conf.RttType == "hoplimited" {
		if conf.MaxTTL == 0 {
			conf.MaxTTL = 64 // default
		} else if conf.MaxTTL <= 0 {
			log.Fatalf("%s monitor: invalid value %d for hopcount\n", name, conf.MaxTTL)
		} else if conf.MaxTTL > 32 {
			log.Fatalf("%s monitor: maxTTL too big for hop-limited probe", name)
		}
	}

	if conf.Interval < time.Millisecond*1 {
		log.Fatalf("%s: interval %v too short", name, conf.Interval)
	}
}

// Init initializes an RTT monitor
func (r *RTTMonitor) Init(name string, verbose bool, defaultInterval time.Duration, conf MonitorConf) error {
	r.CheckConfig(name, conf)
	r.baseInit(name, verbose, defaultInterval)

	r.IPDest = conf.Dest
	r.destIPAddr, _ = net.ResolveIPAddr("ip", conf.Dest) // already validated in CheckConfig
	if ip4 := r.destIPAddr.IP.To4(); ip4 != nil {
		r.useV4 = true
	} else {
		r.useV4 = false
	}

	r.netDev = intfNames.pcapName(conf.Device[0])
	r.MaxTTL = conf.MaxTTL
	r.ProbeAllHops = conf.AllHops
	r.interval = conf.Interval
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
	if conf.RttType == "hoplimited" && r.ProbeAllHops {
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
	r.Protocol = "icmp"
	r.Probetype = conf.RttType

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
		r.PcapStats = *stats
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
		r.PcapStats = *stats
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
			r.handleV4(ts, iphdr, icmphdr, packet)
			continue
		}

		ip6 := packet.Layer(layers.LayerTypeIPv6)
		icmp6 := packet.Layer(layers.LayerTypeICMPv6)
		if ip6 != nil && icmp6 != nil {
			iphdr, _ := ip6.(*layers.IPv6)
			icmphdr, _ := icmp6.(*layers.ICMPv6)
			r.handleV6(ts, iphdr, icmphdr, packet)
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

func (r *RTTMonitor) handleV4(ts time.Time, ip *layers.IPv4, icmp *layers.ICMPv4, packet pkt.Packet) {
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

func (r *RTTMonitor) handleV6(ts time.Time, ip *layers.IPv6, icmp *layers.ICMPv6, packet pkt.Packet) {
	if !(r.isMyIPAddr(ip.SrcIP) || r.isMyIPAddr(ip.DstIP)) {
		return
	}
	var icmpid int
	var icmpseq int

	v6echo := packet.Layer(layers.LayerTypeICMPv6Echo)
	echo, _ := v6echo.(*layers.ICMPv6Echo)
	if echo != nil {
		icmpid = int(echo.Identifier)
		icmpseq = int(echo.SeqNumber)
	}

	icmptype := icmp.TypeCode.Type()
	icmpcode := icmp.TypeCode.Code()
	if icmptype == layers.ICMPv6TypeEchoRequest {
		if r.isMyICMPId(icmpid) {
			r.updateOutgoingProbe(icmpid, icmpseq, ts, ip.SrcIP)
		}
	} else if icmptype == layers.ICMPv6TypeEchoReply {
		if r.isMyICMPId(icmpid) {
			r.updateIncomingProbe(icmpid, icmpseq, ts, int(ip.HopLimit), ip.SrcIP)
		}
	} else if icmptype == layers.ICMPv6TypeTimeExceeded && icmpcode == layers.ICMPv6CodeHopLimitExceeded {
		var nestedv6 layers.IPv6
		var nestedicmpv6 layers.ICMPv6
		var nestedecho layers.ICMPv6Echo
		parser := pkt.NewDecodingLayerParser(layers.LayerTypeIPv6, &nestedv6, &nestedicmpv6, &nestedecho)
		decoded := make([]pkt.LayerType, 3, 3)
		payload := icmp.LayerPayload()
		if err := parser.DecodeLayers(payload[4:], &decoded); err == nil {
			if nestedv6.NextHeader == layers.IPProtocolICMPv6 && nestedicmpv6.TypeCode.Type() == layers.ICMPv6TypeEchoRequest {
				nestedID := int(nestedecho.Identifier)
				if r.isMyICMPId(nestedID) {
					nestedSeq := int(nestedecho.SeqNumber)
					r.updateIncomingProbe(nestedID, nestedSeq, ts, int(ip.HopLimit), ip.SrcIP)
				}
			}
		}
	}
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

func (r *RTTMonitor) probeSweeper(ctx context.Context) {
	// every 2 seconds, sweep through and remove "old" probes
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			r.sweepProbes(false)
		case <-ctx.Done():
			return
		}
	}
}

// Run runs the RTT monitor; this should be invoked in a goroutine
func (r *RTTMonitor) Run(ctx context.Context) error {
	go r.pcapReader()
	go r.probeSweeper(ctx)
	defer r.shutdown()

	// timer := time.NewTimer(gammaInterval(r.interval))
	timer := time.NewTicker(r.interval)
	now := time.Now()
	for {
		select {
		case t := <-timer.C:
			if r.verbose {
				log.Printf("Sending probe %d (gap %v)\n", r.nextSequence, t.Sub(now))
			}
			now = time.Now()
			r.sendProbe()
			// timer.Reset(gammaInterval(r.interval))

		case <-ctx.Done():
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
