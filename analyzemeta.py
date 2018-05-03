import sys
import time
import re
import json
import argparse
from statistics import mean, stdev, median
from math import isinf
from collections import defaultdict

def printstats(name, xlist):
    print("{}".format(name))
    if len(xlist) >= 1:
        print("\t\tmean: {}".format(mean(xlist)))
    if len(xlist) >= 2:
        print("\t\tstdev: {}".format(stdev(xlist)))
    if len(xlist) >= 1:
        print("\t\tmedian: {}".format(median(xlist)))

def parse_ts(ts):
    idx = ts.find('.')
    st = time.strptime(ts[:idx], "%Y-%m-%dT%H:%M:%S")
    unix = time.mktime(st)
    mobj = re.match("^\.(\d+)([-+])(\d{2}):(\d{2})$", ts[idx:])
    matchvals = mobj.groups()
    subsec = float(f".{matchvals[0]}")
    hroff = int(matchvals[2])
    minoff = int(matchvals[3])
    secoff = hroff * 3600 + minoff * 60
    offset = int(f"{matchvals[1]}{secoff}")
    unix += subsec
    unix += offset
    return unix

def zerotime(ts):
    return ts == "0001-01-01T00:00:00Z"

def analyze_probes(name, plist):
    print("\tResults for {}".format(name))
    parse_ts(plist[0]['wiresend'])

    lost = [ parse_ts(xd['sendtime']) for xd in plist \
        if zerotime(xd['wiresend']) or zerotime(xd['wirerecv']) ]
    rtt = [ parse_ts(xd['wirerecv']) - parse_ts(xd['wiresend']) for xd in plist \
        if not zerotime(xd['wirerecv']) and not zerotime(xd['wiresend']) ]
    sendtimes = [ parse_ts(xd['sendtime']) for xd in plist ]
    senddiffs = [ sendtimes[i] - sendtimes[i-1] for i in range(1,len(sendtimes)) ]
    print("\tLost: {}".format(len(lost)))
    printstats('\trtt', rtt)
    printstats('\tsenddiffs', senddiffs)

def analyze_rtt(name, data, xd):
    print(name)
    print("\t{protocol} {probetype} probes to {dest} (maxttl: {maxttl}, allhops: {probe_all_hops})".format(**xd))
    print("\ttotal probes sent: {total_probes_emitted}, total probes received: {total_probes_received}".format(**xd))
    if xd['libpcap_stats'] is not None:
        print("\tlibpcap info: recv: {PacketsReceived}  pcapdrop: {PacketsDropped}  " \
            "ifdrop: {PacketsIfDropped}".format(**xd['libpcap_stats']))

    if xd['probetype'] == 'hoplimited':
        collated = defaultdict(list)
        for probe in data:
            key = "hop_{}".format(probe['outttl'])
            collated[key].append(probe)
    else:
        collated = {'ping': data }

    for name, plist in collated.items():
        analyze_probes(name, plist)

def analyze_io(name, xli, xd):
    # TBD
    for xd in xli:
        ts = xd['timestamp']
        ct = xd['counters']

def analyze_cpu(name, xli, xd):
    if len(xli) == 0:
        return
    data = defaultdict(list)
    for xd in xli:
        # ts = xd['timestamp']
        idle = xd['cpuidle']
        for k, v in idle.items():
            data[k].append(v)

    print(name)
    print("\tMean/stdev CPU idle:")
    for k in sorted(data.keys()):
        m = mean(data[k])
        s = stdev(data[k])
        print("\t{}: {:.3f} ({:.3f})".format(k, m, s))
        lowcpu = len([x for x in data[k] if x < 1])
        if lowcpu > 0:
            print("\t\t{} measurements had low (<1%) idle CPU".format(lowcpu))

def analyze_mem(name, xli, xd):
    if len(xli) == 0:
        return
    available = [ 100.0 - xd['percent_used'] for xd in xli ]
    print(name)
    print("\tMemory available (percent) max: {:.0f} min: {:.0f}".format(
        max(available), min(available)))

def analyze_netstat(name, xli, xd):
    if len(xli) == 0:
        return
    keys_of_interest = []
    counters = defaultdict(list)

    xd = xli[0]
    oneif = list(xd['netstat'].keys())[0]
    for key in xd['netstat'][oneif]:
        if 'drop' in key:
            keys_of_interest.append(key)
        elif 'err' in key:
            keys_of_interest.append(key)
    for xd in xli:
        data = xd['netstat']
        for netif, ifdata in data.items():
            for k in keys_of_interest:
                counters["{}_{}".format(netif, k)].append(ifdata[k])

    print(name)
    flag = False
    for k in sorted(keys_of_interest):
        s = sum(counters[k])
        if s > 0:
            print("\t{}: count is non-zero ({})".format(k, s))
            flag = True
    if not flag:
        print("\tNo drops or errors in netstat counters")

def print_sys(xd):
    print("Metadata for {command} (someta version {version})".format(**xd))
    print(f"\tRun on {xd['sysinfo']['hostname']} at {xd['start']}")
    print(f"\tCPUs: {len(xd['syscpu'])}")
    print(f"\tTotal Memory: {xd['sysmem']['total']/1024/1024}MiB")

def main():
    parser = argparse.ArgumentParser(
            description='Analyze RTTs...')
    parser.add_argument('jsonmeta', nargs=1)
    args = parser.parse_args()

    monitor_analy = {'cpu': analyze_cpu,
            'mem': analyze_mem,
            'io': analyze_io,
            'netstat': analyze_netstat,
            'rtt': analyze_rtt}

    infile = args.jsonmeta[0]
    meta = {}
    meta['monitors'] = {}
    with open(infile) as infileh:
        for line in infileh:
            m = json.loads(line)
            if m['type'] == 'monitor':
                name = m['name']
                key = 'data'
                if m['name'].startswith('rtt'):
                    name = 'rtt'
                    key = 'probes'
                monitor_analy[name](m['name'], m[key], m)
            elif m['type'] == 'system':
                print_sys(m['sysinfo'])

if __name__ == '__main__':
    main()
