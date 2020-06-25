SoMeta
======

Automatic collection of network measurement metadata.

This is a complete rewrite of SoMeta in go.  The earlier (Python) version of `SoMeta` can be found at https://github.com/jsommers/metameasurement.

Current version is 1.2.0.  

Building
--------

The source tree needs to be downloaded to GOPATH/src/github.com/jsommers.

You can do this with: `go get github.com/jsommers/someta`.  The development library and headers for `libpcap` will need to be installed for this to successfully complete.  On Debian-variant Linux systems, you can just do `apt install libpcap-dev`.

You can then `cd` to `$GOPATH/src/github.com/jsommers/someta` and type `go build`.  A binary named `someta` will be produced.


Running
-------

There are several possible command-line options.  See below for a listing of all parameters (i.e., the output of `someta -a`.  Some additional detail is below, specifically regarding monitors and options.


Usage of ./someta:

      -C int
        	Set CPU affinity (default is not to set affinity) (default -1)
      -F duration
         	Time period after which in-memory metadata will be flushed to file (default 10m0s)
      -M value
        	Select monitors to include. Default=None. Valid monitors=cpu,io,mem,netstat,rtt
      -R duration
        	Time period after which metadata output will rollover to a new file (default 1h0m0s)
      -c string
        	Command line for external measurement program
      -d	Debug output (metadata is written to stdout)
      -f string
        	Output file basename; current date/time is included as part of the filename (default "metadata")
      -l	Send logging messages to a file (by default, they go to stdout)
      -m duration
        	Time interval on which to gather metadata from monitors (default 1s)
      -q	Quiet output
      -u duration
        	Time interval on which to show periodic status while running (default 5s)
      -v	Verbose output
      -w duration
        	Wait time before starting external tool, and wait time after external tool stops, during which metadata are collected (default 1s)


The ``-c`` option indicates the "external" measurement tool to start.  By default, 
SoMeta starts ``sleep 5``, which causes SoMeta simply to collect 5 seconds-worth of
metadata, given what ever monitors have been configured.  You'll almost certainly
need to quote the command line for the external tool, and some escaping may be required
if there are embedded quotes needed for the tool (see the example with scamper, below).

The ``-M`` option specifies a monitor to start.  Standard available sources include cpu, mem, io, netstat, rtt (see the ``monitors/`` directory).

To configure a monitor, parameters may be specified along with each monitor name, each separated by a colon (`:`) or a comma (`,`).  Each parameter may be a single string, or a ``key=value`` pair.  The order of parameters doesn't matter.

Note that if you are using the rtt monitor with IPv6, you'll need to use comma separators because the colon key-value separator can't be distinguished from the colon separator within an IPv6 address.

Here's an example with turning on all monitors (io, netstat, cpu, mem, rtt):

    sudo ./someta -M=io,disk0 -M=netstat,en0 -M=cpu -M=me -M=rtt,type=hoplimited,dest=149.43.80.25,maxttl=3,interface=en0 -R 1m -F 20s -f fulltest -m 1s -w 2s -v -c "sleep 150"

Again, type `./someta -h` for a list of command line options and their defaults.

Valid parameters for each standard monitor are:

   * ``-M=cpu:interval=X``: set the periodic sampling interval (default 1 sec)
   * ``-M=io:interval=X``: set the periodic sampling interval (default 1 sec)
   * ``-M=mem:interval=X``: set the periodic sampling interval (default 1 sec)
   * ``-M=netstat:interval=X``: set the periodic sampling interval.

     Note that the interval time value is parsed by go's `time.parseDuration`
     (https://golang.org/pkg/time/#ParseDuration), so any value must also
     include a unit, like `interval=1s` (1 second interval).

     Additional string arguments to the netstat monitor
     can specify interface names to monitor (all
     interfaces are included if none are specified).
     For example, to monitor en0's netstat counters
     every 5 seconds:
     
     * ``-M=netstat:interval=5s:en0``

   * ``-M=rtt:interface=IfaceName:rate=R:dest=D:type=ProbeType:maxttl=MaxTTL:proto=Protocol:allhops:constflow``
     
     Monitor RTT along a path to destination ``D`` out of interface ``IfaceName``
     with probe rate ``R``.  Probe interval is gamma distributed.  The default
     destination is 8.8.8.8 and default probe rate is 1/sec.

     ``ProbeType`` can either be ``ping`` or ``hoplimited`` (default is hoplimited)

     ``MaxTTL`` is maximum ttl for hop-limited probes (pointless for ping probes).  
     Default is maxttl = 1.

     ``Protocol`` is (icmp | tcp | udp) (for hop-limited probes).  Default is icmp.

     ``allhops``: probe all hops up to maxttl (for hop-limited probes)

     ``constflow``: manipulate packet contents to force first 4 bytes of transport header to be constant (to make probes follow a constant path).  This parameter only has an affect on icmp; data are appended to force the checksum to be a constant value.  Note: udp/tcp probes always have const first 4 bytes.

   * ``-M=ss``

     Monitor socket statistics using the `ss` tool (linux only).  Thanks to Ricky Mok (CAIDA) for contributing this module.  


Here are some examples:

    # Monitor only CPU performance while emitting 100 ICMP echo request (ping) probes to
    # www.google.com.
    $ sudo ./someta -M=cpu -c "ping -c 100 www.google.com" 

    # Monitor CPU performance and netstat counters (for all interfaces) for traceroute
    $ sudo ./someta -M=cpu -M=netstat -c "traceroute www.google.com" 

    # Monitor CPU, IO and Netstat counters for ping
    # Set the metadata output file to start with "ping_google"
    $ sudo ./someta -M=io -M=netstat -c "ping www.google.com" -f ping_google

    # Monitor everything, including RTT for the first 3 hops of the network path toward
    # 8.8.8.8.  As the external tool, use scamper to emit ICMP echo requests, dumping
    # its output to a warts file.
    $ sudo ./someta -M=cpu -M=mem -M=io -M=netstat:eth0 -M=rtt:interface=eth0:type=hoplimited:maxttl=3:dest=8.8.8.8 -f ping_metadata -l -c "scamper -c \"ping -P icmp-echo -c 60 -s 64\" -o ping.warts -O warts -i 8.8.8.8"

    # An example with using the RTT monitor w/IPv6 (with the dummy command `sleep`).
    # Note that in my example below I used an IPv6 (6-in-4) tunnel interface.
    $ sudo ./someta -c "sleep 5" -M=rtt,dest="2607:f8b0:4006:805::200e",type=hoplimited,interface=he-ipv6,maxttl=6  -v


Analyzing metadata
------------------

The ``analyzemeta.py`` script performs some simple analysis on SoMeta metadata, printing results to the console.  


Reading into a Pandas DataFrame 
-------------------------------

For more complex data analyses (or, if you prefer, metadata analyses), there is a Python module `read_someta.py` that provides a function `read_someta` for reading data in a SoMeta `.json` file into a dictionary of Pandas DataFrame objects.  There will be a different DataFrame object associated with each monitor.

For example:

```
>>> from read_someta import read_someta
>>> d = read_someta('fulltest_2018-05-03T18:07:11-04:00.json')
>>> d.keys()
dict_keys(['someta', 'cpu', 'mem', 'rtt', 'io', 'netstat'])
>>> d['cpu']
                                     cpu0_idle  cpu1_idle  cpu2_idle  cpu3_idle
timestamp
2018-05-03 18:07:12.978601317-04:00  62.037037  87.735849  68.224299  89.719626
2018-05-03 18:07:13.979181597-04:00  70.000000  93.069307  71.000000  96.000000
2018-05-03 18:07:14.980990941-04:00  82.828283  97.979798  86.000000  98.000000
2018-05-03 18:07:15.980368940-04:00  74.000000  96.039604  79.000000  96.000000
2018-05-03 18:07:16.981288271-04:00  69.306931  89.000000  75.000000  91.089109
...                                        ...        ...        ...        ...
2018-05-03 18:08:08.981608769-04:00  80.808081  94.000000  83.838384  90.000000
2018-05-03 18:08:09.983457489-04:00  83.000000  94.000000  86.274510  89.000000
2018-05-03 18:08:10.981178466-04:00  87.000000  97.000000  93.000000  98.000000
2018-05-03 18:08:11.983964314-04:00  70.297030  92.079208  72.000000  91.000000
2018-05-03 18:08:12.981282530-04:00  90.909091  98.000000  95.959596  99.000000

[61 rows x 4 columns]
>>>
```


Plotting metadata
-----------------

NB: plotting tools need some updating still from the earlier Python versions.  

The ``plotmeta.py`` tool is designed to help plot various metrics collected through SoMeta *monitors*.  To see what metrics may be plotted, you can run the following::

    $ python3 plotmeta.py -l meta.json

where ``meta.json`` is a SoMeta metadata file.  The output of ``plotmeta.py`` with the ``-l`` option shows various *items* that can be plotted.  Each item is organized into *groups*.  You can either plot any number of individual items (``-i`` option), or plot each metric for an entire group (``-g`` option).  If you want everything, use the ``-a`` option.  In addition, ``-t`` option can be used to change the type of output plot. Use *ecdf* for empirical CDF or *timeseries* for simple scatter plot with timeline (which is default output of the plot tool). See ``plotmeta.py -h`` for all options.

Here are some examples::

    $ python3 plotmeta.py -t ecdf -i cpu:idle -i io:disk0_write_time meta.json
    $ python3 plotmeta.py -t timeseries -g cpu meta.json
    $ python3 plotmeta.py -a meta.json



Changes
-------

Changes from the earlier Python version of SoMeta:

 * Because of Go's command-argument handling, flags to someta cannot be written like `-Mcpu`, but must rather be written as `-M=cpu` or `-M cpu`.
 * CPU affinity is not yet implemented
 * Metadata structure is changed to permit a less tightly-coupled architecture between the someta main and monitors
   * The plotting tool hasn't been updated yet to handle these changes, though
     the basic analysis tool has been updated.
 * There's even more rich data collected about the system when someta starts up


Credits
-------

I gratefully acknowledge support from the National Science Foundation.  The materials here are based upon work supported by the NSF under grant 1814537 ("NeTS: Small: RUI: Automating Active Measurement Metadata Collection and Analysis").

Any opinions, findings, and conclusions or recommendations expressed in this material are those of the author and do not necessarily reflect the views of the National Science Foundation.


License
-------

Copyright 2018-19  SoMeta authors.  All rights reserved.

The SoMeta software is distributed under terms of the GNU General Public License, version 3.  See below for the standard GNU GPL v3 copying text.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
