SoMeta
======

Automatic collection of network measurement metadata.

This is a complete rewrite of SoMeta in go.  


Installation
------------

**FIXME**

go install -i github.com/jsommers/someta

(name the dependencies: gopacket, psutil, x/net x/unix)

this should install a binary `someta` in $GOPATH/bin

Running
-------

**FIXME**: describe the command-line options; discuss differences with Python version

Note: below needs updating for Go rewrite; this is a copy of material from the older Python version of the code.


``metameasurement.py`` Python program.  There are several
possible command-line options.  See ``metameasurement.py -h`` for a list.  Some
additional detail is below, specifically regarding monitors and options.

The ``-c`` option indicates the "external" measurement tool to start.  By default, 
SoMeta starts ``sleep 5``, which causes SoMeta simply to collect 5 seconds-worth of
metadata, given what ever monitors have been configured.  You'll almost certainly
need to quote the command line for the external tool, and some escaping may be required
if there are embedded quotes needed for the tool (see the example with scamper, below).

The ``-M`` option specifies a monitor to start.  Standard available sources include cpu, mem, io, netstat, rtt (see the ``monitors/`` directory).

To configure a monitor, parameters may be specified along with each monitor name, each separated by a colon (':').  Each parameter may be a single string, or a ``key=value`` pair.  The order of parameters doesn't matter.



Here's an example with turning on all monitors (io, netstat, cpu, mem, rtt):

    sudo ./someta -M=io,disk0 -M=netstat,en0 -M=cpu -M=me -M=rtt,type=hoplimited,dest=149.43.80.25,maxttl=3,interface=en0 -R 1m -F 20s -f fulltest -l -m 1s -w 2s -v -c "sleep 150"

Type `./someta -h` for a list of command line options and their defaults.


Valid parameters for each standard monitor are:

   * ``-M cpu:interval=X``: set the periodic sampling interval (default 1 sec)
   * ``-M io:interval=X``: set the periodic sampling interval (default 1 sec)
   * ``-M mem:interval=X``: set the periodic sampling interval (default 1 sec)
   * ``-M netstat:interval=X``: set the periodic sampling interval.

     Additional string arguments to the netstat monitor
     can specify interface names to monitor (all
     interfaces are included if none are specified).
     For example, to monitor en0's netstat counters
     every 5 seconds:
     
     * ``-M netstat:interval=5:en0``

   * ``-M rtt:interface=IfaceName:rate=R:dest=D:type=ProbeType:maxttl=MaxTTL:proto=Protocol:allhops:constflow``
     
     Monitor RTT along a path to destination ``D`` out of interface ``IfaceName``
     with probe rate ``R``.  Probe interval is gamma distributed.  The default
     destination is 8.8.8.8 and default probe rate is 1/sec.

     ``ProbeType`` can either be ``ping`` or ``hoplimited`` (default is hoplimited)

     ``MaxTTL`` is maximum ttl for hop-limited probes (pointless for ping probes).  
     Default is maxttl = 1.

     ``Protocol`` is (icmp | tcp | udp) (for hop-limited probes).  Default is icmp.

     ``allhops``: probe all hops up to maxttl (for hop-limited probes)

     ``constflow``: manipulate packet contents to force first 4 bytes of transport header to be constant (to make probes follow a constant path).  This parameter only has an affect on icmp; data are appended to force the checksum to be a constant value.  Note: udp/tcp probes always have const first 4 bytes.


Here are some examples::

    # Monitor only CPU performance while emitting 100 ICMP echo request (ping) probes to
    # www.google.com.
    $ python3 metameasurement.py -Mcpu -c "ping -c 100 www.google.com" 

    # Monitor CPU performance and netstat counters (for all interfaces) for traceroute
    $ python3 metameasurement.py -Mcpu -Mnetstat -c "traceroute www.google.com" 

    # Monitor CPU, IO and Netstat counters for ping
    # Set the metadata output file to start with "ping_google"
    $ python3 metameasurement.py -Mio -Mnetstat -c "ping www.google.com" -f ping_google

    # Monitor everything, including RTT for the first 3 hops of the network path toward
    # 8.8.8.8.  As the external tool, use scamper to emit ICMP echo requests, dumping
    # its output to a warts file.
    $ python3 metameasurement.py -Mcpu -Mmem -Mio -Mnetstat:eth0 -Mrtt:interface=eth0:type=hoplimited:maxttl=3:dest=8.8.8.8 -f ping_metadata -l -c "scamper -c \"ping -P icmp-echo -c 60 -s 64\" -o ping.warts -O warts -i 8.8.8.8"


Analyzing metadata
------------------

The ``analyzemeta.py`` script performs some simple analysis on SoMeta metadata, printing results to the console.  

Plotting metadata
-----------------

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
