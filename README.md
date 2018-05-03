SoMeta
======

Automatic collection of network measurement metadata.

This is a complete rewrite of SoMeta in go.  




Changes
-------

Changes from the earlier Python version of SoMeta:

 * Because of Go's command-argument handling, flags to someta cannot be written like `-Mcpu`, but must rather be written as `-M=cpu` or `-M cpu`.
 * CPU affinity is not yet implemented
 * Metadata structure is changed to permit a less tightly-coupled architecture between the someta main and monitors
   * The plotting tool hasn't been updated yet to handle these changes, though
     the basic analysis tool has been updated.
 * There's even more rich data collected about the system when someta starts up

Examples
--------


Here's an example with turning on all monitors (io, netstat, cpu, mem, rtt):

    sudo ./someta -M=io,disk0 -M=netstat,en0 -M=cpu -M=me -M=rtt,type=hoplimited,dest=149.43.80.25,maxttl=3,interface=en0 -R 1m -F 20s -f fulltest -l -m 1s -w 2s -v -c "sleep 150"

Type `./someta -h` for a list of command line options and their defaults.

License
-------

Copyright 2018  SoMeta authors.  All rights reserved.

The SoMeta software is distributed under terms of the GNU General Public License, version 3.  See below for the standard GNU GPL v3 copying text.

::

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
