#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:		savedump.py
#
# Author:	  Massimo Ciani
#
# Created:	 01/09/2009
# Copyright:   (c) Massimo Ciani 2009
#
#-------------------------------------------------------------------------------



from ctypes import *
from winpcapy import *
import string
import time
import platform

if platform.python_version()[0] == "3":
	raw_input=input
## prototype of the packet handler
## void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data)

PHAND=CFUNCTYPE(None,POINTER(c_ubyte),POINTER(pcap_pkthdr),POINTER(c_ubyte))
## Callback function invoked by libpcap for every incoming packet

def _packet_handler(param,header,pkt_data):
	## save the packet on the dump file
	global dumpfile
	pcap_dump(dumpfile, header, pkt_data)

packet_handler=PHAND(_packet_handler)

alldevs=POINTER(pcap_if_t)()
d=POINTER(pcap_if_t)
adhandle=pcap_t
errbuf= create_string_buffer(PCAP_ERRBUF_SIZE)
#dumpfile=pcap_dumper_t
## Check command line
if (len(sys.argv) != 2):
	print ("usage: %s filename" % sys.argv[0])
	sys.exit(-1)
## Retrieve the device list on the local machine
if (pcap_findalldevs(byref(alldevs),errbuf) == -1):
	print ("Error in pcap_findalldevs: %s\n", errbuf.value)
	sys.exit(1)

## Print the list
i=0
d=alldevs.contents
while d:
	i=i+1
	print ("%d. %s" % (i, d.name))
	if (d.description):
		print (" (%s)\n" % (d.description))
	else:
	    print (" (No description available)\n")
	if d.next:
	    d=d.next.contents
	else:
	    d=False
if (i==0):
	print ("\nNo interfaces found! Make sure WinPcap is installed.\n")
	sys.exit(-1)

print ("Enter the interface number (1-%d):" % (i))
inum= raw_input('--> ')
if inum in string.digits:
	inum=int(inum)
else:
	inum=0
if ((inum < 1) | (inum > i)):
	print ("\nInterface number out of range.\n")
	## Free the device list
	pcap_freealldevs(alldevs)
	sys.exit(-1)

## Jump to the selected adapter
d=alldevs
for i in range(0,inum-1):
	d=d.contents.next


## Open the adapter
adhandle = pcap_open_live(d.contents.name,65536,1,1000,errbuf)
if (adhandle == None):
	print ("\nUnable to open the adapter. %s is not supported by WinPcap\n" % d.contents.name)
	## Free the device list
	pcap_freealldevs(alldevs)
	sys.exit(-1)

## Open the dump file
dumpfile = pcap_dump_open(adhandle, sys.argv[1])
if(dumpfile==None):
	print ("\nError opening output file\n")
	sys.exit(-1)

print ("\nlistening on %s... Press Ctrl+C to stop...\n" % d.contents.description)
## At this point, we no longer need the device list. Free it */
pcap_freealldevs(alldevs)
## start the capture */
support=cast(dumpfile,POINTER(c_ubyte))
pcap_loop(adhandle, 5, packet_handler, support)
pcap_close(adhandle);
sys.exit(0)


