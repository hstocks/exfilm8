#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:        basic_dump_ex.py
#
# Author:      Massimo Ciani
#
# Created:     01/09/2009
# Copyright:   (c) Massimo Ciani 2009
#
#-------------------------------------------------------------------------------



from ctypes import *
from winpcapy import *
import time
import sys
import string
import platform

if platform.python_version()[0] == "3":
	raw_input=input
header = POINTER(pcap_pkthdr)()
pkt_data = POINTER(c_ubyte)()
alldevs=POINTER(pcap_if_t)()
errbuf= create_string_buffer(PCAP_ERRBUF_SIZE)
## Retrieve the device list
if (pcap_findalldevs(byref(alldevs), errbuf) == -1):
	print ("Error in pcap_findalldevs: %s\n" % errbuf.value)
	sys.exit(1)
## Print the list
i=0
try:
	d=alldevs.contents
except:
	print ("Error in pcap_findalldevs: %s" % errbuf.value)
	print ("Maybe you need admin privilege?\n")
	sys.exit(1)
while d:
	i=i+1
	print("%d. %s" % (i, d.name))
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
## Open the device
## Open the adapter
d=d.contents
adhandle = pcap_open_live(d.name,65536,1,1000,errbuf)
if (adhandle == None):
    print("\nUnable to open the adapter. %s is not supported by Pcap-WinPcap\n" % d.contents.name)
    ## Free the device list
    pcap_freealldevs(alldevs)
    sys.exit(-1)
print("\nlistening on %s...\n" % (d.description))
## At this point, we don't need any more the device list. Free it
pcap_freealldevs(alldevs)
## Retrieve the packets
res=pcap_next_ex( adhandle, byref(header), byref(pkt_data))
while(res >= 0):
	if(res == 0):
		# Timeout elapsed
		break
	# convert the timestamp to readable format
	## convert the timestamp to readable format
	local_tv_sec = header.contents.ts.tv_sec
	ltime=time.localtime(local_tv_sec);
	timestr=time.strftime("%H:%M:%S", ltime)
	print
	print("%s,%.6d len:%d" % (timestr, header.contents.ts.tv_usec, header.contents.len))
	res=pcap_next_ex( adhandle, byref(header), byref(pkt_data))
	#print
	#print(pkt_data[0:header.contents.len])
if(res == -1):
	print("Error reading the packets: %s\n", pcap_geterr(adhandle));
	sys.exit(-1)
pcap_close(adhandle)
