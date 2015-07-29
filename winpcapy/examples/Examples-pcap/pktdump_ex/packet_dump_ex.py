#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:        packet_dump_ex.py
#
# Author:      Massimo Ciani
#
# Created:     01/09/2009
# Copyright:   (c) Massimo Ciani 2009
#
#-------------------------------------------------------------------------------


from ctypes import *
from winpcapy import *
import sys
import string
import platform

if platform.python_version()[0] == "3":
	raw_input=input
LINE_LEN=16
alldevs=POINTER(pcap_if_t)()
d=POINTER(pcap_if_t)
fp=pcap_t
errbuf= create_string_buffer(PCAP_ERRBUF_SIZE)
header=POINTER(pcap_pkthdr)()
pkt_data=POINTER(c_ubyte)()


print ("pktdump_ex: prints the packets of the network using WinPcap.\n")
print ("   Usage: pktdump_ex [-s source]\n\n")
print ("   Examples:\n")
print ("      pktdump_ex -s file.acp\n")
print ("      pktdump_ex -s \\Device\\NPF_{C8736017-F3C3-4373-94AC-9A34B7DAD998}\n\n")
if len(sys.argv) < 3:
    print ("\nNo adapter selected: printing the device list:\n")
    ## The user didn't provide a packet source: Retrieve the local device list
    if (pcap_findalldevs(byref(alldevs), errbuf) == -1):
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

    d=alldevs
    for i in range(0,inum-1):
        d=d.contents.next
    fp = pcap_open_live(d.contents.name,65536,1,1000,errbuf)
    if (fp == None):
        print ("\nError opening adapter\n")
        ## Free the device list
        pcap_freealldevs(alldevs)
        sys.exit(-1)
else:
    ## Do not check for the switch type ('-s')
    fp = pcap_open_live(sys.argv[2],65536,1,1000,errbuf)
    if (fp == None):
        print ("\nError opening adapter\n")
        ## Free the device list
        pcap_freealldevs(alldevs)
        sys.exit(-1)

## Read the packets
res = pcap_next_ex( fp, byref(header), byref(pkt_data))
while(res >= 0):
    if(res == 0):
        ## Timeout elapsed
        break
    ## print pkt timestamp and pkt len
    print ("%ld:%ld (%ld)\n" % (header.contents.ts.tv_sec,header.contents.ts.tv_usec, header.contents.len))
    ##  Print the packet
    for i in range(1,header.contents.len + 1):
        print ("%.2x " % pkt_data[i-1])
        if (i % LINE_LEN) == 0:
            print ("\n")
    print ("\n\n")
    res = pcap_next_ex( fp, byref(header), byref(pkt_data))

if(res == -1):
    print ("Error reading the packets: %s\n" % pcap_geterr(fp))
    sys.exit(-1)

pcap_close(fp)
sys.exit(0)

