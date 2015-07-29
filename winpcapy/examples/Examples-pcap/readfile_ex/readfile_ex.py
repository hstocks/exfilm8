#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:        readfile_ex.py
#
# Author:      Massimo Ciani
#
# Created:     01/09/2009
# Copyright:   (c) Massimo Ciani 2009
#
#-------------------------------------------------------------------------------


from ctypes import *
from winpcapy import *
import string
import sys

LINE_LEN=16

fp=pcap_t
errbuf= create_string_buffer(PCAP_ERRBUF_SIZE)
header=POINTER(pcap_pkthdr)()
pkt_data=POINTER(c_ubyte)()
if(len(sys.argv) != 2):
    print ("usage: %s filename" % sys.argv[0])
    sys.exit(-1)

## Open the capture file
fp = pcap_open_offline(sys.argv[1],errbuf)
if not bool(fp):
    print ("\nUnable to open the file %s.\n" % sys.argv[1])
    sys.exit(-1)
## Retrieve the packets from the file
res = pcap_next_ex(fp, byref(header), byref(pkt_data))
while(res >= 0):
    ## print pkt timestamp and pkt len
    print ("%ld:%ld (%ld)\n" % (header.contents.ts.tv_sec,header.contents.ts.tv_usec, header.contents.len))
    ##  Print the packet
    for i in range(1,header.contents.len + 1):
        print ("%.2x " % pkt_data[i-1],)
        if (i % LINE_LEN) == 0:
            print ("\n")
    print ("\n\n")
    res = pcap_next_ex(fp, byref(header), byref(pkt_data))

if (res == -1):
    print ("Error reading the packets: %s\n" % pcap_geterr(fp))

pcap_close(fp)
sys.exit(0)

