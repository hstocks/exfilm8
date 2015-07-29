#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:        readfile.py
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

## prototype of the packet handler
## void dispatcher_handler(u_char *, const struct pcap_pkthdr *, const u_char *)

DHAND=CFUNCTYPE(None,POINTER(c_ubyte),POINTER(pcap_pkthdr),POINTER(c_ubyte))

## Callback function invoked by libpcap for every incoming packet
def _dispatcher_handler(temp1,header,pkt_data):
    ## print pkt timestamp and pkt len
    print ("%ld:%ld (%ld)\n" % (header.contents.ts.tv_sec,header.contents.ts.tv_usec, header.contents.len))
    ##  Print the packet
    for i in range(1,header.contents.len + 1):
        print ("%.2x " % pkt_data[i-1])
        if (i % LINE_LEN) == 0:
            print ("\n")
    print ("\n\n")

dispatcher_handler=DHAND(_dispatcher_handler)


fp=pcap_t
errbuf= create_string_buffer(PCAP_ERRBUF_SIZE)
if (len(sys.argv) != 2):
    print ("usage: %s filename" % sys.argv[0])
    sys.exit(-1)

## Open the capture file
fp = pcap_open_offline(sys.argv[1],errbuf)
if not bool(fp):
    print ("\nUnable to open the file %s.\n" % sys.argv[1])
    sys.exit(-1)
## read and dispatch packets until EOF is reached
pcap_loop(fp, 0, dispatcher_handler, None)
pcap_close(fp)
sys.exit(0)
