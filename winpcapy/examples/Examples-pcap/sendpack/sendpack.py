#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:        sendpack.py
#
# Author:      Massimo Ciani
#
# Created:     01/09/2009
# Copyright:   (c) Massimo Ciani 2009
#
#-------------------------------------------------------------------------------

from ctypes import *
from winpcapy import *

fp=pcap_t
errbuf= create_string_buffer(PCAP_ERRBUF_SIZE)
packet=(c_ubyte * 100)()

## Check the validity of the command line
if len(sys.argv) != 2:
    print ("usage: %s interface" % sys.argv[0])
    sys.exit(1)

## Open the adapter
fp = pcap_open_live(sys.argv[1],65536,1,1000,errbuf)
if not bool(fp):
    print ("\nUnable to open the adapter. %s is not supported by WinPcap\n" % sys.argv[1])
    sys.exit(2)

## Supposing to be on ethernet, set mac destination to 1:1:1:1:1:1
packet[0]=1
packet[1]=1
packet[2]=1
packet[3]=1
packet[4]=1
packet[5]=1

## set mac source to 2:2:2:2:2:2
packet[6]=2
packet[7]=2
packet[8]=2
packet[9]=2
packet[10]=2
packet[11]=2

## Fill the rest of the packet
for i in range(12,100):
    packet[i]=i

## Send down the packet
if (pcap_sendpacket(fp,packet,100) != 0):
    print ("\nError sending the packet: %s\n" % pcap_geterr(fp))
    sys.exit(3)

pcap_close(fp)
sys.exit(0)
