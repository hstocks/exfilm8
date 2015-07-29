#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:        basic_dump.py
#
# Author:      Massimo Ciani
#
# Created:     01/09/2009
# Copyright:   (c) Massimo Ciani 2009
#
#-------------------------------------------------------------------------------

import ctypes
from ctypes import *
from winpcapy import *
import time
import sys
import string
import platform

import socket
u_short = c_ushort
u_char = c_ubyte
u_int = c_int


class ip_address(Structure):
    _fields_ = [("byte1", u_char),
                ("byte2", u_char),
                ("byte3", u_char),
                ("byte4", u_char)]


class ip_header(BigEndianStructure):
    _fields_ = [("ver_ihl", u_char),
                ("tos", u_char),
                ("tlen", u_short),
                ("identification", u_short),
                ("flags_fo", u_short),
                ("ttl", u_char),
                ("proto", u_char),
                ("crc", u_short),
                ("saddr", ip_address),
                ("daddr", ip_address),
                ("op_pad", u_int)]


class udp_header(BigEndianStructure):
    _fields_ = [("sport", u_short),
                ("dport", u_short),
                ("len", u_short),
                ("crc", u_short)]





def main(packet_file):
    with open(packet_file, "rb") as fd:
        data = fd.read()

    # create ctypes.c_char_array
    pkt_data = ctypes.c_buffer(data)
    packet_handler(pkt_data)

if __name__ == '__main__':
    if len(sys.argv) == 2:
        main(sys.argv[1])






if platform.python_version()[0] == "3":
	raw_input=input
#/* prototype of the packet handler */
#void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
PHAND=CFUNCTYPE(None,POINTER(c_ubyte),POINTER(pcap_pkthdr),POINTER(c_ubyte))


def _packet_handler(param,header,pkt_data):

    # cast pkt_data to void so we can do some pointer arithmetic
    v_pkt_data = ctypes.cast(pkt_data, ctypes.c_void_p)

    # retrieve the position of the ip header
    v_ip_header = ctypes.c_void_p(v_pkt_data.value + 14)
    pih = ctypes.cast(v_ip_header, ctypes.POINTER(ip_header))
    ih = pih.contents

    # retrieve the position of the udp header
    ip_len = (ih.ver_ihl & 0xf) * 4
    uh = ctypes.cast(ctypes.cast(pih, ctypes.c_void_p).value + ip_len,
                     ctypes.POINTER(udp_header)).contents

    # convert from network byte order to host byte order
    sport = socket.ntohs(uh.sport)
    dport = socket.ntohs(uh.dport)

    print("{}.{}.{}.{}:{} -> {}.{}.{}.{}:{}".format(
        ih.saddr.byte1, ih.saddr.byte2, ih.saddr.byte3, ih.saddr.byte4, sport,
        ih.daddr.byte1, ih.daddr.byte2, ih.daddr.byte3, ih.daddr.byte4, dport))

    # Extracting data
    #

    # data offset from ip header start
    data_offset = ip_len + ctypes.sizeof(udp_header)
    # data length
    data_len = ih.tlen - ip_len - ctypes.sizeof(udp_header)
    # get data
    arr_type = (ctypes.c_uint8 * data_len)
    data = arr_type.from_address(v_ip_header.value + data_offset)

    #print(data[0:data_len])

    # note: same thing could be achieved from pkt_data
    #print(pkt_data[14+data_offset:14+data_offset+data_len])
    
'''## Callback function invoked by libpcap for every incoming packet
def _packet_handler(param,header,pkt_data):
	## convert the timestamp to readable format
	#print(dir(pkt_data.contents.value));
	#print(str(pkt_data.contents.value.real))
	print(header[14])
	hbytes = bytes(header)
	#ipb1 = hbytes[14]
	#ipb2 = hbytes[15]
	#ipb3 = hbytes[16]
	#ipb4 = hbytes[17]
	#print("%d.%d.%d.%d" % (ipb1, ipb2, ipb3, ipb4))
	
	local_tv_sec = header.contents.ts.tv_sec
	ltime=time.localtime(local_tv_sec);
	timestr=time.strftime("%H:%M:%S", ltime)
	print("%s,%.6d len:%d" % (timestr, header.contents.ts.tv_usec, header.contents.len))

'''
packet_handler=PHAND(_packet_handler)
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
## start the capture (we take only 15 packets)
pcap_loop(adhandle, 30, packet_handler, None)
pcap_close(adhandle)
