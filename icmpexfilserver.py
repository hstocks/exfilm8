import socket
import binascii
import math

incomingFileBytes = bytearray()

def init():
    listen()

def addNextChunk(data):
    # Ensure correct byte order when adding
    return

def eof(data):
    return

def calculateChecksum(data):
    return

def confirmIntegrity(checksum):
    return

def parseDNSPacket(data):
    print("Next packet, length: %d" % len(data))
    # Remove DNS header and footer - first 12, and last 5 bytes
    data = data[12:-5]

    buf = b''
    labelLen = 0
    labelProgress = 0
    readingLabel = False

    for i in range(0, len(data)):
        if readingLabel:
            buf += data[i].to_bytes(1, "little")
            labelProgress += 1

            if labelProgress == labelLen:
                readingLabel = False
                labelProgress = 0
        else:
            labelLen = data[i]
            print("Next labelLen is: " + str(labelLen))
            readingLabel = True
    return buf

def parseICMPPacket(data):
    # Remove DNS header and footer - first 12, and last 5 bytes
    data = data[12:]
    return data

def listen():
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    serverSocket.bind(("127.0.0.1", 53))

    while True:
        data = serverSocket.recv(1024)
        if not data: break

        # packetData = extractPacketData(data)
        # if expectingChecksum:
        #   confirmIntegrity(packetData)   
        # else:
        #    if eof(packetData):
        #      expectChecksum = True
        #    else:
        #      addNextChunk(fileData)
        print(parseDNSPacket(data))
    return

init()