import socket
import binascii
import math

incomingFileBytes = bytearray()

complete = False
packetCount = 0
verboseMode = True

handle = open("test.exe", "wb")

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
    global complete
    global packetCount


    packetCount += 1
    print("Type: DNS Length: %d Index: %d" % (len(data),packetCount))
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
            readingLabel = True
    
    print(buf)

    if b'Completed' in buf:
        if verboseMode:
            print("Received end of file transfer")
        complete = True
    else:
        try:
            handle.write(buf)
        except Exception as e:
            print("Error: " + str(e))

    return buf

def parseICMPPacket(data):
    # Remove DNS header and footer - first 12, and last 5 bytes
    data = data[12:]
    return data

def listen():
    global serverSocket

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
        parseDNSPacket(data)

        if complete:
            if verboseMode:
                print("Closing file and socket")
            close()
            break
    return

def close():
    serverSocket.close()
    handle.close()
init()