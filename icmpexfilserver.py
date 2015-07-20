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

def listen():
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    serverSocket.bind(("192.168.0.104", 53))
    # serverSocket.listen(1) UDP sockets don't listen
    # conn, addr = serverSocket.accept()
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
        print(data)
    return

init()
    
