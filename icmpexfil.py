import struct
import socket
import binascii
import random

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0

ICMP_CODE = socket.getprotobyname('icmp')

def createPacket(id):
    t = ICMP_ECHO_REQUEST # This is the type of ICMP packet
    c = 0 # This is the code, or sub type, for the ICMP packet
    checkSum = 0
    # Type (8), code(8), checksum(16), id(16), sequence(16)
    icmpHeader = struct.pack("bbHHh", t, c, checkSum, id, 0)
    #data = "Hello World!"
    #data = (192 - len(data)) * 'Z' #Fill the rest of the data with Zs
    bytesInDouble = struct.calcsize("d")
    data = 192 * 'Q'
    
    return icmpHeader + binascii.a2b_base64(data)

def do_one(dest_addr, timeout=1):
    """
    Sends one ping to the given "dest_addr" which can be an ip or hostname.
    "timeout" can be any integer or float except negatives and zero.

    Returns either the delay (in seconds) or None on timeout and an invalid
    address, respectively.

    """
    try:
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)
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
    packet = createPacket(packet_id)
    while packet:
        # The icmp protocol does not use a port, but the function
        # below expects it, so we just give it a dummy port.
        sent = my_socket.sendto(packet, (dest_addr, 1))
        packet = packet[sent:]
    #delay = receive_ping(my_socket, packet_id, time.time(), timeout)
    my_socket.close()
    #return delay
    return

do_one("8.8.8.8")
    
