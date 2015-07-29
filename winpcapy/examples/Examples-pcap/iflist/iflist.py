#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:        iflist.py
#
# Author:      Massimo Ciani
#
# Created:     01/09/2009
# Copyright:   (c) Massimo Ciani 2009
#
#-------------------------------------------------------------------------------


from ctypes import *
from winpcapy import *
import string
import time
import socket as sk
import platform

if platform.python_version()[0] == "3":
	raw_input=input
#
# Basic structures and data definitions for AF_INET family
#
class S_un_b(Structure):
    _fields_ = [("s_b1",c_ubyte),
                ("s_b2",c_ubyte),
                ("s_b3",c_ubyte),
                ("s_b4",c_ubyte)]

class S_un_w(Structure):
    _fields_ = [("s_wl",c_ushort),
                ("s_w2",c_ushort)]

class S_un(Union):
    _fields_ = [("S_un_b",S_un_b),
                ("S_un_w",S_un_w),
                ("S_addr",c_ulong)]

class in_addr(Structure):
    _fields_ = [("S_un",S_un)]



class sockaddr_in(Structure):
    _fields_ = [("sin_family", c_ushort),
                ("sin_port", c_ushort),
                ("sin_addr", in_addr),
                ("sin_zero", c_char * 8)]

#
# Basic structures and data definitions for AF_INET6 family
#
class _S6_un(Union):
    _fields_=[("_S6_u8",c_ubyte *16),
              ("_S6_u16",c_ushort *8),
              ("_S6_u32",c_ulong *4)]

class in6_addr(Structure):
    _fields_=[("_S6_un",_S6_un)]

s6_addr=_S6_un._S6_u8
s6_addr16=_S6_un._S6_u16
s6_addr32=_S6_un._S6_u32

IN6_ADDR=in6_addr
PIN6_ADDR=POINTER(in6_addr)
LPIN6_ADDR=POINTER(in6_addr)

class sockaddr_in6(Structure):
    _fields_=[("sin6_family",c_short),
              ("sin6_port",c_ushort),
              ("sin6_flowinfo",c_ulong),
              ("sin6_addr",in6_addr),
              ("sin6_scope_id",c_ulong)]

SOCKADDR_IN6=sockaddr_in6
PSOCKADDR_IN6=POINTER(sockaddr_in6)
LPSOCKADDR_IN6=POINTER(sockaddr_in6)


def iptos(in_):
   return "%d.%d.%d.%d" % (in_.s_b1,in_.s_b2 , in_.s_b3, in_.s_b4)

def ip6tos(in_):
    addr=in_.contents.sin6_addr._S6_un._S6_u16
    vals=[]
    for x in range(0,8):
        vals.append(sk.ntohs(addr[x]))
    host= ("%x:%x:%x:%x:%x:%x:%x:%x" % tuple(vals))
    port=0
    flowinfo=in_.contents.sin6_flowinfo
    scopeid=in_.contents.sin6_scope_id
    flags=sk.NI_NUMERICHOST | sk.NI_NUMERICSERV
    retAddr,retPort=sk.getnameinfo((host, port, flowinfo, scopeid), flags)
    return retAddr

def ifprint(d):
    a=POINTER(pcap_addr_t)
    ip6str=c_char * 128
    ## Name
    print("%s\n" % d.name)
    ## Description
    if (d.description):
        print ("\tDescription: %s\n" % d.description)
    ## Loopback Address
    if (d.flags & PCAP_IF_LOOPBACK):
        print ("\tLoopback: %s\n" % "yes")
    else:
        print ("\tLoopback: %s\n" % "no")
    ## IP addresses
    if d.addresses:
        a=d.addresses.contents
    else:
        a=False
    while a:
        print ("\tAddress Family: #%d\n" % a.addr.contents.sa_family)
        if a.addr.contents.sa_family == sk.AF_INET:
            mysockaddr_in=sockaddr_in
            print ("\tAddress Family Name: AF_INET\n")
            if (a.addr):
                aTmp=cast(a.addr,POINTER(mysockaddr_in))
                print ("\tAddress: %s\n" % iptos(aTmp.contents.sin_addr.S_un.S_un_b))
            if a.netmask:
                aTmp=cast(a.netmask,POINTER(mysockaddr_in))
                print ("\tNetmask: %s\n" % iptos(aTmp.contents.sin_addr.S_un.S_un_b))
            if a.broadaddr:
                aTmp=cast(a.broadaddr,POINTER(mysockaddr_in))
                print ("\tBroadcast Address: %s\n" % iptos(aTmp.contents.sin_addr.S_un.S_un_b))
            if a.dstaddr:
                aTmp=cast(a.dstaddr,POINTER(mysockaddr_in))
                print ("\tDestination Address: %s\n" % iptos(aTmp.contents.sin_addr.S_un.S_un_b))
        elif a.addr.contents.sa_family == sk.AF_INET6:
            mysockaddr_in6=sockaddr_in6
            print ("\tAddress Family Name: AF_INET6\n")
            if (a.addr):
                aTmp=cast(a.addr,POINTER(mysockaddr_in6))
                print ("\tAddress: %s\n" % ip6tos(aTmp))
        else:
            print ("\tAddress Family Name: Unknown\n")
        if a.next:
            a=a.next.contents
        else:
            a=False
    print ("\n")


alldevs=POINTER(pcap_if_t)()
d=POINTER(pcap_if_t)
errbuf= create_string_buffer(PCAP_ERRBUF_SIZE)

## Retrieve the device list
if (pcap_findalldevs(byref(alldevs), errbuf) == -1):
    print ("Error in pcap_findalldevs: %s\n" % errbuf.value)
    sys.exit(1)

d=alldevs.contents
while d:
    ifprint(d)
    if d.next:
         d=d.next.contents
    else:
         d=False
## Free the device list
pcap_freealldevs(alldevs)
sys.exit(1)
