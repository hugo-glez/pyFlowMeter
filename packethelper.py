#! /bin/env python
# coding=utf-8
# Copyright (C) 2019 CRI-Lab @ UPSLP
# This file is part of pyFlowMeter - CRI-Lab @ UPSLP
"""
This module is a helper to obtain info from packets

"""
import dpkt
from dpkt.ethernet import Ethernet #pylint: disable=import-error
from dpkt.ip import IP #pylint: disable=import-error
from dpkt.ip6 import IP6 #pylint: disable=import-error
from dpkt.icmp import ICMP #pylint: disable=import-error
from dpkt.icmp6 import ICMP6 #pylint: disable=import-error
from dpkt.tcp import TCP #pylint: disable=import-error
from dpkt.udp import UDP #pylint: disable=import-error
from dpkt.sctp import SCTP #pylint: disable=import-error

def getFlags(pkt):
    flags ={}
    for f in ['fin','syn','rst','psh','ack','urg','ece','cwr']:
        flags[f] = 0
    
    if TCP in pkt:
            tcp = pkt[TCP]
            flags['fin'] = ( tcp.flags & 0x01 ) != 0
            flags['syn'] = ( tcp.flags & 0x02 ) != 0
            flags['rst'] = ( tcp.flags & 0x04 ) != 0
            flags['psh'] = ( tcp.flags & 0x08 ) != 0
            flags['ack'] = ( tcp.flags & 0x10 ) != 0
            flags['urg'] = ( tcp.flags & 0x20 ) != 0
            flags['ece'] = ( tcp.flags & 0x40 ) != 0
            flags['cwr'] = ( tcp.flags & 0x80 ) != 0
    return flags
