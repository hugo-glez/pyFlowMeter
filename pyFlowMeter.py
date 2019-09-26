#! /bin/env python
# coding=utf-8
# Copyright (C) 2019 CRI-Lab @ UPSLP
# This file is part of pyFlowMeter - CRI-Lab @ UPSLP
"""
pyFlowMeter is originally based on the script provided by communityid,
and inspired by CICFlowMeter.

The idea is to create network flows with similar features than CICFlowMeter
but it includes Community ID hashes and other features.

From the original script:

Currently supported protocols include IP, IPv6, ICMP, ICMPv6, TCP,
UDP, SCTP.

Please note: the protocol parsing implemented in this script relies
on the dpkt module and is somewhat simplistic:

- dpkt seems to struggle with some SCTP packets, for which it fails
  to register SCTP even though its header is correctly present.

- The script doesn't try to get nested network layers (IP over IPv6,
  IP in IP, etc) right. It expects either IP or IPv6, and it expects
  a transport-layer protocol (including the ICMPs here) as the
  immediate next layer.
"""
import argparse
import base64
import hashlib
import socket
import struct
import sys

#import numpy as np

from collections import defaultdict

import communityid


#Auxiliar classes
import BasicFlow as bf
import packethelper as ph

FinishedFlows = defaultdict(dict)
ActualFlows = defaultdict(dict)

try:
    import dpkt
except ImportError:
    print('This software requiere the dpkt Python module')
    sys.exit(1)

from dpkt.ethernet import Ethernet #pylint: disable=import-error
from dpkt.ip import IP #pylint: disable=import-error
from dpkt.ip6 import IP6 #pylint: disable=import-error
from dpkt.icmp import ICMP #pylint: disable=import-error
from dpkt.icmp6 import ICMP6 #pylint: disable=import-error
from dpkt.tcp import TCP #pylint: disable=import-error
from dpkt.udp import UDP #pylint: disable=import-error
from dpkt.sctp import SCTP #pylint: disable=import-error


class PcapIterator(object):
    def __init__(self, commid, pcap):
        self._commid = commid
        self._pcap = pcap
        self.GoodPackets = 0
        self.BadPackets = 0

    def process(self):
        with open(self._pcap, 'r+b') as hdl:
            reader = dpkt.pcap.Reader(hdl)
            for tstamp, pktdata in reader:
                r = self._process_packet(tstamp, pktdata)
                if r=="G":
                    self.GoodPackets += 1
                else :
                    self.BadPackets += 1

    def _process_packet(self, tstamp, pktdata):
        pkt = self._packet_parse(pktdata)

        if not pkt:
            self._print_result(tstamp, pkt, '<not IP>')
            return "B"

        if IP in pkt:
            saddr = pkt[IP].src
            daddr = pkt[IP].dst
        elif IP6 in pkt:
            saddr = pkt[IP6].src
            daddr = pkt[IP6].dst
        else:
            self._print_result(tstamp, pkt, '<not IP (???)>')
            return "B"

        tpl = None

        if TCP in pkt:
            tpl = communityid.FlowTuple(
                dpkt.ip.IP_PROTO_TCP, saddr, daddr,
                pkt[TCP].sport, pkt[TCP].dport)

        elif UDP in pkt:
            tpl = communityid.FlowTuple(
                dpkt.ip.IP_PROTO_UDP, saddr, daddr,
                pkt[UDP].sport, pkt[UDP].dport)

        elif SCTP in pkt:
            tpl = communityid.FlowTuple(
                dpkt.ip.IP_PROTO_SCTP, saddr, daddr,
                pkt[SCTP].sport, pkt[SCTP].dport)

        elif ICMP in pkt:
            tpl = communityid.FlowTuple(
                dpkt.ip.IP_PROTO_ICMP, saddr, daddr,
                pkt[ICMP].type, pkt[ICMP].code)

        elif ICMP6 in pkt:
            tpl = communityid.FlowTuple(
                dpkt.ip.IP_PROTO_ICMP6, saddr, daddr,
                pkt[ICMP6].type, pkt[ICMP6].code)

        if tpl is None:
            # Fallbacks to other IP protocols:
            if IP in pkt:
                tpl = communityid.FlowTuple(pkt[IP].p, saddr, daddr)
            elif IP6 in pkt:
                tpl = communityid.FlowTuple(pkt[IP].nxt, saddr, daddr)

        if tpl is None:
            self._print_result(tstamp, pkt, '<not IP (???)>')
            return "B"

        #self._print_result(tstamp, pkt, self._commid.calc(tpl))
        #Check Flags, 
        flags = ph.getFlags(pkt)
                
        
        #add packet to a flow
        cid = self._commid.calc(tpl)
        if cid in ActualFlows.keys():
            cFlow = ActualFlows[cid]
            
        else:
            cFlow = bf.InitFlow(cid, tstamp,tpl,pkt)
        bf.FlowUpdate(cFlow, tstamp,tpl,pkt)
        ActualFlows[cid] = cFlow
        return "G"

    def _packet_to_str(self, pkt):
        """
        Helper that returns flow tuple string of given packet, as-is (no
        canonicalization).
        """
        parts = []

        if IP in pkt:
            parts.append(socket.inet_ntop(socket.AF_INET, pkt[IP].src))
            parts.append(socket.inet_ntop(socket.AF_INET, pkt[IP].dst))
            parts.append(pkt[IP].p)
        elif IP6 in pkt:
            parts.append(socket.inet_ntop(socket.AF_INET6, pkt[IP6].src))
            parts.append(socket.inet_ntop(socket.AF_INET6, pkt[IP6].dst))
            parts.append(pkt[IP6].nxt)

        if ICMP in pkt:
            parts.append(pkt[ICMP].type)
            parts.append(pkt[ICMP].code)
        elif ICMP6 in pkt:
            parts.append(pkt[ICMP6].type)
            parts.append(pkt[ICMP6].code)
        elif TCP in pkt:
            parts.append(pkt[TCP].sport)
            parts.append(pkt[TCP].dport)
        elif UDP in pkt:
            parts.append(pkt[UDP].sport)
            parts.append(pkt[UDP].dport)
        elif SCTP in pkt:
            parts.append(pkt[SCTP].sport)
            parts.append(pkt[SCTP].dport)

        return ' '.join(str(part) for part in parts)

    def _packet_parse(self, pktdata):
        """
        Parses the protocols in the given packet data and returns the
        resulting packet (here, as a dict indexed by the protocol layers
        in form of dpkt classes).
        """
        layer = Ethernet(pktdata)
        pkt = {}

        if isinstance(layer.data, IP):
            pkt[IP] = layer = layer.data
        elif isinstance(layer.data, IP6):
            # XXX This does not correctly skip IPv6 extension headers
            pkt[IP6] = layer = layer.data
        else:
            return pkt

        if isinstance(layer.data, ICMP):
            pkt[ICMP] = layer.data
        elif isinstance(layer.data, ICMP6):
            pkt[ICMP6] = layer.data
        elif isinstance(layer.data, TCP):
            pkt[TCP] = layer.data
        elif isinstance(layer.data, UDP):
            pkt[UDP] = layer.data
        elif isinstance(layer.data, SCTP):
            pkt[SCTP] = layer.data

        return pkt

    def _print_result(self, tstamp, pkt, res):
        print('%10.6f | %s | %s' % (tstamp, res, self._packet_to_str(pkt)))


def main():
    parser = argparse.ArgumentParser(description='Community ID pcap processor')
    parser.add_argument('pcaps', metavar='PCAP', nargs='+',
                        help='PCAP packet capture files')
    parser.add_argument('--seed', type=int, default=0, metavar='NUM',
                        help='Seed value for hash operations')
    parser.add_argument('--no-base64', action='store_true', default=False,
                        help="Don't base64-encode the SHA1 binary value")
    args = parser.parse_args()

    commid = communityid.CommunityID(args.seed, not args.no_base64)
    GoodPackets = 0
    BadPackets = 0
    
    for pcap in args.pcaps:
        itr = PcapIterator(commid, pcap)
        itr.process()
        print (f'Good packets: {itr.GoodPackets}, Bad packets: {itr.BadPackets}')
        tflows = len(ActualFlows)
        print (f'Total flows generated {tflows}')
        for k,Flow in ActualFlows.items():
            bf.printFlow(Flow)
        

    return 0

if __name__ == '__main__':
    sys.exit(main())
