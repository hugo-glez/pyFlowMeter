#! /bin/env python
# coding=utf-8
# Copyright (C) 2019 CRI-Lab @ UPSLP
# This file is part of pyFlowMeter - CRI-Lab @ UPSLP
"""
This module create and update the flows

It also create consistent headers for the results

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

import numpy as np

import communityid
import packethelper as ph


#Values from tcp packets that could be of interes
#seq
#win
#offset

intvalues = "fwPackets,\
bwPackets,\
"   

npvalues = "flSize,\
fwSize,\
bwSize\
"

npfvalues = "flIAT,\
fwIAT,\
bwIAT\
"

values = "timestamp,\
cid,\
src,\
dst,\
sport,\
dport,\
proto,\
fwPackets,\
bwPackets\
"   


# BasicFlow manipulations:

def InitFlow( cid,tstamp,tpl,pkt):
    """ InitFlow will create the basic structure to store a flow information"""
    newFlow ={}
    newFlow['timestamp'] = tstamp
    newFlow['cid'] = cid
    newFlow['tpl'] = tpl
    newFlow['proto'] = tpl.proto
    newFlow['orig'] = tpl.saddr
    newFlow['bsrc'] = tpl.saddr
    newFlow['bdst'] = tpl.daddr
    newFlow['src'] = tpl._addr_to_ascii(tpl.saddr)
    newFlow['dst'] = tpl._addr_to_ascii(tpl.daddr)
    newFlow['sport'] = tpl.sport
    newFlow['dport'] = tpl.dport
    newFlow['lastseen'] = tstamp
    newFlow['fwlastseen'] = tstamp
    newFlow['bwlastseen'] = -1
    #for sv in stringvalues.split(','):
    #    newFlow[sv] = ''
    
    #Header bytes
    #Packets per second
    #Flow lenght
    #DownUpRatio
    #fAVGSegmentSize
    #FAvgBytesPerBulk
    #fAvgPacketsPerBulk
    #fAvgBulkRate
    #label


    #Values of all flags, and forward and backward flags
    for fl in ['fin','syn','rst','psh','ack','urg','ece','cwr']:
        newFlow[fl] = 0
        newFlow['ff'+fl] = 0
        newFlow['bf'+fl] = 0
    
    for iv in intvalues.split(','):
        newFlow[iv] = 0
    
    for nv in npvalues.split(','):
        newFlow[nv] = np.array([], dtype=np.int64)
    
    for fv in npfvalues.split(','):
        newFlow[fv] = np.array([], dtype=np.float64)
    
    return newFlow
        
        
    
#FlowUpdate(cFlow, tstamp,tpl,pkt)
def FlowUpdate(newFlow, tstamp,tpl,pkt) :
    
    if IP in pkt:
            saddr = pkt[IP].src
            daddr = pkt[IP].dst
            leng = pkt[IP].len
    elif IP6 in pkt:
            saddr = pkt[IP6].src
            daddr = pkt[IP6].dst
            leng =  pkt[IP6].plen
    
    flags = ph.getFlags(pkt)
    if newFlow['orig'] == saddr:
        newFlow['fwPackets'] += 1
        newFlow['fwSize'] = np.append(newFlow['fwSize'], leng)
        newFlow['fwIAT'] = np.append(newFlow['fwIAT'],tstamp - newFlow['fwlastseen'])
        newFlow['fwlastseen'] = tstamp
        for fl in ['fin','syn','rst','psh','ack','urg','ece','cwr']:
            newFlow['ff'+fl] += flags[fl]
    else:
        newFlow['bwPackets'] += 1
        newFlow['bwSize'] = np.append(newFlow['bwSize'],leng)
        if newFlow['fwlastseen'] > 0 :
           newFlow['bwIAT'] = np.append(newFlow['bwIAT'],tstamp - newFlow['bwlastseen']) 
        else:
           newFlow['bwlastseen'] = tstamp
        newFlow['bwlastseen'] = tstamp    
        for fl in ['fin','syn','rst','psh','ack','urg','ece','cwr']:
            newFlow['bf'+fl] += flags[fl]
    
    newFlow['flSize'] = np.append(newFlow['flSize'],leng)
    newFlow['flIAT'] = np.append(newFlow['flIAT'],tstamp - newFlow['lastseen'])
    newFlow['lastseen'] = tstamp
    
    for fl in ['fin','syn','rst','psh','ack','urg','ece','cwr']:
        newFlow[fl] += flags[fl]
        

def printHeaders():
    """ Print the headers for the features """
    strs = ''
    for kv in values.split(','):
        strs += kv + ','
    for kv in npvalues.split(','):
        strs += kv+"_sum,"
        strs += kv+"_max,"
        strs += kv+"_min,"
        strs += kv+"_mean,"
        strs += kv+"_median,"
        strs += kv+"_std,"
    for kv in ['fin','syn','rst','psh','ack','urg','ece','cwr']:
        strs += kv + ','
    for kv in ['fin','syn','rst','psh','ack','urg','ece','cwr']:
        strs += 'ff'+kv + ','
    for kv in ['fin','syn','rst','psh','ack','urg','ece','cwr']:
        strs += 'bf'+kv + ','
    print (strs)

def printFlow(Flow):
    strs = ''
    for kv in values.split(','):
        strs += str(Flow[kv]) + ','
    for kv in npvalues.split(','):
        if Flow[kv].size > 0:
            strs += str(np.sum(Flow[kv])) + ','
            strs += str(np.max(Flow[kv])) + ','
            strs += str(np.min(Flow[kv])) + ','
            strs += str(np.mean(Flow[kv])) + ','
            strs += str(np.median(Flow[kv])) + ','
            strs += str(np.std(Flow[kv])) + ','
        else:
            strs += "0.0,"*6
    for kv in ['fin','syn','rst','psh','ack','urg','ece','cwr']:
        strs += str(Flow[kv]) + ','
    for kv in ['fin','syn','rst','psh','ack','urg','ece','cwr']:
        strs += str(Flow['ff'+kv]) + ','
    for kv in ['fin','syn','rst','psh','ack','urg','ece','cwr']:
        strs += str(Flow['bf'+kv]) + ','
    print(strs)
