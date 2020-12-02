#! /bin/env python
# coding=utf-8
# Copyright (C) 2019 CRI-Lab @ UPSLP
# This file is part of pyFlowMeter - CRI-Lab @ UPSLP
"""
pyFlowMeter is originally based on the script provided by communityid,
and inspired by CICFlowMeter.

This is genLabels.py part of pyFlowMeter to generate labels from datasets.
This version supports only files from zeek or broids format, for other 
formats, work should be done.

The format is as follows:
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents   label   detailed-label
#types	time	string	addr	port	addr	port	enum	string	interval	count	count	string	bool	bool	count	string	count	count	count	count	set[string]   string   string

This is the fomat for the labels provided by CTU-Malware-Captures for IoT traffic
https://www.stratosphereips.org/datasets-malware
"""

import argparse
import communityid
import sys
import socket

def processfile(commid, txtfile):
    proto = {'tcp':6 , 'udp':17}
    file1 = open(txtfile, 'r') 
    Lines = file1.readlines() 
    for li in Lines: 
          vals = li.split() 
       #try :
          tpl = communityid.FlowTuple(proto[vals[6]],
                                      socket.inet_aton(vals[2]), socket.inet_aton(vals[4]),
                                      int(vals[3]), int(vals[5]) )
          cid = commid.calc(tpl)  
  
          print(cid,',',vals[-1])  
       #except: 
       #   print (li) 




def main():
    parser = argparse.ArgumentParser(description='genLabels for communityid')
    parser.add_argument('txtfiles', metavar='TXTFILES', nargs='+',
                        help='Text files from zeek')
    parser.add_argument('--seed', type=int, default=0, metavar='NUM',
                        help='Seed value for hash operations')
    parser.add_argument('--no-base64', action='store_true', default=False,
                        help="Don't base64-encode the SHA1 binary value")
    args = parser.parse_args()

    commid = communityid.CommunityID(args.seed, not args.no_base64)
    
    for txtfile in args.txtfiles:
        processfile(commid,txtfile)
        
    return 0

    
if __name__ == '__main__':
    sys.exit(main())
