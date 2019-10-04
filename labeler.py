#! /bin/env python
# coding=utf-8
# Copyright (C) 2019 CRI-Lab @ UPSLP
# This file is part of pyFlowMeter - CRI-Lab @ UPSLP
"""
This module is a helper to obtain info for labels

"""

labelArray = {}

def loadLabels(lfile='labels.txt'):
    #try:
        with open(lfile,'r') as fs:
            info = fs.read().split('/n')
        for kv in info:
            k,v = kv.split(',')
            labelArray[k] = v
    #except:
    #    labelArray['n'] = 'a'


def getLabel(cid):
    if len(labelArray) == 0:
        loadLabels()
    r = labelArray.get(cid,"NoneLabel")
    return r
