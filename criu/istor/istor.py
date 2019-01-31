#!/usr/bin/python3

import argparse
import datetime
import calendar
import logging
import pprint
import socket
import struct
import uuid
import json
import time
import sys
import os
import re

from struct import *
from datetime import datetime
from enum import Enum

class ISTOR_CMD(Enum):
    NONE    = 0
    INIT    = 1
    FINI    = 2
    FIND    = 3
    LIST    = 4
    EXIT    = 5
    ACK     = 6
    ERR     = 7

class ISTOR_FLAGS(Enum):
    NONE    = 0
    FIN     = 1

def istor_oid_zero():
    return uuid.UUID(bytes=pack('<QQ', 0, 0))

def istor_hdr_zero():
    return pack('<II16sQ', ISTOR_CMD.NONE.value, 0,
                istor_oid_zero().bytes, 0)

def istor_oid_pack(oid=None):
    if not oid: oid = istor_oid_zero()
    return pack('<16s', oid.bytes)

def istor_oid_unpack(raw=None):
    if not raw: return istor_oid_zero()
    return uuid.UUID(bytes=raw[0:16])

def pack_istor_hdr(cmd=ISTOR_CMD.NONE, oid=None, flags=ISTOR_FLAGS.FIN, size=0):
    return pack('<II16sQ', cmd.value, flags.value, istor_oid_pack(oid), size)

def unpack_istor_hdr(hdr):
    cmd, flags, oid_raw, size = unpack('<II16sQ', hdr)
    return cmd, flags, istor_oid_unpack(oid_raw), size

def repr_istor_hdr(raw=None):
    if not raw: raw = istor_hdr_zero()
    cmd, flags, oid, size = unpack_istor_hdr(raw)
    return format('cmd %2d flags %2x size %4d oid %s' %
                  (cmd, flags, size, oid))

class istor:
    def __init__(self, log, conf):
        self.log = log
        self.conf = conf
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addr, self.port = conf["address"].split(":")

    def connect(self):
        try:
            self.sock.connect((self.addr, int(self.port)))
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.log.debug("istor: Connected")
        except:
            self.sock.close()
            self.sock = None
            self.log.error("istor: Can't connect %s:%s" % (self.addr, self.port))

    def disconnect(self):
        if self.connected():
            self.send_recv_istor_msg(pack_istor_hdr(cmd=ISTOR_CMD.NONE))
            self.sock.close()
            self.sock = None
            self.log.debug("istor: Disconnected")

    def connected(self):
        return self.sock != None

    def receive(self,size=16384):
        if self.connected():
            return self.sock.recv(size)
        return None

    def send(self,obj):
        if self.connected():
            self.sock.send(obj)

    def recv_istor_msg(self,size=32):
        recv = self.receive(size)
        self.log.debug("istor: recv: %s" % (repr_istor_hdr(recv)))
        return recv

    def send_istor_msg(self, obj):
        self.log.debug("istor: send: %s" % (repr_istor_hdr(obj)))
        self.send(obj)

    def send_recv_istor_msg(self, obj):
        self.send_istor_msg(obj)
        return self.recv_istor_msg()

    def stor_init(self, oid=None):
        return self.send_recv_istor_msg(pack_istor_hdr(cmd=ISTOR_CMD.INIT, oid=oid))

    def stor_list(self, oid=None):
        oids = []
        reply = self.send_recv_istor_msg(pack_istor_hdr(cmd=ISTOR_CMD.LIST, oid=oid))
        if reply:
            cmd, flags, oid, size = unpack_istor_hdr(reply)
            for i in range(0, size):
                reply = self.recv_istor_msg()
                cmd, flags, oid, size = unpack_istor_hdr(reply)
                oids.append(oid)
        return oids

conf = {}

parser = argparse.ArgumentParser(prog='istor.py')
parser.add_argument('--addr', dest = 'addr',
                    default = '127.0.0.1:44444',
                    help = 'address of the store server')

sp = parser.add_subparsers(dest = 'cmd')

for cmd in ['init']:
    spp = sp.add_parser(cmd, help = 'Init new store.')
    spp.add_argument('--oid', dest = 'oid',
                     default = '00000000-0000-0000-0000-000000000000',
                     help = 'OID of the store to init')

for cmd in ['fini']:
    spp = sp.add_parser(cmd, help = 'Close the store.')
    spp.add_argument('--oid', dest = 'oid',
                     default = '00000000-0000-0000-0000-000000000000',
                     help = 'OID of the store to delete')
    spp.add_argument('--all', dest = 'all',
                     help = 'Delete all stores',
                     action = 'store_true')

for cmd in ['exit']:
    spp = sp.add_parser(cmd, help = 'Force the store to exit.')

for cmd in ['list']:
    spp = sp.add_parser(cmd, help = 'List the object store.')
    spp.add_argument('--mode', dest = 'mode',
                     help = 'Listing mode: oid')

args, unknown_args = parser.parse_known_args()
if args.cmd == None:
    parser.print_help()
    sys.exit(1)

loglevel = logging.DEBUG

logging.basicConfig(format = '%(asctime)s %(filename)s %(funcName)s %(message)s',
                    datefmt = '%m/%d/%Y %H:%M:%S', level = loglevel)

conf['address'] = args.addr

istorcli = istor(logging, conf)
istorcli.connect()

if istorcli.connected() == False:
    logging.error("Not connected")
    sys.exit(1)

if args.cmd == 'init':
    reply = istorcli.stor_init(uuid.UUID(args.oid))
    if reply:
        cmd, flags, oid, size = unpack_istor_hdr(reply)
        print(oid)
elif args.cmd == 'list':
    oids = istorcli.stor_list()
    for oid in oids:
        print(oid)

istorcli.disconnect()
