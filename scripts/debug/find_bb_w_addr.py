import pickle
import basic_block
import sys
from idaapi import *
from idautils import *
from idc import *

BATCH_MODE = False


def find_bb_w_addr_brute(bbs, addr):
    for bb in bbs:
        for a in bb.addrs:
            if a == addr:
                return bb

if __name__ == "__main__":
    autoWait()

    bbsf = open(ARGV[1], 'rb')
    bbs = pickle.load(bbsf)

    bb = find_bb_w_addr_brute(bbs, 0x431AC3)

    print("dbg: bb.addrs[0]: " + str(hex(bb.addrs[0])))
    print("dbg: bb.addrs[-1]: " + str(hex(bb.addrs[-1])))
    for h in Heads(bb.addrs[0], bb.addrs[-1]+1):
        print GetMnem(h)

    if BATCH_MODE:
        Exit(0)