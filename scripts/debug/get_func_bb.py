import sys
import pickle
from verify_bb_order import *


def get_func_bb(func, i_bb, bbs):
    func_bbs = get_bbs_for_func(bbs,func)
    return func_bbs[i_bb]


if __name__ == "__main__":
    bbsf = open(sys.argv[1], 'rb')
    bbs = pickle.load(bbsf)

    bb = get_func_bb("mpc_input_mark", 18, bbs)
    for i in bb.opcodes:
        print i