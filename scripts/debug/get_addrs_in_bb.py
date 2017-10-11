import basic_block
import sys
import pickle

def get_addrs_in_bb(bbs):
    func_name_to_count = dict()

    for bb in bbs:
        if 0x419484 in range(bb.start_addr, bb.end_addr+1):
            for x in range(bb.start_addr, bb.end_addr+1):
                print hex(x)

if __name__ == "__main__":
    bbsf = open(sys.argv[1], 'rb')
    bbs = pickle.load(bbsf)

    get_addrs_in_bb(bbs)