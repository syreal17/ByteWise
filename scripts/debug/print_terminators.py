import pickle
import basic_block
import sys


def print_terminators(bbs):
    for bb in bbs:
        #print("%s @ %x" % (bb.end_mnem, bb.h_end))
        print("%s" % (bb.end_mnem))


if __name__ == "__main__":
    bbsf = open(sys.argv[1], 'rb')
    bbs = pickle.load(bbsf)

    print_terminators(bbs)



