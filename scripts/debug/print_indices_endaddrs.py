import pickle
import sys



if __name__ == "__main__":
    bbsf = open(sys.argv[1], 'rb')
    bbs = pickle.load(bbsf)

    for bb in bbs:
        print("%d,%x" % (bb.index, bb.end_addr))