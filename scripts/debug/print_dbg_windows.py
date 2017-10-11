import sys
import pickle


def print_dbg_windows(bbs):
    for bb in bbs:
        print("bb#%d" % bb.index)
        for window in bb.dbg_windows:
            print window


if __name__ == "__main__":
    bbsf = open(sys.argv[1], 'rb')
    bbs = pickle.load(bbsf)

    print_dbg_windows(bbs)