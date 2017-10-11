import pickle
import basic_block
import sys


def compare_size(bbs1, bbs2):
    print("bbs1 has %d basic blocks" % len(bbs1))
    print("bbs2 has %d basic blocks" % len(bbs2))


if __name__ == "__main__":
    bbs1f = open(sys.argv[1], 'rb')
    bbs2f = open(sys.argv[2], 'rb')

    bbs1 = pickle.load(bbs1f)
    bbs2 = pickle.load(bbs2f)

    compare_size(bbs1, bbs2)