import sys
import pickle
import basic_block


def count_bytes_per_label(bbsann):
    c_none = 0
    c_original = 0
    c_altered = 0
    for bb in bbsann:
        if bb.annotated == basic_block.ANN_NONE:
            c_none += 1#len(range(bb.start_addr, bb.end_addr + 1))
        elif bb.annotated == basic_block.ANN_ORIGINAL:
            c_original += 1#len(range(bb.start_addr, bb.end_addr + 1))
        elif bb.annotated == basic_block.ANN_ALTERED:
            c_altered += 1#len(range(bb.start_addr, bb.end_addr + 1))
        else:
            print("Basic block without legit annotation")

    return c_none, c_original, c_altered

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("First and only argument is annotated basic block list")

    bbsannf = open(sys.argv[1], 'rb')
    bbsann = pickle.load(bbsannf)

    c_none, c_original, c_altered = count_bytes_per_label(bbsann)
    print("None=%d" % c_none)
    print("Original=%d" % c_original)
    print("Altered=%d" % c_altered)
