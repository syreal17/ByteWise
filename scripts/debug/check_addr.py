import pickle
import basic_block
import sys

def print_readable_ann_from_str_addr(addr):
    ann = addr_to_ann.get(int(addr, 16), basic_block.ANN_NONE)

    if ann == basic_block.ANN_NONE:
        print("None")
    elif ann == basic_block.ANN_ORIGINAL:
        print("Original")
    elif ann == basic_block.ANN_ALTERED:
        print("Altered")
    elif ann == basic_block.ANN_SKIP:
        print("Skip")
    else:
        print("UNKNOWN!")

def print_readable_ann_from_addr(addr):
    ann = addr_to_ann.get(addr, basic_block.ANN_NONE)

    if ann == basic_block.ANN_NONE:
        print("None")
    elif ann == basic_block.ANN_ORIGINAL:
        print("Original")
    elif ann == basic_block.ANN_ALTERED:
        print("Altered")
    elif ann == basic_block.ANN_SKIP:
        print("Skip")
    else:
        print("UNKNOWN!")

if __name__ == "__main__":
    path_d = sys.argv[1]
    key_d = sys.argv[2]

    fs_d = open(path_d, "rb")
    addr_to_ann = pickle.load(fs_d)

    for x in range(0x4022a0, 0x402409):
        print_readable_ann_from_addr(x)