import sys
import pickle
import basic_block
from verify_bb_order import *

DEBUG_PRINT = False

def create_annotated_addrs(bbs, bbsann):
    addr_to_ann = dict()
    func = ""
    bb_w_prolog_c = 0
    bb_w_prolog_ann_c = 0
    for bb in bbsann:
        if bb.func != func:
            func = bb.func
            func_bbsann = get_bbs_for_func(bbsann, func)
            func_bbs = get_bbs_for_func(bbs, func)

            # ltj: more for the sake of correct indexing, than verification
            if len(func_bbs) != len(func_bbsann):
                if DEBUG_PRINT:
                    print(func + " has different # of bbs b/w annotated and unannotated")
                    print("func_bbs:")
                    print_func_code(func_bbs)
                    print("func_bbsann:")
                    print_func_code(func_bbsann)
                    print("============================")

                #TODO: write dict with ANN_SKIP
                for bb in func_bbs:
                    for addr in range(bb.start_addr, bb.end_addr + 1):
                        addr_to_ann[addr] = basic_block.ANN_SKIP

                continue
            else:
                for x in range(0, len(func_bbs)):
                    bb = func_bbs[x]
                    bbann = func_bbsann[x]

                    # ltj: new line of code
                    bb.annotated = bbann.annotated

                    if bbann.annotated == basic_block.ANN_ORIGINAL or bbann.annotated == basic_block.ANN_ALTERED:
                        for addr in range(bb.start_addr, bb.end_addr + 1):
                            addr_to_ann[addr] = bbann.annotated
    return addr_to_ann

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Please supply an annotated list of basic blocks for the first argument, and the unannotated list of "
              "basic blocks of the same binary as the second option, and the file to be saved as the addr to ann "
              "dictionary")
        sys.exit(1)
    bbsannf = open(sys.argv[1], 'rb')
    bbsf = open(sys.argv[2], 'rb')
    dictf = open(sys.argv[3], 'wb')

    bbsann = pickle.load(bbsannf)
    bbs = pickle.load(bbsf)

    addr_to_ann = create_annotated_addrs(bbs, bbsann)

    #ltj: new line of code - hardcoded for simplicity now
    bbsannupdatef = open("beanstalkd.o0.bcf.g.elf.ann.bbs", 'wb')
    pickle.dump(bbs, bbsannupdatef)

    pickle.dump(addr_to_ann, dictf)
    print("addr_to_ann written to %s" % sys.argv[3])