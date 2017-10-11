import pickle
import basic_block
import sys
import asm_helper
import re

PROLOG_MAX_LENGTH = 15
PROLOG_MIN_LENGTH = 2
SKIP_MAX = 5
JACCARD_THRES_INSPECT = 0.10
BITSHRED_W_SIZE = 3

def verify_bb_order_hybrid_ann_only(bbsann, bbs):
    og_form = re.compile("^_*original_annotation$")
    alt_form = re.compile("^_*altered_annotation$")

    print("Verifying that we can one-to-one match between same functions the unannotated and annotated basic blocks")

    func = ""
    bb_w_prolog_c = 0
    bb_w_prolog_ann_c = 0
    for bb in bbsann:
        if bb.func != func:
            if og_form.match(bb.func) or alt_form.match(bb.func):
                continue
            func = bb.func
            func_bbsann = get_bbs_for_func(bbsann, func)
            func_bbs = get_bbs_for_func(bbs, func)

            #ltj: more for the sake of correct indexing, than verification
            if len(func_bbs) != len(func_bbsann):
                print(func + " has different # of bbs b/w annotated and unannotated, " +
                      str(len(func_bbsann)) + " vs " + str(len(func_bbs)))
                print("func_bbs:")
                print_func_code(func_bbs)
                print("func_bbsann:")
                print_func_code(func_bbsann)
                print("============================")
                continue
            else:
                for x in range(0, len(func_bbs)):
                    bb = func_bbs[x]
                    bbann = func_bbsann[x]
                    bb_l = len(bb.opcodes)
                    bbann_l = len(bbann.opcodes)

                    if bbann.annotated == basic_block.ANN_ORIGINAL or bbann.annotated == basic_block.ANN_ALTERED:

                        #if bbann_l - bb_l <= PROLOG_MAX_LENGTH and bbann_l - bb_l >= PROLOG_MIN_LENGTH:
                        #    bb_w_prolog_c += 1
                        #    if bbann.annotated == basic_block.ANN_ORIGINAL or bbann.annotated == basic_block.ANN_ALTERED:
                        #        bb_w_prolog_ann_c += 1
                        #else:
                        #    if bbann.annotated == basic_block.ANN_ORIGINAL or bbann.annotated == basic_block.ANN_ALTERED:
                        #        print("%s-bb#%d is annotated and bbann is %d longer" % (func,x,bbann_l-bb_l))

                        if bbann_l - bb_l > PROLOG_MAX_LENGTH:
                            # TODO: maybe find a way to skip to next func instead of bb
                            print("Sizing issue")
                            print("dbg: bb_l: " + str(bb_l))
                            print("dbg: bbann_l: " + str(bbann_l))
                            if bbann_l - bb_l > PROLOG_MAX_LENGTH:
                                print(func + "-bb#" + str(x) + " bbann prologue is too big")
                            #elif bbann_l - bb_l < 0:
                                #print(func + "-bb#" + str(x) + " bb bigger than bbann")
                            print("bb:")
                            for line in bb.opcodes:
                                print line
                                # for c in line:
                                #    sys.stdout.write(str(ord(c)))
                                # sys.stdout.write("\n")
                            print("bbann:")
                            for line in bbann.opcodes:
                                print line
                                # for c in line:
                                #    sys.stdout.write(str(ord(c)))
                                # sys.stdout.write("\n")
                            print("============================")
                            continue
                        else:
                            # print("dbg: comparing bbs inst by inst, skipping one instruction at a time if not matching")
                            # min_l = min(bb_l, bbann_l)
                            # max_l = max(bb_l, bbann_l)
                            bb_printed = False
                            skip_ann = 0
                            skip_unann = 0
                            for i in range(1, bb_l + 1):
                                i *= -1
                                try:
                                    bb_ins = bb.opcodes[i + skip_unann]
                                    bbann_ins = bbann.opcodes[i + skip_ann]
                                    # skip epilog bbs, they are almost always different b/w ann and unann
                                    if asm_helper.is_ret(bb_ins) and asm_helper.is_ret(bbann_ins):
                                        break
                                    if bb_ins != bbann_ins:
                                        # implement skipping for just one instruction
                                        if bb.opcodes[i + skip_unann - 1] == bbann.opcodes[i + skip_ann]:
                                            skip_unann -= 1
                                        elif bb.opcodes[i + skip_unann] == bbann.opcodes[i + skip_ann - 1]:
                                            skip_ann -= 1
                                        else:
                                            j_i = get_jaccard_index(bb, bbann)
                                            if j_i < JACCARD_THRES_INSPECT:
                                                print("%s-bb#%d: Not near exact match. %f jaccard index" % (func,x,j_i))
                                                #print(func + "-bb#" + str(x) + "-ins#" + str(i) + ":")
                                                #print("bb: " + bb_ins + "(skip:" + str(skip_unann) + ")")
                                                #print("bbann: " + bbann_ins + "(skip:" + str(skip_ann) + ")")
                                                if not bb_printed:
                                                    bb_printed = True
                                                    print("-----------------------------")
                                                    print("bb#%d@%x:" % (x,bb.start_addr))
                                                    for line in bb.opcodes:
                                                        print line
                                                    print("-----------------------------")
                                                    print("bbann#%d@%x:" % (x,bbann.start_addr))
                                                    for line in bbann.opcodes:
                                                        print line
                                                    print("=============================")
                                                    sys.stdout.flush()
                                            break
                                except IndexError:
                                    break

    #print("bb's with probably prolog: %d" % bb_w_prolog_c)
    #print("bb's with probably prolog actually annotated: %d" % bb_w_prolog_ann_c)

def verify_bb_order_bb_bitshred(bbsann, bbs):
    func = ""
    for bb in bbsann:
        if bb.func != func:
            func = bb.func
            func_bbsann = get_bbs_for_func(bbsann, func)
            func_bbs = get_bbs_for_func(bbs, func)

            if len(func_bbs) != len(func_bbsann):
                print(func + " has different # of bbs b/w annotated and unannotated")
                print("func_bbs:")
                print_func_code(func_bbs)
                print("func_bbsann:")
                print_func_code(func_bbsann)
                print("============================")
                continue
            else:
                for x in range(0, len(func_bbs)):
                    #print("dbg: " + func + "-bb#" + str(x))
                    bb = func_bbs[x]
                    bbann = func_bbsann[x]
                    #for inst in bb.opcodes:
                    #   print inst
                    bbann_bs = bbann.get_bf(BITSHRED_W_SIZE, 0)
                    bb_bs = bbann.get_bf(BITSHRED_W_SIZE, 0)

                    if bb_bs.bitarray.count(True) > 0 and bbann_bs.bitarray.count(True) > 0:
                    #if bb.bitshred.bitarray.count(True) > 0 and bbann.bitshred.bitarray.count(True) > 0:
                        j_i = get_jaccard_index(bb, bbann)
                        if j_i < JACCARD_THRES_INSPECT:
                            print(str(j_i) + " for "+ func +"-bb#" + str(x) +" len:"+str(len(bbann.opcodes)))


def get_jaccard_index(bb, bbann):
    bbann_bs = bbann.get_bf(BITSHRED_W_SIZE, 0)
    bb_bs = bb.get_bf(BITSHRED_W_SIZE, 0)

    b_inter = bbann_bs.intersection(bb_bs)
    b_union = bbann_bs.union(bb_bs)
    #b_inter = bbann.bitshred.intersection(bb.bitshred)
    #b_union = bbann.bitshred.union(bb.bitshred)
    bits_inter = b_inter.bitarray.count(True)
    bits_union = b_union.bitarray.count(True)
    j_i = float(bits_inter) / float(bits_union)
    return j_i


def verify_bb_order_strict_per_inst(bbsann, bbs):
    func = ""
    for bb in bbsann:
        if bb.func != func:
            func = bb.func
            func_bbsann = get_bbs_for_func(bbsann, func)
            func_bbs = get_bbs_for_func(bbs, func)

            if len(func_bbs) != len(func_bbsann):
                print(func + " has different # of bbs b/w annotated and unannotated")
                print("func_bbs:")
                print_func_code(func_bbs)
                print("func_bbsann:")
                print_func_code(func_bbsann)
                print("============================")
                continue
            else:
                for x in range(0, len(func_bbs)):
                    bb = func_bbs[x]
                    bbann = func_bbsann[x]
                    bb_l = len(bb.opcodes)
                    bbann_l = len(bbann.opcodes)
                    if bbann_l - bb_l > PROLOG_MAX_LENGTH or bbann_l - bb_l < 0:
                        #TODO: maybe find a way to skip to next func instead of bb
                        print("Sizing issue")
                        print("dbg: bb_l: " + str(bb_l))
                        print("dbg: bbann_l: " + str(bbann_l))
                        if bbann_l - bb_l > PROLOG_MAX_LENGTH:
                            print(func + "-bb#" + str(x) + " bbann prologue is too big")
                        elif bbann_l - bb_l < 0:
                            print(func + "-bb#" + str(x) + " bb bigger than bbann")
                        print("bb:")
                        for line in bb.opcodes:
                            print line
                            #for c in line:
                            #    sys.stdout.write(str(ord(c)))
                            #sys.stdout.write("\n")
                        print("bbann:")
                        for line in bbann.opcodes:
                            print line
                            #for c in line:
                            #    sys.stdout.write(str(ord(c)))
                            #sys.stdout.write("\n")
                        print("============================")
                        continue
                    else:
                        #print("dbg: comparing bbs inst by inst, skipping one instruction at a time if not matching")
                        #min_l = min(bb_l, bbann_l)
                        #max_l = max(bb_l, bbann_l)
                        bb_printed = False
                        skip_ann = 0
                        skip_unann = 0
                        for i in range(1, bb_l+1):
                            i *= -1
                            try:
                                bb_ins = bb.opcodes[i+skip_unann]
                                bbann_ins = bbann.opcodes[i+skip_ann]
                                #skip epilog bbs, they are almost always different b/w ann and unann
                                if asm_helper.is_ret(bb_ins) and asm_helper.is_ret(bbann_ins):
                                    break
                                if bb_ins != bbann_ins:
                                    #implement skipping for just one instruction
                                    if bb.opcodes[i+skip_unann-1] == bbann.opcodes[i+skip_ann]:
                                        skip_unann -= 1
                                    elif bb.opcodes[i+skip_unann] == bbann.opcodes[i+skip_ann-1]:
                                        skip_ann -= 1
                                    else:
                                        print(func + "-bb#" + str(x) + "-ins#" + str(i) + ":")
                                        print("bb: " + bb_ins + "(skip:" + str(skip_unann) + ")")
                                        print("bbann: " + bbann_ins + "(skip:" + str(skip_ann) + ")")
                                        if not bb_printed:
                                            bb_printed = True
                                            print("-----------------------------")
                                            print("bb#" + str(x) + ":")
                                            for line in bb.opcodes:
                                                print line
                                            print("-----------------------------")
                                            print("bbann#" + str(x) + ":")
                                            for line in bbann.opcodes:
                                                print line
                                        print("=============================")
                                        sys.stdout.flush()
                                        continue
                            except IndexError:
                                break


def get_bbs_for_func(bbs, func):
    func_bbs = list()
    func_found = False
    for bb in bbs:
        if bb.func == func:
            func_found = True
            func_bbs.append(bb)
        elif bb.func != func and func_found:
            return func_bbs
    return func_bbs


def print_bb_code(bb):
    for line in bb.opcodes:
        print(line)
    return


def print_func_code(bbs):
    x = 0
    for bb in bbs:
        print(str(x)+": ")
        print_bb_code(bb)
        x += 1
    return


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Please supply an annotated list of basic blocks for the first argument, and the unannotated list of "
              "basic blocks of the same binary as the second option")
        sys.exit(1)
    bbsannf = open(sys.argv[1], 'rb')
    bbsf = open(sys.argv[2], 'rb')

    bbsann = pickle.load(bbsannf)
    bbs = pickle.load(bbsf)

    verify_bb_order_hybrid_ann_only(bbsann, bbs)
    #verify_bb_order_bb_bitshred(bbsann, bbs)