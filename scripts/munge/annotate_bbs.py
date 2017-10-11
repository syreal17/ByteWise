import pickle
from idaapi import *
from idautils import *
from idc import *
import basic_block
import asm_helper
require("basic_block")

BATCH_MODE = True
DEBUG_COUNT = True

SEARCH_DONE = 30
SEARCH_SUCCESS = 31
FIRST_OPND = 0
SECOND_OPND = 1
LARGE_BASE = 0x1000  # ltj: using a large base forces IDA to stop using alias for location
DEBUG_FUNCTIONS = False


def print_bbs_per_func(bbs):
    with open("funcs.bbs.txt", 'w') as funcs_file:
        checked_funcs = list()
        for bb in bbs:
            if bb.func not in checked_funcs:
                count,func_bb_start_addrs = find_bbs_for_func(bbs, bb.func)
                print("%s: %d @ %s" % (bb.func, count, func_bb_start_addrs))
                #print("%s: %d" % (bb.func, count))
                checked_funcs.append(bb.func)
                funcs_file.write("%s: %d\n" % (bb.func, count))


def find_bbs_for_func(bbs, func_str):
    func_bb_start_addrs = ""
    count = 0
    for bb in bbs:
        if bb.func == func_str and (bb.annotated == basic_block.ANN_ORIGINAL):
            func_bb_start_addrs += " " + str(hex(bb.start_addr))
            count += 1

    return count,func_bb_start_addrs


def get_c_str_at_offset(addr):
    c_str = ""
    b = Byte(addr)
    i = 0
    while b != 0:
        i += 1
        c_str += chr(b)
        b = Byte(addr+i)

    return c_str


def get_opcodes(start_addr, end_addr):
    opcodes = ""


def annotate_bbs(bbs):
    og_form = re.compile("^_*original_annotation$")
    alt_form = re.compile("^_*altered_annotation$")

    for bb in bbs:
        i_h = 0
        for h_ea in Heads(bb.start_addr, bb.end_addr):
            if i_h < SEARCH_DONE:
                mnem = GetMnem(h_ea)
                if (asm_helper.is_call(mnem)):
                    if (og_form.match(GetOpnd(h_ea, 0))):
                        bb.annotated = basic_block.ANN_ORIGINAL
                        i_h = SEARCH_SUCCESS
                    elif (alt_form.match(GetOpnd(h_ea, 0))):
                        bb.annotated = basic_block.ANN_ALTERED
                        i_h = SEARCH_SUCCESS

                i_h += 1
        if bb.annotated is None:
            bb.annotated = basic_block.ANN_NONE

    if DEBUG_COUNT:
        count_none = 0
        count_orig = 0
        count_alt = 0
        count_unkn = 0
        for bb in bbs:
            if bb.annotated == basic_block.ANN_NONE:
                #print("ANN_NONE")
                count_none += 1
            elif bb.annotated == basic_block.ANN_ALTERED:
                #print("ANN_ALTERED")
                count_alt += 1
            elif bb.annotated == basic_block.ANN_ORIGINAL:
                #print("ANN_ORIGINAL")
                count_orig += 1
            else:
                #print("Unknown")
                count_unkn += 1

        print("Summary of obfuscated basic blocks:")
        print("Original: " + str(count_orig))
        print("Altered: " + str(count_alt))
        print("None: " + str(count_none))
        print("Unknown: " + str(count_unkn))


def annotate_bbs_old(bbs):
    origannstr = ""
    altannstr = ""
    segformat = re.compile("^[a-zA-Z\ ]*cs:[0-9A-Fa-f]+h$")
    offformat = re.compile("^[0-9A-Fa-f]+h$")
    dynformat = re.compile("^\[[a-z0-9]?[a-z0-9]?[a-z0-9]?\*[0-9]*\+[0-9A-Fa-f]+h\]$")
    segoff = ""
    pfformat = re.compile("^_*printf$")

    for bb in bbs:
        i_h = 0
        for h_ea in Heads(bb.start_addr, bb.end_addr):
            if i_h < SEARCH_DONE:
                mnem = GetMnem(h_ea)
                #TODO: how to make applicable to 3 op code? API Underlying isOff1??
                if (asm_helper.is_lea(mnem) or asm_helper.is_mov(mnem)) and isOff1(GetFlags(h_ea)):
                    strname = GetOpnd(h_ea, SECOND_OPND)
                    if strname == origannstr:
                        bb.annotated = basic_block.ANN_ORIGINAL
                        i_h = SEARCH_SUCCESS
                    if strname == altannstr:
                        bb.annotated = basic_block.ANN_ALTERED
                        i_h = SEARCH_SUCCESS
                    OpOff(h_ea, SECOND_OPND, LARGE_BASE)  # convert to offset
                    segoff = GetOpnd(h_ea, SECOND_OPND)
                    OpOff(h_ea, SECOND_OPND, 0)
                    if segformat.match(segoff):
                        offset = segoff.split(":")[1]
                    elif offformat.match(segoff):
                        offset = segoff
                    elif dynformat.match(segoff):
                        continue
                    else:
                        #print("Offset at %x converted to unrecognized format" % h_ea)
                        #raise FormatError(-1)
                        continue

                    offset = offset[:-1]
                    c_str = get_c_str_at_offset(int(offset, 16))
                    if c_str == "originalBBStartAnnotation":
                        origannstr = strname
                        bb.annotated = basic_block.ANN_ORIGINAL
                        #bb.add_bf(5, i_h + 1) #ltj:move to after call printf, but other code still interleaved...?
                        i_h = SEARCH_SUCCESS
                    elif c_str == "alteredBBStartAnnotation":
                        altannstr = strname
                        bb.annotated = basic_block.ANN_ALTERED
                        #bb.add_bf(5, i_h + 1) #ltj:move to after call printf, but other code still interleaved...?
                        i_h = SEARCH_SUCCESS
                i_h += 1
        if bb.annotated is None:
            bb.annotated = basic_block.ANN_NONE

    if DEBUG_COUNT:
        count_none = 0
        count_orig = 0
        count_alt = 0
        count_unkn = 0
        for bb in bbs:
            if bb.annotated == basic_block.ANN_NONE:
                #print("ANN_NONE")
                count_none += 1
            elif bb.annotated == basic_block.ANN_ALTERED:
                #print("ANN_ALTERED")
                count_alt += 1
            elif bb.annotated == basic_block.ANN_ORIGINAL:
                #print("ANN_ORIGINAL")
                count_orig += 1
            else:
                #print("Unknown")
                count_unkn += 1

        print("Summary of obfuscated basic blocks:")
        print("Original: " + str(count_orig))
        print("Altered: " + str(count_alt))
        print("None: " + str(count_none))
        print("Unknown: " + str(count_unkn))

if __name__ == '__main__':
    print("Annotating basic blocks from annotated binary...")
    if len(ARGV) < 3:
        print("You must specify path to saved, unannotated basic block list as first parameter.")
        print("You must specify path to save annotated basic block list as second parameter.")
        print("You may indicate -DEBUG_FUNCTIONS as an optional third parameter.")
        Exit(1)

    autoWait()

    if len(ARGV) >= 4:
        if ARGV[3] == "-DEBUG_FUNCTIONS":
            DEBUG_FUNCTIONS = True

    with open(ARGV[1], 'rb') as fr:
        bbs = pickle.load(fr)

        with open("bb.starts.txt", "w") as bb_starts:
            for bb in bbs:
                bb_starts.write("%x\n" % bb.start_addr)

        annotate_bbs(bbs)

        with open(ARGV[2], 'wb') as fw:
            pickle.dump(bbs, fw)

        print("%s saved" % ARGV[2])

        if DEBUG_FUNCTIONS:
            print("Printing bbs per funcs")
            print_bbs_per_func(bbs)

        print("Finished")
        if BATCH_MODE:
            Exit(0)