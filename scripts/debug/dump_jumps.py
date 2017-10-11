import pickle
from idaapi import *
from idautils import *
from idc import *
import basic_block
import asm_helper
require("basic_block")
require("asm_helper")

if __name__ == "__main__":
    bbsannf = open(ARGV[1], 'rb')
    bbsann = pickle.load(bbsannf)

    autoWait()
    print("Dumping all jmps of binary text section to csv...")

    textSel = SegByName(".text")
    textEa = SegByBase(textSel)

    f = open('dumpjumpsNONE.csv', 'w')

    for bb in bbsann:
        if bb.annotated == basic_block.ANN_NONE:
            heads = list()
            for h_ea in Heads(bb.start_addr, bb.end_addr):
                heads.append(h_ea)

            start_ea = ""
            addr_print = False
            for ea in range(bb.start_addr, bb.end_addr):
                if ea in heads:
                    if asm_helper.is_jmp(GetMnem(ea)):
                        f.write("\n")
                        start_ea = ea
                        addr_print = False
                    else:
                        start_ea = ""

                if start_ea != "":
                    if not addr_print:
                        addr_print = True
                        f.write(str(hex(ea)+","))
                    if hasValue(GetFlags(ea)):
                        byte = Byte(ea)
                        f.write(str(hex(byte))+",")

    f.close()