import pickle
from idaapi import *
from idautils import *
from idc import *
import basic_block
import asm_helper
require("basic_block")
require("asm_helper")

if __name__ == "__main__":
    autoWait()
    print("Dumping all bytes of binary text section to csv...")

    textSel = SegByName(".text")
    textEa = SegByBase(textSel)

    f = open('bytes.csv', 'w')

    for ea in range(SegStart(textEa), SegEnd(textEa)):
        if hasValue(GetFlags(ea)):
            byte = Byte(ea)
            f.write(str(byte)+",\n")

    f.close()