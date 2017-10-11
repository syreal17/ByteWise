import pickle
from idaapi import *
from idautils import *
from idc import *
import basic_block
import asm_helper
require("basic_block")
require("asm_helper")

BATCH_MODE = True
INCLUDE_FUNCTIONS = True
BITSHRED_W_SIZE = 3
INCLUDE_OPCODES = True
INCLUDE_BITSHRED = False    #ltj: warning: makes bbs lists 300x larger
INDIVISBLE_BB = True        #ltj: doesn't divide any basic blocks for any jump into a non-entry instruction


def get_operand_generalization(o_type):
    if o_type == o_crb:
        return "CRB"
    elif o_type == o_creg:
        return "CREG"
    elif o_type == o_creglist:
        return "CREGLIST"
    elif o_type == o_crf:
        return "CRF"
    elif o_type == o_crreg:
        return "CRREG"
    elif o_type == o_dbreg:
        return "DBREG"
    elif o_type == o_dcr:
        return "DCR"
    elif o_type == o_displ:
        return "DISPL"
    elif o_type == o_far:
        return "FAR"
    elif o_type == o_fpreg:
        return "FPREG"
    elif o_type == o_fpreg_arm:
        return "FPREG_ARM"
    elif o_type == o_fpreglist:
        return "FPREGLIST"
    elif o_type == o_idpspec0:
        return "IDPSPEC0"
    elif o_type == o_idpspec1:
        return "IDPSPEC1"
    elif o_type == o_idpspec2:
        return "IDPSPEC2"
    elif o_type == o_idpspec3:
        return "IDPSPEC3"
    elif o_type == o_idpspec4:
        return "IDPSPEC4"
    elif o_type == o_idpspec5:
        return "IDPSPEC5"
    elif o_type == o_imm:
        return "IMM"
    elif o_type == o_mem:
        return "MEM"
    elif o_type == o_mmxreg:
        return "MMXREG"
    elif o_type == o_near:
        return "NEAR"
    elif o_type == o_phrase:
        return "PHRASE"
    elif o_type == o_reg:
        return "REG"
    elif o_type == o_reglist:
        return "REGLIST"
    elif o_type == o_shmbme:
        return "SHMBME"
    elif o_type == o_spr:
        return "SPR"
    elif o_type == o_text:
        return "TEXT"
    elif o_type == o_trreg:
        return "TRREG"
    elif o_type == o_twofpr:
        return "TWOFPR"
    elif o_type == o_void:
        return "VOID"
    elif o_type == o_xmmreg:
        return "XMMREG"
    else:
        return "OTHER"

def add_opcode(bb, h_bb, mnem, op1, op1type, op2, op2type, op3, op3type):
    #varform = re.compile("^\[rbp\+var_.*$")W

    if INCLUDE_OPCODES:

        if op1 == "" and op2 == "" and op3 == "":
            # print("dbg: added no operand instruction, mnem:" + mnem + " @ " + str(hex(h_bb)))
            bb.opcodes.append(mnem + ";")

        elif op1 != "" and op2 == "" and op3 == "":
            op1 = get_operand_generalization(op1type)
            bb.opcodes.append(mnem + " " + op1 + ";")

        elif op1 == "" and op2 != "" and op3 == "":
            op2 = get_operand_generalization(op1type)
            bb.opcodes.append(mnem + " " + op2 + ";")

        elif op1 != "" and op2 != "" and op3 == "":
            # TODO: ltj: take this out as one instruction skipping covers this
            # if asm_helper.is_mov(mnem):
            #    if asm_helper.is_reg_a(op2):
            #        if varform.match(op1):
            #            return
            op1 = get_operand_generalization(op1type)
            op2 = get_operand_generalization(op2type)
            bb.opcodes.append(mnem + " " + op1 + " " + op2 + ";")

        elif op1 != "" and op2 == "" and op3 != "":
            op1 = get_operand_generalization(op1type)
            op3 = get_operand_generalization(op3type)
            bb.opcodes.append(mnem + " " + op1 + " " + op3 + ";")

        elif op1 != "" and op2 != "" and op3 != "":
            op1 = get_operand_generalization(op1type)
            op2 = get_operand_generalization(op2type)
            op3 = get_operand_generalization(op3type)
            bb.opcodes.append(mnem + " " + op1 + " " + op2 + " " + op3 + ";")

        else:
            print("Unconventional instruction at " + hex(h_bb))


def bbify(textEa, out_filepath):
    #dbgf = open("bbify.debug.txt", "w")
    bbs = list()
    new_bb = basic_block.BasicBlockSeq(0, textEa)
    bbs.append(new_bb)
    end_bb = False
    for h_ea in Heads(SegStart(textEa), SegEnd(textEa)):
        #dbgf.writelines(str(hex(h_ea)) + "\n")
        #dbgf.flush()
        if end_bb:
            #dbgf.writelines("end old bb and start new one\n")
            #dbgf.flush()
            end_bb = False
            old_bb = new_bb
            new_bb = None
            if INCLUDE_FUNCTIONS:
                old_bb.func = GetFunctionName(old_bb.start_addr)
            old_bb.end_addr = h_ea - 1
            for h_bb in Heads(old_bb.start_addr, old_bb.end_addr+1):
                mnem = GetMnem(h_bb)
                op1 = GetOpnd(h_bb, 0)
                op1type = GetOpType(h_bb, 0)
                op2 = GetOpnd(h_bb, 1)
                op2type = GetOpType(h_bb, 1)
                op3 = GetOpnd(h_bb, 2)
                op3type = GetOpnd(h_bb, 2)
                add_opcode(old_bb, h_bb, mnem, op1, op1type, op2, op2type, op3, op3type)
            if INCLUDE_BITSHRED:
                old_bb.add_bf(BITSHRED_W_SIZE, 0)

        #dbgf.writelines("check if skippable code\n")
        #dbgf.flush()
        if isData(GetFlags(h_ea)):# or GetFunctionFlags(h_ea) & FUNC_LIB != 0:
            #dbgf.writelines("skipping code\n")
            #dbgf.flush()
            continue

        #dbgf.writelines("about to check if start new bb\n")
        #dbgf.flush()
        if new_bb is None:
            #dbgf.writelines("starting new bb\n")
            #dbgf.flush()
            new_bb = basic_block.BasicBlockSeq(len(bbs), h_ea)
            #dbgf.writelines("after construction, before appending\n")
            #dbgf.writelines("len of bbs: " + str(len(bbs)) + "\n")
            ##dbgf.flush()
            bbs.append(new_bb)


        ##dbgf.writelines("before ua_ana0\n")
        ##dbgf.flush()
        ua_ana0(h_ea)
        ##dbgf.writelines("after ua_ana0\n")
        ##dbgf.flush()
        if not INDIVISBLE_BB:
            if ida_idp.is_basic_block_end(False):
                new_bb.h_last = h_ea
                new_bb.end_mnem = GetMnem(h_ea)
                end_bb = True
        else:
            if asm_helper.is_jump(GetMnem(h_ea)) or asm_helper.is_ret(GetMnem(h_ea)):
                new_bb.h_last = h_ea
                new_bb.end_mnem = GetMnem(h_ea)
                end_bb = True

    ##dbgf.writelines("after for h_ea\n")
    ##dbgf.flush()
    #finishing last basic block if unfinished
    if new_bb.end_addr is None:
        new_bb.end_addr = SegEnd(textEa)
        for h_bb in Heads(new_bb.start_addr, new_bb.end_addr+1):
            mnem = GetMnem(h_bb)
            op1 = GetOpnd(h_bb, 0)
            op1type = GetOpType(h_bb, 0)
            op2 = GetOpnd(h_bb, 1)
            op2type = GetOpType(h_bb, 1)
            op3 = GetOpnd(h_bb, 2)
            op3type = GetOpType(h_bb, 2)
            add_opcode(new_bb, h_bb, mnem, op1, op1type, op2, op2type, op3, op3type)
        new_bb.h_last = h_bb
        if INCLUDE_BITSHRED:
            new_bb.add_bf(BITSHRED_W_SIZE, 0)

    ##dbgf.writelines("after adding possible last inst\n")
    ##dbgf.flush()
    with open(out_filepath, 'wb') as f:
        ##dbgf.writelines("before pickle\n")
        ##dbgf.flush()
        pickle.dump(bbs, f)

	#dbgf.close()
    print("%s saved" % out_filepath)
    return bbs

if __name__ == "__main__":
    autoWait()
    print("Starting to create sequential basic block list out of text section...")
    if len(ARGV) < 2:
        print("You must specify path to save basic block list as first parameter.")
        print("You can optionally include -INCLUDE_FUNCTIONS as the second argument.")
        Exit(1)

    textSel = SegByName(".text")
    textEa = SegByBase(textSel)

    if len(ARGV) >= 3:
        if ARGV[2] == "-INCLUDE_FUNCTIONS":
            INCLUDE_FUNCTIONS = True

    bbs = bbify(textEa, ARGV[1])

    print("...Finished")
    if BATCH_MODE:
        Exit(0)