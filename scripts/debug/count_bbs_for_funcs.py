import basic_block
import sys
import pickle


def count_bbs_for_funcs(bbs):
    func_name_to_count = dict()

    for bb in bbs:
        c_bytes = len(range(bb.start_addr, bb.end_addr + 1))
        func_name_to_count[bb.func] = func_name_to_count.get(bb.func, 0) + 1 #for counting bbs
        #func_name_to_count[bb.func] = func_name_to_count.get(bb.func, 0) + c_bytes  # for counting bytes

    return func_name_to_count

if __name__ == "__main__":
    bbsf = open(sys.argv[1], 'rb')
    bbs = pickle.load(bbsf)

    func_name_to_count = count_bbs_for_funcs(bbs)
    for func_name in func_name_to_count:
        print("%d = %s" % (func_name_to_count[func_name], func_name))