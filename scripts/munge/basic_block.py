import pybloom

ANN_NONE = 0
ANN_ORIGINAL = 1
ANN_ALTERED = 2
ANN_SKIP = 3

class BasicBlockSeq(object):
    def __init__(self, index, start_addr):
        self.index = index
        self.annotated = None
        self.start_addr = start_addr #TODO: change to h_start sometime
        self.end_addr = None
        self.opcodes = list()
        self.func = ""
        self.h_last = None
        self.end_mnem = ""
        #self.bitshred = pybloom.BloomFilter(capacity=10000, error_rate=0.001)
        #self.dbg_windows = list()
        #self.next_bb = None
        #self.prev_bb = prev_bb

    def add_bf(self, w_size, offset):
        for i in range(-1+offset, (len(self.opcodes) - w_size)*-1, -1):
            window = ""
            for asm in self.opcodes[i:i - w_size:-1]:
                window += asm + "\n"
            #print("dbg: window:\n%s" % window)
            #self.dbg_windows.append(window)
            self.bitshred.add(window)

    def get_bf(self, w_size, offset):
        bitshred = pybloom.BloomFilter(capacity=10000, error_rate=0.001)
        for i in range(-1+offset, (len(self.opcodes) - w_size)*-1, -1):
            window = ""
            for asm in self.opcodes[i:i - w_size:-1]:
                window += asm + "\n"
            #print("dbg: window:\n%s" % window)
            #self.dbg_windows.append(window)
            bitshred.add(window)

        return bitshred