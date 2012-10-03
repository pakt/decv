import os 
from config import *

#for arithmetic ops:
#e1 = s.pop()
#e2 = s.pop()
#e = e1 op e2
#s.push(e)
#s.push(new eflags)
REG_DICT = {0: "ebp", 1: "ebx", 2: "ecx", 3: "edi", 4: "esi", 5: "edx", 6: "eax", 7: "eflags"}

class VM_Instruction:
    def __init__(self):
        if hasattr(self, "fn"):     #fn is defined only in subclasses
            self.src = self.load_src(self.fn)
        name = self.__class__.__name__
        vid = name.replace("VM_", "")
        self.vid = vid
        self.param = None

    def load_src(self, fn):
        fn = os.path.join(CLEAN_HANDLERS_DIR, fn)
        f = open(fn)
        src = f.read()
        f.close()
        return src

    def disasm(self, param=None):
        o = "%s"%(self.vid)
        if param != None:
            o += " param: %s"%hex(param)
        return o

    def pre_disasm(self):
        vid = self.vid
        param = self.param
        param_size = self.param_size
        off = self.code_off

        param_s = ""
        if param != None:
            if param_size == 1: param_s = "%02x"%param
            elif param_size == 2: param_s = "%04x"%param
            elif param_size == 4: param_s = "%08x"%param
            else: assert(False)
            
        if param != None:
            s = "%s[%s]"%(vid, param_s)
        else:
            s = vid

        sep = "\t\t"
        if param_size == 4:
            sep = "\t"

        o = "0x%08x %s%s"%(off, s, sep)
        return o
    
    def all_disasm(self):
        pre = self.pre_disasm()
        dis = self.disasm(self.param)
        s = "%s %s"%(pre, dis)
        return s

    def is_halt(self):
        return False

    def affects_ctx(self):
        return False

    def is_branch(self):
        assert(False)
    
    #only IFJMP will have these 2 methods below
    def true_branch(self):
        assert(False)

    def false_branch(self):
        assert(False)

class VM_Inst_With_Suff(VM_Instruction):
    def __init__(self):
        assert(hasattr(self, "mnem"))
        assert(self.size in [8, 16, 32])
        self.size_dict = {8: "byte", 16: "word", 32: "dword"}
        VM_Instruction.__init__(self)

    def disasm(self, param):
        size = self.size_dict[self.size]
        o = "%s %s"%(self.mnem, size)
        return o

