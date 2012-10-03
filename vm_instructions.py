from op_classes import *
from vmi_top_common import *
from vmi_auto_gen import *

class VM_000(VM_Instruction):
    def __init__(self):
        self.fn = "000.txt"
        VM_Instruction.__init__(self)

    def disasm(self, param):
        o = "load ptr %s"%REG_DICT[param]
        return o

class VM_001(VM_Instruction):
    def __init__(self):
        self.fn = "001.txt"
        VM_Instruction.__init__(self)

    def disasm(self, param):
        o = "store addr"
        return o

#top: load ptr reg (pointer to value holding reg's value)
class VM_Load(VM_Inst_With_Suff):
    def __init__(self):
        self.mnem = "load"
        VM_Inst_With_Suff.__init__(self)

    def disasm(self, param):
        d = VM_Inst_With_Suff.disasm(self, param)
        d += " %s"%hex(param)
        return d

class VM_006(VM_Instruction):
    def __init__(self):
        self.fn = "006.txt"
        VM_Instruction.__init__(self)

    def disasm(self, param):
        o = "add. dword"
        return o

class VM_009(VM_Instruction):
    def __init__(self):
        self.fn = "009.txt"
        VM_Instruction.__init__(self)

    def disasm(self, param):
        o = "load addr"
        return o

class VM_013(VM_Instruction):
    def __init__(self):
        self.fn = "013.txt"
        VM_Instruction.__init__(self)
    
    def disasm(self, param):
        o = "load ptr; store dword [ptr]"

class VM_015(VM_Instruction):
    def __init__(self):
        self.fn = "015.txt"
        VM_Instruction.__init__(self)
    
    def disasm(self, param):
        o = "store addr"

#top: store [addr]
class VM_Store(VM_Inst_With_Suff):
    def __init__(self):
        self.mnem = "store"
        VM_Inst_With_Suff.__init__(self)

    def disasm(self, param):
        d = VM_Inst_With_Suff.disasm(self, param)
        d += " [addr]"
        return d

class VM_019(VM_Store):
    def __init__(self):
        self.fn = "019.txt"
        self.size = 32
        VM_Store.__init__(self)

class VM_026(VM_Instruction):
    def __init__(self):
        self.fn = "026.txt"
        VM_Instruction.__init__(self)

    def disasm(self, param):
        o = "sub. dword"
        return o

class VM_048(VM_Instruction):
    def __init__(self):
        self.fn = "048.txt"
        VM_Instruction.__init__(self)

class VM_049(VM_Instruction):
    def __init__(self):
        self.fn = "049.txt"
        VM_Instruction.__init__(self)

class VM_04d(VM_Instruction):
    def __init__(self):
        self.fn = "04d.txt"
        VM_Instruction.__init__(self)

class VM_06f(VM_Instruction):
    def __init__(self):
        self.fn = "06f.txt"
        VM_Instruction.__init__(self)

class VM_070(VM_Instruction):
    def __init__(self):
        self.fn = "070.txt"
        VM_Instruction.__init__(self)

class VM_071(VM_Instruction):
    def __init__(self):
        self.fn = "071.txt"
        VM_Instruction.__init__(self)

class VM_07b(VM_Instruction):
    def __init__(self):
        self.fn = "07b.txt"
        VM_Instruction.__init__(self)

class VM_080(VM_Instruction):
    def __init__(self):
        self.fn = "080.txt"
        VM_Instruction.__init__(self)

class VM_081(VM_Instruction):
    def __init__(self):
        self.fn = "081.txt"
        VM_Instruction.__init__(self)

class VM_085(VM_Instruction):
    def __init__(self):
        self.fn = "085.txt"
        VM_Instruction.__init__(self)

class VM_087(VM_Instruction):
    def __init__(self):
        self.fn = "087.txt"
        VM_Instruction.__init__(self)

class VM_08b(VM_Instruction):
    def __init__(self):
        self.fn = "08b.txt"
        VM_Instruction.__init__(self)

class VM_08f(VM_Instruction):
    def __init__(self):
        self.fn = "08f.txt"
        VM_Instruction.__init__(self)

class VM_093(VM_Instruction):
    def __init__(self):
        self.fn = "093.txt"
        VM_Instruction.__init__(self)
    
class VM_097(VM_Instruction):
    def __init__(self):
        self.fn = "097.txt"
        VM_Instruction.__init__(self)

class VM_09b(VM_Instruction):
    def __init__(self):
        self.fn = "09b.txt"
        VM_Instruction.__init__(self)

class VM_09f(VM_Instruction):
    def __init__(self):
        self.fn = "09f.txt"
        VM_Instruction.__init__(self)

class VM_0a3(VM_Instruction):
    def __init__(self):
        self.fn = "0a3.txt"
        VM_Instruction.__init__(self)

class VM_0cd(VM_Instruction):
    def __init__(self):
        self.fn = "0cd.txt"
        VM_Instruction.__init__(self)
    
    def disasm(self, param):
        return "bswap"

class VM_14a(VM_Instruction):
    def __init__(self):
        self.fn = "14a.txt"
        VM_Instruction.__init__(self)

class VM_14b(VM_Instruction):
    def __init__(self):
        self.fn = "14b.txt"
        VM_Instruction.__init__(self)

class VM_14c(VM_Instruction):
    def __init__(self):
        self.fn = "14c.txt"
        VM_Instruction.__init__(self)

class VM_14d(VM_Instruction):
    def __init__(self):
        self.fn = "14d.txt"
        VM_Instruction.__init__(self)

class VM_14e(VM_Instruction):
    def __init__(self):
        self.fn = "14e.txt"
        VM_Instruction.__init__(self)

    def disasm(self, param):
        o = "move addr, STACK" #stack = current esp
        return o

class VM_14f(VM_Instruction):
    def __init__(self):
        self.fn = "14f.txt"
        VM_Instruction.__init__(self)

class VM_150(VM_Instruction):
    def __init__(self):
        self.fn = "150.txt"
        VM_Instruction.__init__(self)

class VM_151(VM_Instruction):
    def __init__(self):
        self.fn = "151.txt"
        VM_Instruction.__init__(self)

class VM_152(VM_Instruction):
    def __init__(self):
        self.fn = "152.txt"
        VM_Instruction.__init__(self)

class VM_153(VM_Instruction):
    def __init__(self):
        self.fn = "153.txt"
        VM_Instruction.__init__(self)

# lodsd
# add esi, eax
# mov ebx, 0
class VM_154(VM_Instruction):
    def __init__(self):
        self.fn = "154.txt"
        VM_Instruction.__init__(self)

    def disasm(self, param):
        o = "jmp $+%s"%hex(param)
        return o
    
    def affects_ctx(self):
        return True
    
    def update_ctx(self, ctx, vm_code, param):
        assert(param != None)
        vm_code.advance(param)
        ctx.set_reg(EBX, 0)

class VM_155(VM_Instruction):
    def __init__(self):
        self.fn = "155.txt"
        VM_Instruction.__init__(self)
    
    def disasm(self, param):
        cond = param & 0x7f
        o = "check_cond 0x%02x"%cond
        return o

#jmp iff [edi+20h] == 1
class VM_156(VM_Instruction):
    def __init__(self):
        self.fn = "156.txt"
        VM_Instruction.__init__(self)
    
    def disasm(self, param):
        o = "cond_jmp $+%s"%hex(param)
        return o

class VM_157(VM_Instruction):
    def __init__(self):
        self.fn = "157.txt"
        VM_Instruction.__init__(self)
    
    def disasm(self, param):
        o = "157 param: 0x%02x"%param
        return o

class VM_158(VM_Instruction):
    def __init__(self):
        self.fn = "158.txt"
        VM_Instruction.__init__(self)

class VM_15a(VM_Instruction):
    def __init__(self):
        self.fn = "15a.txt"
        VM_Instruction.__init__(self)

class VM_15d(VM_Instruction):
    def __init__(self):
        self.fn = "15d.txt"
        VM_Instruction.__init__(self)

class VM_15e(VM_Instruction):
    def __init__(self):
        self.fn = "15e.txt"
        VM_Instruction.__init__(self)

class VM_15f(VM_Instruction):
    def __init__(self):
        self.fn = "15f.txt"
        VM_Instruction.__init__(self)

class VM_160(VM_Instruction):
    def __init__(self):
        self.fn = "160.txt"
        VM_Instruction.__init__(self)

    def disasm(self, param):
        o = "xor. dword"
        return o

#set ebx=0
class VM_161(VM_Instruction):
    def __init__(self):
        self.fn = "161.txt"
        VM_Instruction.__init__(self)
    
    def disasm(self, param):
        return "reset_key"

    def affects_ctx(self):
        return True

    def update_ctx(self, ctx, vm_code, param):
        ctx.set_reg(EBX, 0)

class VM_200(VM_Instruction):
    def __init__(self):
        self.fn = "200.txt"
        VM_Instruction.__init__(self)
    
    def disasm(self, param):
        o = "load ptr; load dword; [ptr] = dword"
        return o

class VM_201(VM_Instruction):
    def __init__(self):
        self.fn = "201.txt"
        VM_Instruction.__init__(self)

    def disasm(self, param):
        o = "xor addr, 0x%08x"%param
        return o

class VM_202(VM_Instruction):
    def __init__(self):
        self.fn = "202.txt"
        VM_Instruction.__init__(self)

class VM_203(VM_Instruction):
    def __init__(self):
        self.fn = "203.txt"
        VM_Instruction.__init__(self)

class VM_204(VM_Instruction):
    def __init__(self):
        self.fn = "204.txt"
        VM_Instruction.__init__(self)
    
    def disasm(self, param):
        o = "load TMP"
        return o

class VM_205(VM_Instruction):
    def __init__(self):
        self.fn = "205.txt"
        VM_Instruction.__init__(self)

    def disasm(self, param):
        o = "store TMP"
        return o

class VM_206(VM_Instruction):
    def __init__(self):
        self.fn = "206.txt"
        VM_Instruction.__init__(self)

class VM_207(VM_Instruction):
    def __init__(self):
        self.fn = "207.txt"
        VM_Instruction.__init__(self)

    def disasm(self, param):
        o = "sub. addr, %s"%hex(param)
        return o

class VM_208(VM_Instruction):
    def __init__(self):
        self.fn = "208.txt"
        VM_Instruction.__init__(self)

    def disasm(self, param):
        o = "move STACK, [STACK]"
        return o

class VM_209(VM_Instruction):
    def __init__(self):
        self.fn = "209.txt"
        VM_Instruction.__init__(self)

    def disasm(self, param):
        o = "move addr, %s"%hex(param)
        return o

class VM_20a(VM_Instruction):
    def __init__(self):
        self.fn = "20a.txt"
        VM_Instruction.__init__(self)

class VM_20b(VM_Instruction):
    def __init__(self):
        self.fn = "20b.txt"
        VM_Instruction.__init__(self)

    def disasm(self, param):
        o = "add. addr, %s"%hex(param)
        return o

class VM_20d(VM_Instruction):
    def __init__(self):
        self.fn = "20d.txt"
        VM_Instruction.__init__(self)

class VM_20e(VM_Instruction):
    def __init__(self):
        self.fn = "20e.txt"
        VM_Instruction.__init__(self)

class VM_20f(VM_Instruction):
    def __init__(self):
        self.fn = "20f.txt"
        VM_Instruction.__init__(self)

# xchg edx, [esp[
class VM_210(VM_Instruction):
    def __init__(self):
        self.fn = "210.txt"
        VM_Instruction.__init__(self)

    def disasm(self, param):
        o = "xchg [STACK], addr"
        return o

#add reg to edx
class VM_211(VM_Instruction):
    def __init__(self):
        self.fn = "211.txt"
        VM_Instruction.__init__(self)

    def disasm(self, param):
        o = "add_reg_to_addr"
        if param == 7:
            reg = "esp"
        else:
            reg = REG_DICT[param]
        o += " %s"%reg
        return o

# vm_exit ?
class VM_212(VM_Instruction):
    def __init__(self):
        self.fn = "212.txt"
        VM_Instruction.__init__(self)

    def is_halt(self):
        return True

    def disasm(self, param):
        o = "gtfo"
        return o

class VM_213(VM_Instruction):
    def __init__(self):
        self.fn = "213.txt"
        VM_Instruction.__init__(self)
    
    def disasm(self, param):
        o = "swap; store TMP"
        return o

# empty handler
class VM_214(VM_Instruction):
    def __init__(self):
        self.fn = "214.txt"
        VM_Instruction.__init__(self)
    
    def disasm(self, param=None):
        return "nop"

VM_INSTRUCTIONS_SET = [
        VM_000, VM_001, VM_002, VM_003, VM_004, VM_006, VM_007, VM_009, 
        VM_00a, VM_00b, VM_00c, VM_00e, VM_00f, VM_011, VM_012, VM_013,
        VM_015, VM_016, VM_017, VM_018, VM_019, VM_01a, VM_01b, VM_01c,
        VM_01e, VM_01f, VM_020, VM_022, VM_023, VM_024, VM_026, VM_027,
        VM_028, VM_029, VM_02c, VM_02d, VM_02f, VM_030, VM_031, VM_033,
        VM_034, VM_035, VM_037, VM_038, VM_039, VM_03b, VM_03c, VM_03d,
        VM_03f, VM_040, VM_041, VM_043, VM_044, VM_045, VM_048, VM_049,
        VM_04d, VM_053, VM_054, VM_055, VM_057, VM_058, VM_059, VM_05b,
        VM_05c, VM_05d, VM_05f, VM_060, VM_061, VM_063, VM_064, VM_065,
        VM_067, VM_068, VM_069, VM_06b, VM_06c, VM_06d, VM_06f, VM_070,
        VM_071, VM_073, VM_074, VM_075, VM_077, VM_078, VM_079, VM_07b,
        VM_080, VM_081, VM_085, VM_087, VM_08b, VM_08f, VM_093, VM_097,
        VM_09b, VM_09f, VM_0a3, VM_0a8, VM_0a9, VM_0ab, VM_0ac, VM_0af,
        VM_0b0, VM_0b3, VM_0b4, VM_0b7, VM_0b8, VM_0b9, VM_0bb, VM_0bc,
        VM_0bd, VM_0bf, VM_0c0, VM_0c1, VM_0c3, VM_0c4, VM_0c5, VM_0c7,
        VM_0c8, VM_0c9, VM_0cd, VM_0cf, VM_0d0, VM_0d1, VM_0d3, VM_0d4,
        VM_0d5, VM_14a, VM_14b, VM_14c, VM_14d, VM_14e, VM_14f, VM_150,
        VM_151, VM_152, VM_153, VM_154, VM_155, VM_156, VM_157, VM_158,
        VM_15a, VM_15d, VM_15e, VM_15f, VM_160, VM_161, VM_200, VM_201,
        VM_202, VM_203, VM_204, VM_205, VM_206, VM_207, VM_208, VM_209,
        VM_20a, VM_20b, VM_20c, VM_20d, VM_20e, VM_20f, VM_210, VM_211,
        VM_212, VM_213, VM_214
        ]
