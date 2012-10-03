import re
from common import *
from PyFlags import PyFlags

NOT_IMPLEMENTED = set(['lea', 'adc', 'bswap', 'bt', 'btc', 'btr', 'bts', 'cmp', 'div', 'idiv', 'imul', 'lods', 'movs', 'movsx', 'movzx', 'mul', 'popa', 'rcl', 'rcr', 'retn', 'rol', 'ror', 'sar', 'sbb', 'std'])

ESP = "esp"
EAX = "eax"
EBX = "ebx"
ESI = "esi"

EAX_REGS = set(["al", "ah", "ax", "eax"])
EBX_REGS = set(["bl", "bh", "bx", "ebx"])
ECX_REGS = set(["cl", "ch", "cx", "ecx"])
EDX_REGS = set(["dl", "dh", "dx", "edx"])
ESI_REGS = set(["si", "esi"])
EDI_REGS = set(["di", "edi"])
EBP_REGS = set(["bp", "ebp"])
ESP_REGS = set(["sp", "esp"])

UNSET_EAX_AFFECTED = {  "al": EAX_REGS-set(["ah"]),
                        "ah": EAX_REGS-set(["al"]),
                        "ax": EAX_REGS,
                        "eax": EAX_REGS
                        }
def unset_affected_aux(unset, patt, rep):
    new_unset = dict()
    for reg, affected in unset.iteritems():
        new_reg = reg.replace(patt, rep)
        new_unset[new_reg] = set(map(lambda r: r.replace(patt, rep), affected))
    return new_unset

def combine_unset_affected(reg_sets, aff_sets):
    combined = dict()
    for reg_set, aff_set in zip(reg_sets, aff_sets):
        for reg in reg_set:
            combined[reg] = aff_set
    return combined

UNSET_EBX_AFFECTED = unset_affected_aux(UNSET_EAX_AFFECTED, "a", "b") 
UNSET_ECX_AFFECTED = unset_affected_aux(UNSET_EAX_AFFECTED, "a", "c") 
UNSET_EDX_AFFECTED = unset_affected_aux(UNSET_EAX_AFFECTED, "a", "d") 
UNSET_ESI_AFFECTED = {"si": ESI_REGS, "esi": ESI_REGS}
UNSET_EDI_AFFECTED = {"di": EDI_REGS, "edi": EDI_REGS}
UNSET_EBP_AFFECTED = {"bp": EBP_REGS, "ebp": EBP_REGS}
UNSET_ESP_AFFECTED = {"sp": ESP_REGS, "esp": ESP_REGS}

RESET_EAX_AFFECTED = {  "eax": EAX_REGS,
                        "ax": EAX_REGS-set(["eax"]),
                        "ah": set(["ah"]),
                        "al": set(["al"])
                        }
RESET_EBX_AFFECTED = unset_affected_aux(RESET_EAX_AFFECTED, "a", "b") 
RESET_ECX_AFFECTED = unset_affected_aux(RESET_EAX_AFFECTED, "a", "c") 
RESET_EDX_AFFECTED = unset_affected_aux(RESET_EAX_AFFECTED, "a", "d") 
RESET_ESI_AFFECTED = {"si": ESI_REGS, "esi": ESI_REGS}
RESET_EDI_AFFECTED = {"di": EDI_REGS, "edi": EDI_REGS}
RESET_EBP_AFFECTED = {"bp": EBP_REGS, "ebp": EBP_REGS}
RESET_ESP_AFFECTED = {"sp": ESP_REGS, "esp": ESP_REGS}

REG_UNSET_AFFECTED_LIST = [ UNSET_EAX_AFFECTED, UNSET_EBX_AFFECTED, UNSET_ECX_AFFECTED, UNSET_EDX_AFFECTED,
                            UNSET_ESI_AFFECTED, UNSET_EDI_AFFECTED, UNSET_EBP_AFFECTED, UNSET_ESP_AFFECTED  
                            ]
REG_RESET_AFFECTED_LIST = [ RESET_EAX_AFFECTED, RESET_EBX_AFFECTED, RESET_ECX_AFFECTED, RESET_EDX_AFFECTED,
                            RESET_ESI_AFFECTED, RESET_EDI_AFFECTED, RESET_EBP_AFFECTED, RESET_ESP_AFFECTED  
                            ]

REG_LIST = [EAX_REGS, EBX_REGS, ECX_REGS, EDX_REGS, ESI_REGS, EDI_REGS, EBP_REGS, ESP_REGS]
REG_UNSET_AFFECTED = combine_unset_affected(REG_LIST, REG_UNSET_AFFECTED_LIST)
REG_RESET_AFFECTED = combine_unset_affected(REG_LIST, REG_RESET_AFFECTED_LIST)

REG_TO_REG_SET = combine_unset_affected(REG_LIST, REG_LIST)

REG_SET = reduce(lambda x,y: x|y, REG_LIST, set())

REG_8BIT = set(filter(lambda r: r[1] in ["l","h"], REG_SET))
REG_16BIT = set(filter(lambda r: len(r)==2 and r not in REG_8BIT, REG_SET))
REG_32BIT = REG_SET - REG_8BIT - REG_16BIT

F_SET_EAX = lambda reg_dict,reg,val: f_reg_set32(reg_dict, reg, val, "eax", "ax", "ah", "al")
F_SET_EBX = lambda reg_dict,reg,val: f_reg_set32(reg_dict, reg, val, "ebx", "bx", "bh", "bl")
F_SET_ECX = lambda reg_dict,reg,val: f_reg_set32(reg_dict, reg, val, "ecx", "cx", "ch", "cl")
F_SET_EDX = lambda reg_dict,reg,val: f_reg_set32(reg_dict, reg, val, "edx", "dx", "dh", "dl")
F_SET_ESI = lambda reg_dict,reg,val: f_reg_set32(reg_dict, reg, val, "esi", "si", None, None)
F_SET_EDI = lambda reg_dict,reg,val: f_reg_set32(reg_dict, reg, val, "edi", "di", None, None)
F_SET_EBP = lambda reg_dict,reg,val: f_reg_set32(reg_dict, reg, val, "ebp", "bp", None, None)
F_SET_ESP = lambda reg_dict,reg,val: f_reg_set32(reg_dict, reg, val, "esp", "sp", None, None)

FUN_SET_LIST = [(EAX_REGS, F_SET_EAX), (EBX_REGS, F_SET_EBX), (ECX_REGS, F_SET_ECX), (EDX_REGS, F_SET_EDX),
                (ESI_REGS, F_SET_ESI), (EDI_REGS, F_SET_EDI), (EBP_REGS, F_SET_EBP), (ESP_REGS, F_SET_ESP)]
                
CF = "CF" #carry
PF = "PF" #parity
AF = "AF" #auxiliary
ZF = "ZF" #zero
SF = "SF" #sign
OF = "OF" #overflow
FLAGS = [CF, PF, AF, ZF, SF, OF]

def set_reg_aux(values, reg, value):
    assert(reg in REG_SET)
    
    for reg_set, func_set in FUN_SET_LIST:
        if reg in reg_set:
            return func_set(values, reg, value)
    assert(False)

O_MEM = 0
O_REG = 1
O_IMM = 2
O_MEM_REG_PLUS_INDEX = 0x10
O_MEM_COMPLEX = 0x11

imm_re = re.compile("([0-9a-fA-F]+)h?")

def try_get_from_dict(dic, k):
    try:
        v = dic[k]
    except:
        v = None
    return v

def f_reg_upd32(mod_values, reg32, value):

    bit32v = try_get_from_dict(mod_values, reg32)
    if bit32v != None:
        bit32v = (bit32v & 0xFFFF0000) | value
        mod_values[reg32] = bit32v

    return mod_values

def f_reg_set8(values, reg, value):
    assert(reg in REG_8BIT)
    values[reg] = value
    return values

def f_reg_set16(values, reg, value, hi_bit8, lo_bit8):
    assert(reg in REG_16BIT)
    mod_values = values
    mod_values[reg] = value
    if hi_bit8:
        assert(lo_bit8 != None)
        mod_values = f_reg_set8(values, hi_bit8, value>>8)
        mod_values = f_reg_set8(mod_values, lo_bit8, value&0xFF)
    return mod_values

def f_reg_set32(values, reg, value, bit32, lo_bit16, hi_bit8, lo_bit8):
    if reg == bit32:
        value16 = value & 0xFFFF
        mod_values = f_reg_set16(values, lo_bit16, value16, hi_bit8, lo_bit8)
        mod_values[bit32] = value

    elif reg == lo_bit16:
        mod_values = f_reg_set16(values, reg, value, hi_bit8, lo_bit8)
        mod_values = f_reg_upd32(mod_values, bit32, value)

    elif reg in [lo_bit8, hi_bit8]:
        mod_values = f_reg_set8(values, reg, value)
        hi8v = try_get_from_dict(mod_values, hi_bit8)
        lo8v = try_get_from_dict(mod_values, lo_bit8)
        if hi8v != None and lo8v != None:
            lo16v = (hi8v<<8)|lo8v
            mod_values[lo_bit16] = lo16v
            mod_values = f_reg_upd32(mod_values, bit32, lo16v)
    else:
        print "bad reg to set:", reg
        assert(False)

    return mod_values


def is_special_case(dis):
    special_hints = ["pushf", "popf", "lods", "movs", "stos", "ret", "mul", "div"]
    for hint in special_hints:
        if dis.find(hint)>=0:
            return True
    return False

def special_read_mod_regs(dis):
    esi = set(ESI_REGS)
    edi = set(EDI_REGS)
    esi_edi = esi|edi
    eax = set(EAX_REGS)
    edx = set(EDX_REGS)
    esp = set(ESP_REGS)
    rep_reg = set()
    if dis.find("rep")>=0:
        rep_reg = set(ECX_REGS)
    
    if dis.find("movs")>=0:
        (read, mod) = (esi_edi, esi_edi)
    elif dis.find("stos")>=0:
        (read, mod) = (eax|edi, edi)
    elif dis.find("lods")>=0:
        (read, mod) = (esi, eax|esi)
    elif dis == "popa":
        (read, mod) = (esp,REG_SET)
    elif dis == "pusha":
        (read, mod) = (REG_SET,esp)
    elif dis.find("pushf")>=0 or dis.find("popf")>=0:
        (read, mod) = (esp, esp)
    elif dis.find("ret")>=0:
        (read, mod) = (esp, esp)
    elif dis.find("mul")>=0 or dis.find("div")>=0: 
        (read, mod) = (eax|edx, eax|edx)
    else:
        print dis
        assert(False)

    return (rep_reg|read, rep_reg|mod)

def bwd_variants(mnem):
    variants = []
    for bits, postfix in zip([8,16,32],["b","w","d"]):
        variants.append((mnem+postfix, bits))
    return variants

#FIXME(?): movzx, etc
def guess_bits(dis, addr, op1, op2):
    o = dis
    hints = [("small", 16), ("dword", 32), ("word", 16), ("byte", 8)]
    for hint,bits in hints:
        if o.find(hint)>=0:
            return bits
    
    reg_classes = [(REG_8BIT, 8), (REG_16BIT, 16), (REG_32BIT, 32)]
    ops = filter(lambda o: o != None, [op1, op2])
    for op in ops:
        if op.type == O_REG:
            reg = op.reg
            for reg_class, bits in reg_classes:
                if reg in reg_class:
                    return bits
    
    mnem = idc.GetMnem(addr)
    if mnem in ["pushf", "popf"]:
        return 8
    if mnem in ["push", "pop", "popa", "pusha", "std", "retn"]:
        return 32 #not important anyway


    dis = idc.GetDisasm(addr)
    hints = reduce(lambda l,mnem: l+bwd_variants(mnem), ["lods", "stos", "movs"], [])
    
    if is_jxx(addr):
        return 32

    for hint, bits in hints:
        if dis.find(hint)>=0:
            return bits

    print "can't guess bits of instruction @ %08x: %s"%(addr, mnem)
    assert(False)

##################################################
#  basic block for wrapped code
##################################################
class DBB(BB_):
    def __init__(self):
        BB_.__init__(self)

    def dump(self):
        l = []
        for inst in self.body:
            l.append(inst.dump())
        
        o = "DBB(%08x)\n"%self.get_addr()
        o += "\n".join(l)
        o += "\n"
        o += "#"*10
        o += "\n"
        return o
    
    def get_org_disasm(self):
        disasm = []
        for bb in self.body:
            disasm.append(bb.get_org_disasm())
        disasm = "\n".join(disasm)
        return disasm

    def set_body(self, new_body):
        if not self.get_addr():
            self.org_addr = new_body[0].get_addr()
        self.body = new_body

    def disasm(self):
        di = dfs(self, dbb_f_disasm)
        return di
    
    #remove conditional jump at the end and one instruction before it
    #return the result as new DBB
    def trim_jxx(self):
        assert(len(self.body) >= 2)

        i = self.body[-1]
        assert(i.is_jxx())

        dbb = DBB()
        new_body = self.body[:-2]
        dbb.set_body(new_body)
        
        return dbb
    
    def untrim_jxx(self, tdbb):
        new_body = tdbb.body + self.body[-2:]
        tdbb.set_body(new_body)
        return tdbb

    def true_branch(self):
        if self.child1 and self.child2:
            return self.child2
        elif self.child1 and not self.child2:
            return self.child1
        else:
            assert(False)
    
    def false_branch(self):
        if self.child1 and self.child2:
            return self.child1
        else:
            assert(False)

def dbb_f_disasm(acc, node, children):
    if acc == None:
        acc = ""
    acc += node.dump()
    return acc

##################################################
# main instruction wrapper 
##################################################
class Inst():
    
    def make_disasm(self, mnem, op1, op2, bits=0):
        t1 = t2 = comma = ""
        if op1: t1 = op1.text_org
        if op2:
            t2 = op2.text_org
            comma = ","
        #we don't want to have: mov eax, dword ptr [xyz] (dword ptr is redundant)
        if mnem == "mov" and (op2.type == O_MEM or (op1.type == O_MEM and op2.type == O_REG)):
            t1 = self.clean_disasm(t1)
            t2 = self.clean_disasm(t2)
        elif bits != 0:
            if mnem == "lods": 
                assert(bits in [8,16,32])
                l = ["b","w","LOL","d"]
                mnem = "lods" + l[(bits/8)-1]
            elif ((op1 and op2 and op1.type == O_MEM and op2.type == O_IMM) or
                    (op1 and not op2 and op1.type == O_MEM)):
                ptr = self.bits_text(bits)
                t1 = self.clean_disasm(t1)
                t1 = "%s %s"%(ptr, t1)
        
        dis = "%s %s%s %s"%(mnem, t1, comma, t2)
        dis = dis.strip()
        return dis
    
    def get_org_disasm(self):
        disasm = self.make_disasm(self.mnem, self.op1, self.op2, bits=self.bits)
        return disasm

    def update_disasm(self):
        self.dis = self.make_disasm(self.mnem, self.op1, self.op2, bits=self.bits)
        self.clean_dis = self.clean_disasm(self.dis)

    def clean_disasm(self, dis):
        dis = re.sub("(dword ptr |word ptr |byte ptr |small )", "", dis)
        dis = re.sub("\s+", " ", dis)
        return dis
    
    def get_clean_dis(self):
        #return self.clean_disasm(self.dis)
        return self.clean_dis

    # True in Branch instrunctions (JMP/Jcc)
    def is_jxx(self):
        return False

    # True only in Jxx()
    def is_cond_jmp(self):
        return False

    def __init__(self, addr, mnem, op1, op2, bits=0):
        self.read_regs = set()
        self.modified_regs = set()
        self.modified_flags = set()
        self.op1 = None
        self.op2 = None

        self.mnem = mnem
        self.op1 = op1
        self.op2 = op2
        self.addr = addr

        dis = idc.GetDisasm(addr)
        if dis == "":
            dis = self.make_disasm(mnem, op1, op2)
        self.dis = dis

        if bits == 0:
            self.bits = guess_bits(dis, addr, op1, op2)
        else:
            self.bits = bits

        #guessbits uses hints for determining size, so clean here
        self.dis = self.clean_disasm(dis)
        self.clean_dis = self.dis
    
        #override this behavior in subclasses!!!

        if op1 and op1.type != O_MEM: 
            self.modified_regs = op1.regs

        if op1 and op2:
            self.read_regs = op2.regs.union(op1.regs)

        elif op1 and not op2:
            self.read_regs = op1.regs

        elif not op1 and op2:
            # GetOpnd("imul cx", 0) -> None
            # GetOpnd("imul cx", 1) -> "cx"
            # just switch args..
            if mnem in ["imul", "mul", "idiv", "div"]:
                self.op1 = op2
                self.op2 = None
                self.read_regs = op2.regs
            else:
                print "op2 but no op1:", mnem, op2.text
                assert(False)

        else:
            #print "no arg. instr:", mnem
            pass
        
        dis = self.dis
        if is_special_case(dis):
            (read, mod) = special_read_mod_regs(dis)
            self.read_regs |= read
            self.modified_regs |= mod
    
    def update_ops(self, new_op1, new_op2, bits=None):
        if bits == None:
            bits = self.bits
        self.__init__(FAKE_INSTR_ADDR, self.mnem, new_op1, new_op2, bits)

    def update_op2(self, new_op2):
        assert(new_op2.type == O_IMM)
        assert(self.op2.type == O_REG)

        dis = self.make_disasm(self.mnem, self.op1, new_op2)
        self.dis = dis
        self.clean_dis = self.clean_disasm(self.dis)
        self.read_regs = self.read_regs - self.op2.regs
        self.modified_regs = self.modified_regs - self.op2.regs
        self.op2 = new_op2
        self.read_regs |= new_op2.regs

    def get_addr(self): return self.addr
    
    def bits_text(self, bits):
        if bits == 8:
            o = "byte ptr"
        elif bits == 16:
            o = "word ptr"
        elif bits == 32:
            o = "dword ptr"
        else:
            print "bits:", bits
            assert(False)
        return o

    def dump(self):
        if False:
            t1 = t2 = ""
            if self.op1: t1 = self.op1.text
            if self.op2: t2 = self.op2.text

            if ((self.op1 and not self.op2 and self.op1.type == O_MEM) or
               (self.op1 and self.op2 and self.op1.type == O_MEM and self.op2.type == O_IMM)):
                ptr = self.bits_text()
                t1 = "%s %s"%(ptr, t1)

            o = "%s %s %s"%(self.mnem, t1, t2)

        else:
            o = self.get_clean_dis()

        return o
    
    def dump_verbose(self):
        o = self.dump()
        o += " \t# bits: %d "%self.bits
        if self.op1:
            o += "OP1(%s)"%self.op1.dump()
        if self.op2:
            o += "OP2(%s)"%self.op2.dump()
        
        read = self.read_regs
        mod = self.modified_regs
        o += " read_regs: %s, mod_regs: %s"%(str(read), str(mod))
        return o

    #needs to be overridden in subclasses
    #always fail to evaluate and set modified regs to unk. state
    #set modified flags to unknown state
    def eval(self, ctx):
        ctx.unset_regs(self.modified_regs)
        ctx.unset_flags(self.modified_flags)
        return False
    
    def can_substitue(self, ctx):
        return False

##################################################
# operand
##################################################
class Opnd:
    #"parse" a text representation
    #easier than reading IDA's dox :p
    def __init__(self, op):

        if type(op) in [int, long]:
            #op = str(hex(op))
            op = self.nice_hex(op)
            op = op.replace("0x", "")
            op = op.replace("L", "")

        self.type = None
        self.regs = set()
        self.imm = None
        self.text_org = op

        op = re.sub("(dword ptr |word ptr |byte ptr |small )", "", op)
        self.text = op
        
        #push small 0000h
        op = op.replace("small ", "")

        match = imm_re.match(op)

        if op.find("]")>=0:
            self.type = O_MEM
            self.regs = self.extract_regs(op)
            mem_type, match_obj = self.get_mem_type(op)
            if mem_type == O_MEM_REG_PLUS_INDEX:
                reg = match_obj.group(1)
                assert(reg in REG_SET)
                #sign = match_obj.group(2)
                index = match_obj.group(3)
                index = int(index, 16)
                self.mem_reg = reg
                self.mem_idx = index
                self.mem_type = O_MEM_REG_PLUS_INDEX
                self.set_mem_idx(index)
            else:
                self.mem_type = O_MEM_COMPLEX

        elif op in REG_SET:
            self.type = O_REG
            self.regs = set([op])
            self.reg = op
        elif match != None:
            self.type = O_IMM
            num = match.group(1)
            imm = int(num, 16)
            self.imm = imm
            self.text = self.nice_hex(imm)
        else:
            print "strange op:", op
            #assert(False)
    
    def nice_hex(self, v):
        o = "%x"%v
        if o[0] in "abcdef":
            o = "0%sh"%o
        elif v>9:
            o = "%sh"%o
        return o

    def update_mem_idx(self, value):
        assert(self.mem_type == O_MEM_REG_PLUS_INDEX)
        value = value + self.mem_idx
        self.set_mem_idx(value)

    def set_mem_idx(self, value):
        assert(self.mem_type == O_MEM_REG_PLUS_INDEX)
        self.mem_idx = value
        v_abs = abs(value)
        v = self.nice_hex(v_abs)
        if value>0:
            sign = "+"
        elif value == 0:
            sign = ""
            v = ""
        else:
            sign = "-"
        old_text = self.text
        self.text = "[%s%s%s]"%(self.mem_reg, sign, v)
        self.text_org = self.text_org.replace(old_text, self.text)

    def get_mem_type(self, op):
        hits = re.findall(r".*?\[[a-z]+\]", op)
        if len(hits)>0:
            op = op.replace("]", "+0]")
        base_idx_re =  ".*?\[([a-z]+)(\+|\-)([0-9a-fA-F]+)h?\]"
        base_idx_re = re.compile(base_idx_re)
        m = re.match(base_idx_re, op)
        if m != None:
            return (O_MEM_REG_PLUS_INDEX, m)

        return (None, None)

    def extract_regs(self, op):
        parts = re.split("\W+", op)
        regs = filter(lambda part: part in REG_SET, parts)
        return set(regs)

    def dump(self):
        o = "type: %d, regs: %s"%(self.type, str(self.regs))
        if self.imm:
            o += " imm: %08x"%self.imm
        return o

    def get_mem_addr(self, ctx):
        assert(self.type == O_MEM) 

        if self.mem_type != O_MEM_REG_PLUS_INDEX:
            return None

        reg = self.mem_reg
        idx = self.mem_idx

        if not ctx.is_known(reg):
            return None

        reg_val = ctx.get_reg(reg)
        return reg_val+idx

    def unpack_type(self, ctx):
        my_type = self.type
        if my_type == O_MEM:
            unp = self.get_mem_addr(ctx)
        elif my_type == O_REG:
            unp = self.reg
        elif my_type == O_IMM:
            unp = self.imm
        else:
            assert(False)

        return unp

##################################################
# context (registers/flags state and values)
##################################################
class Ctx():
    def __init__(self):
        self.known_regs = set()
        self.unknown_regs = REG_SET
        self.values = dict()
        self.mem = dict()
        self.flags = dict()

        self.unset_flags(FLAGS)

    def is_known_flag(self, flag):
        assert(flag in FLAGS)
        return self.flags[flag] != None

    def get_flag(self, flag):
        assert(self.is_known_flag(flag))
        return self.flags[flag]

    def set_flag(self, flag, value):
        assert(value in [True, False])
        self.flags[flag] = value
    
    def mod_flag(self, flag, value):
        #PyFlags returns None in 2 cases:
        # - when flag in unaffected
        # - when instruction is not supported
        # we chose to always interpret it as option 1
        if value == None:
            pass
        elif value == 1:
            self.set_flag(flag, True)
        elif value == 0:
            self.set_flag(flag, False)
        else:
            print "flag: %s, value: %s"%(flag, str(value))
            assert(False)

    def unset_flag(self, flag):
        self.flags[flag] = None

    def unset_flags(self, flags):
        for flag in flags:
            self.unset_flag(flag)

    def is_known_mem(self, addr):
        try:
            self.mem[addr]
            return True
        except:
            return False
    
    def set_mem(self, addr, value):
        assert(value != None)
        self.mem[addr] = value

    def get_mem(self, addr):
        assert(self.is_known_mem(addr))
        return self.mem[addr]

    def unset_mem(self, addr):
        try:
            del self.mem[addr]
        except:
            pass

    def unset_by_type(self, op_type, op):
        if op_type == O_REG:
            self.unset_reg(op)
        elif op_type == O_MEM:
            self.unset_mem(op)
        elif op_type == O_IMM:
            pass
        else:
            assert(False)
    
    def is_known_by_type(self, op_type, op):
        if op_type == O_REG:
            return self.is_known(op)
        elif op_type == O_MEM:
            return self.is_known_mem(op)
        elif op_type == O_IMM:
            return True
        else:
            assert(False)
    
    def set_by_type(self, op_type, op, value):
        if op_type == O_REG:
            self.set_reg(op, value)
        elif op_type == O_MEM:
            self.set_mem(op, value)
        elif op_type == O_IMM:
            pass
        else:
            assert(False)

    def get_by_type(self, op_type, op):
        if op_type == O_REG:
            return self.get_reg(op)
        elif op_type == O_MEM:
            return self.get_mem(op)
        elif op_type == O_IMM:
            return op
        else:
            assert(False)

    def is_known(self, reg):
        return reg in self.known_regs

    def get_reg(self, reg):
        assert(self.is_known(reg))
        return self.values[reg]

    def set_reg(self, reg, val):
        assert(type(val) in [int, long])
        
        self.values = set_reg_aux(self.values, reg, val)
        self.known_regs |= set(self.values.keys())
        self.unknown_regs = REG_SET - self.known_regs

        #invariants
        assert(self.known_regs | self.unknown_regs == REG_SET)
        assert(self.known_regs & self.unknown_regs == set())
    
    def unset_regs(self, regs):
        for reg in regs:
            self.unset_reg(reg)

    def unset_reg(self, reg):
        assert(reg in REG_SET)
        unset_affected = REG_UNSET_AFFECTED[reg]
        affected_regs = unset_affected[reg]
        new_known = self.known_regs - affected_regs
        if new_known == self.known_regs:
            return
        self.known_regs = new_known
        self.unknown_regs = self.unknown_regs | affected_regs
        for reg in affected_regs:
            try:
                del(self.values[reg])
            except:
                pass
        #invariants
        #assert(self.known_regs | self.unknown_regs == REG_SET)
        #assert(self.known_regs & self.unknown_regs == set())
        #assert(self.known_regs == set(self.values.keys()))

    def update_flags(self, mnem, val1, val2, res, bits):
        size = bits/8
        if mnem in ["and", "or", "xor", "not", "test"]:
            mnem = "logic"
        mnem = mnem.upper()
        flags = PyFlags(mnem, val1, val2, res, size)
        self.mod_flag(AF, flags.get_AF())
        self.mod_flag(CF, flags.get_CF())
        self.mod_flag(OF, flags.get_OF())
        self.mod_flag(PF, flags.get_PF())
        self.mod_flag(SF, flags.get_SF())
        self.mod_flag(ZF, flags.get_ZF())
    
    def dump(self):
        o = "regs: %s\n" % str(self.known_regs)
        o += "reg values: %s\n" % str(self.values)
        o += "mem: %s\n" % str(self.mem)
        o += "flags: %s\n" % str(self.flags)
        return o

##################################################
#  common things for instructions used in handlers
##################################################
class Comp(Inst):
    def __init__(self, addr, mnem, op1, op2, bits=0):
        Inst.__init__(self, addr, mnem, op1, op2, bits=bits)
        self.modified_flags = FLAGS

    def eval(self, ctx):
        type1 = self.op1.type
        N = 1<<self.bits
        
        if type1 == O_REG and ctx.is_known(self.op1.reg):
            reg1 = self.op1.reg
            val1 = ctx.get_reg(reg1)
            if self.op2 != None:
                type2 = self.op2.type
                if type2 == O_IMM:
                    val2 = self.op2.imm
                elif type2 == O_REG and ctx.is_known(self.op2.reg):
                    reg2 = self.op2.reg
                    val2 = ctx.get_reg(reg2)
                else:
                    return Inst.eval(self, ctx)
            else:
                val2 = None

            res = self.eval_imm(val1, val2)

            if res<0:
                res = N+res
            res = res % N

            v2 = val2
            if val2 == None:
                v2 = 0
            ctx.update_flags(self.mnem, val1, v2, res, self.bits)

            #print "set_reg:", reg1, res, type(res)
            ctx.set_reg(reg1, res)
            return True

        return Inst.eval(self, ctx)
   

    def equivalent_mov(self, ctx):
        assert(self.op1.type == O_REG)

        dst_reg = self.op1.reg
        imm = ctx.get_reg(dst_reg)
        """
        if self.op2:
            type2 = self.op2.type
            if type2 == O_REG:
               src_reg = self.op2.reg
               imm = ctx.get_reg(src_reg)
            elif type2 == O_IMM:
               pass
            else:
                assert(False)
        #1arg instructions: neg, not, inc, dec
        else:
            imm = ctx.get_reg(dst_reg)
        """

        new_op1 = Opnd(dst_reg)
        new_op2 = Opnd(imm)
        mov = Mov(FAKE_INSTR_ADDR, "mov", new_op1, new_op2)

        return mov

    #is there any reg with known value, that is read?
    def can_substitue(self, ctx):
        if self.op2 and self.op2.type == O_REG:
            return ctx.is_known(self.op2.reg)
        
        return False

    #substitute known regs for their values
    def substitute_reg(self, ctx):
        assert(self.op2.type == O_REG)

        src_reg = self.op2.reg
        imm = ctx.get_reg(src_reg)
        new_op2 = Opnd(imm)
        #just update to keep consistent state :p
        self.update_op2(new_op2)
        return self

##################################################
#  instructions used to obfuscate handlers
##################################################
class Add(Comp):
    def eval_imm(self, v1, v2):
        return v1+v2

class Sub(Comp):
    def eval_imm(self, v1, v2):
        return v1-v2

class And(Comp):

    def eval_imm(self, v1, v2):
        return v1 & v2

class Or(Comp):

    def eval_imm(self, v1, v2):
        return v1 | v2

class Xor(Comp):

    def eval_imm(self, v1, v2):
        return v1 ^ v2

class Dec(Comp):

    def eval_imm(self, v1, v2):
        assert(v2 == None)
        return v1-1 

class Inc(Comp):

    def eval_imm(self, v1, v2):
        assert(v2 == None)
        return v1+1

#no flags modified
class Not(Comp):
    def __init__(self, addr, mnem, op1, op2, bits=0):
        Inst.__init__(self, addr, mnem, op1, op2, bits=bits)
        self.modified_flags = set()

    def eval_imm(self, v1, v2):
        assert(v2 == None)
        return ~v1

class Neg(Comp):
    def eval_imm(self, v1, v2):
        assert(v2 == None)
        return (~v1)+1

class Shl(Comp):

    def eval_imm(self, v1, v2):
        return v1<<v2

class Shr(Comp):

    def eval_imm(self, v1, v2):
        return v1>>v2

# test is used only before pushf, so we can ignore how it affects flags
class Test(Inst):

    def __init__(self, addr, mnem, op1, op2):
        Inst.__init__(self, addr, mnem, op1, op2)
        self.modified_regs = set()

#no flags modified
class Xchg(Inst):
    def __init__(self, addr, mnem, op1, op2):
        Inst.__init__(self, addr, mnem, op1, op2)
        if op2.type == O_REG:
            self.modified_regs = self.modified_regs.union(op2.regs)
    
    def equivalent_mov(self, ctx):
        type1 = self.op1.type
        type2 = self.op2.type

        if type1 != O_REG or type2 != O_REG:
            assert(False)

        reg1 = self.op1.reg
        reg2 = self.op2.reg
        assert(ctx.is_known(reg1) and ctx.is_known(reg2))
        v1 = ctx.get_reg(reg1)
        v2 = ctx.get_reg(reg2)

        op_reg1 = Opnd(reg1)
        op_reg2 = Opnd(reg2)
        op_v1 = Opnd(v1)
        op_v2 = Opnd(v2)

        mov1 = Mov(FAKE_INSTR_ADDR, "mov", op_reg1, op_v1, self.bits)
        mov2 = Mov(FAKE_INSTR_ADDR, "mov", op_reg2, op_v2, self.bits)

        return [mov1, mov2]

    def eval(self, ctx):
        type1 = self.op1.type
        type2 = self.op2.type

        rm = (type1 == O_REG and type2 == O_MEM) 
        mr = (type1 == O_MEM and type2 == O_REG) 
        mm = (type1 == O_MEM and type2 == O_MEM)

        if type1 == O_REG and type2 == O_REG:
            reg1 = self.op1.reg
            reg2 = self.op2.reg
            v1, v2 = None, None
            if ctx.is_known(reg1):
                v1 = ctx.get_reg(reg1)
            if ctx.is_known(reg2):
                v2 = ctx.get_reg(reg2)

            v1, v2 = v2, v1

            for reg,val in [(reg1,v1),(reg2,v2)]:
                if val != None:
                    ctx.set_reg(reg, val)
                else:
                    ctx.unset_reg(reg)
            
            if None not in [v1, v2]:
                # can return TWO equivalent movs
                return True

        elif rm or mr or mm:
            op1 = self.op1.unpack_type(ctx)
            op2 = self.op2.unpack_type(ctx)

            if None in [op1, op2]:
                #print "None"
                #print op1, op2
                return Inst.eval(self, ctx)
            
            t1 = self.op1.type
            t2 = self.op2.type

            known1 = ctx.is_known_by_type(t1, op1)
            known2 = ctx.is_known_by_type(t2, op2)

            v1, v2 = None, None
            if known1:
                v1 = ctx.get_by_type(t1, op1)
            if known2:
                v2 = ctx.get_by_type(t2, op2)

            if known1:
                ctx.set_by_type(t2, op2, v1)
            else:
                ctx.unset_by_type(t2, op2)

            if known2:
                ctx.set_by_type(t1, op1, v2)
            else:
                ctx.unset_by_type(t1, op1)
            
            print "xchg info:"
            print t1, t2
            print known1, known2
            print v1, v2

        #we don't want to be asked about "equivalent mov"
        return False

#no flags modified
class Mov(Inst):
    def __init__(self, addr, mnem, op1, op2, bits = 0):
        Inst.__init__(self, addr, mnem, op1, op2, bits)
        if op1.type != O_MEM:
            self.read_regs = self.read_regs - op1.regs

    def eval(self, ctx):
        type1 = self.op1.type
        type2 = self.op2.type

        if type1 == O_REG and type2 == O_IMM:
            reg = self.op1.reg
            imm = self.op2.imm
            ctx.set_reg(reg, imm)
            return True

        elif type1 == type2 == O_REG: 
            reg1 = self.op1.reg
            reg2 = self.op2.reg
            if ctx.is_known(reg2):
                val2 = ctx.get_reg(reg2)
                ctx.set_reg(reg1, val2)
                return True
        
        elif O_MEM in [type1, type2]:
            src_type = self.op2.type
            dst_type = self.op1.type

            src_val = None
            if src_type == O_IMM:
                src_val = self.op2.imm
            else:
                op = self.op2.unpack_type(ctx)
                if ctx.is_known_by_type(src_type, op):
                    src_val = ctx.get_by_type(src_type, op)
            
            #addr or reg
            dst = self.op1.unpack_type(ctx)

            if src_val == None:
                ctx.unset_by_type(dst_type, dst)
            else:
                if dst != None:
                    ctx.set_by_type(dst_type, dst, src_val)

            if src_type in [O_IMM, O_REG] and src_val != None:
                return True

        return Inst.eval(self, ctx)

    def equivalent_mov(self, ctx):
        type2 = self.op2.type
        if type2 == O_REG:
            src_reg = self.op2.reg
            imm = ctx.get_reg(src_reg)
            new_op2 = Opnd(imm)
            new_mov = Mov(FAKE_INSTR_ADDR, "mov", self.op1, new_op2, self.bits)
        elif type2 == O_IMM:
            new_mov = self
        else:
            assert(False)

        return new_mov

#no flags modified
class Push(Inst):
    def __init__(self, addr, mnem, op1, op2, bits=0):
        Inst.__init__(self, addr, mnem, op1, op2, bits)
        self.modified_regs = ESP_REGS
        self.read_regs = ESP_REGS|op1.regs
    
    def eval(self, ctx):

        type1 = self.op1.type
        op1 = self.op1.unpack_type(ctx)

        if not ctx.is_known(ESP):
            ctx.unset_by_type(type1, op1)
        else:
            esp = ctx.get_reg(ESP)
            #FIXME: 16bit push

            val = None
            if ctx.is_known_by_type(type1, op1):
                val = ctx.get_by_type(type1, op1)

            esp = esp-4
            ctx.set_reg(ESP, esp)

            if val:
                ctx.set_mem(esp, val)

        #we never want this instruction to be replaced by a mov
        return False

#no flags modified
class Pop(Inst):
    def __init__(self, addr, mnem, op1, op2):
        Inst.__init__(self, addr, mnem, op1, op2)
        self.modified_regs = ESP_REGS|op1.regs
        self.read_regs = ESP_REGS

    def eval(self, ctx):

        type1 = self.op1.type
        if type1 == O_REG:
            o1_reg = self.op1.reg
            op1 = o1_reg

        elif type1 == O_MEM:
            o1_addr = self.op1.get_mem_addr(ctx)
            op1 = o1_addr
        else:
            assert(False)

        if not ctx.is_known(ESP):
            ctx.unset_by_type(type1, op1)
        else:
            esp = ctx.get_reg(ESP)
            if not ctx.is_known_mem(esp):
                ctx.unset_by_type(type1, op1)
            elif type1 == O_REG or (type1 == O_MEM and op1 != None):
                stack_val = ctx.get_mem(esp)
                ctx.set_by_type(type1, op1, stack_val)
            #FIXME: pop 16bit
            if not (type1 == O_REG and op1 == ESP):
                ctx.set_reg(ESP, esp+4)

        #we never want this instruction to be replaced by a mov
        return False

class Pushf(Inst):
    def __init__(self, addr, mnem, op1, op2):
        Inst.__init__(self, addr, mnem, op1, op2)

    def eval(self, ctx):
        if ctx.is_known(ESP):
            esp = ctx.get_reg(ESP)
            esp = esp-4
            ctx.set_reg(ESP, esp)
        #we never want this instruction to be replaced by a mov
        return False

class Popf(Inst):
    def __init__(self, addr, mnem, op1, op2):
        Inst.__init__(self, addr, mnem, op1, op2)

    def eval(self, ctx):
        if ctx.is_known(ESP):
            esp = ctx.get_reg(ESP)
            esp = esp+4
            ctx.set_reg(ESP, esp)
        #we never want this instruction to be replaced by a mov
        return False

##################################################
# jump classes
##################################################
class Branch(Inst):
    def __init__(self, addr, mnem, op1):
        assert(op1.type == O_IMM)
        Inst.__init__(self, addr, mnem, op1, None)
        self.target = op1.imm
    
    def is_jxx(self):
        return True

class Jmp(Branch):
    def __init__(self, addr, mnem, op1):
        Branch.__init__(self, addr, mnem, op1)
    
    def can_eval(self, ctx):
        return True

    def eval_jxx(self, ctx):
        return True

#these should be lambdas, but lambdas can't be pickled :(
def jo_func ((of,)): of==True
def jno_func ((of,)): return of==False
def js_func ((sf,)): return sf==True
def jns_func ((sf,)): return sf==False
def je_func ((zf,)): return zf==True
def jne_func ((zf,)): return zf==False
def jb_func ((cf,)): return cf==True
def jnb_func ((cf,)): return cf==False
def jbe_func ((cf,zf)): return cf==True or zf==True
def jnbe_func ((cf,zf)): return cf==False and zf==False
def jl_func ((sf,of)): return sf != of
def jnl_func ((sf,of)): return sf == of
def jle_func ((zf,sf,of)): return zf == True or (sf != of)
def jnle_func  ((zf,sf,of)): return zf == False and (sf == of)
def jp_func ((pf,)): return pf==True
def jnp_func ((pf,)): return pf==False

class Jxx(Branch):
    def __init__(self, addr, mnem, op1):
        Branch.__init__(self, addr, mnem, op1)

        self.conds = []
        self.conds += [(["jo"], [OF], jo_func)]
        self.conds += [(["jno"], [OF], jno_func)]
        self.conds += [(["js"], [SF], js_func)]
        self.conds += [(["jns"], [SF], jns_func)]
        self.conds += [(["je", "jz"], [ZF], je_func)]
        self.conds += [(["jne", "jnz"], [ZF], jne_func)]
        self.conds += [(["jb", "jnae", "jc"], [CF], jb_func)]
        self.conds += [(["jnb", "jae", "jnc"], [CF], jnb_func)]
        self.conds += [(["jbe", "jna"], [CF, ZF], jbe_func)]
        self.conds += [(["jnbe", "ja"], [CF, ZF], jnbe_func)]
        self.conds += [(["jl", "jnge"], [SF, OF], jl_func)]
        self.conds += [(["jnl", "jge"], [SF, OF], jnl_func)]
        self.conds += [(["jle", "jng"], [ZF, SF, OF], jle_func)]
        self.conds += [(["jnle", "jg"], [ZF, SF, OF], jnle_func)]
        self.conds += [(["jp", "jpe"], [PF], jp_func)]
        self.conds += [(["jnp", "jpo"], [PF], jnp_func)]

        self.flag_list = None
        self.lambda_cond = None

        mnem = self.mnem.lower()
        for cond in self.conds:
            mnem_list, flag_list, lambda_cond = cond
            if mnem in mnem_list:
                self.flag_list = flag_list
                self.lambda_cond = lambda_cond
                break
        
        assert(self.lambda_cond != None)
        assert(self.flag_list != None)

    def get_flags(self, flag_list, ctx):
        o = []
        for flag in flag_list:
            if ctx.is_known_flag(flag):
                flag = ctx.get_flag(flag)
            else:
                flag = None
            o.append(flag)
        return o

    def can_eval(self, ctx):
        flags = self.get_flags(self.flag_list, ctx)
        if None in flags:
            return False
        return True
        
    def eval_jxx(self, ctx):
        # callers need to check if they can eval 
        if not self.can_eval(ctx):
            assert(False)

        flags = self.get_flags(self.flag_list, ctx)
        flags = tuple(flags)
        taken = self.lambda_cond(flags)
        return taken
    
    def is_cond_jmp(self):
        return True
