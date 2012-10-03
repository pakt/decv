from config import *
import pickle
from vmi_top_common import *

ID_EFLAGS = 7
REG_EFLAGS = REG_DICT[ID_EFLAGS]
ID_ESP = 7

#FIXME: autogen these
LOAD_PTR_REG = 0x000
STORE_ADDR = 0x001
STORE_DWORD_ADDR = 0x018
MOVE_ADDR_STACK = 0x14e
LOAD_ADDR = 0x009
LOAD_DWORD = 0x004
LOAD_REG = 0x007
ADD_NO_FLAGS = 0x006
MOVE_STACK_STACK = 0x208
LOAD_DWORD_ADDR = 0x00c
LOAD_WORD = 0x003
STORE_DWORD_REG = 0x01c
INC_DWORD = 0x055
ADD_DWORD = 0x024
XOR_DWORD = 0x03d
ADD_REG_TO_ADDR = 0x211
PUSH_RET_ADDR = 0x15d
UNCOND_JMP = 0x154
GTFO = 0x212

STACK = "stack"
ADDR = "addr"

T_INVALID = "t_invalid"
T_REG_PTR = "t_reg_ptr"
T_CONST = "t_const"
T_REG = "t_reg"

T_BINOP = "t_binop"

N = 2**32

XOR = "OP_XOR"
ADD = "OP_ADD"

class Thing:
    def __init__(self, typ, thing):
        self.typ = typ
        self.thing = thing

    def __repr__(self):
        typ = self.typ
        thing = self.thing
        if typ == T_REG:
            return thing
        elif typ == T_CONST:
            return hex(thing)
        elif typ == T_REG_PTR:
            return "ptr "+thing
        else:
            assert False, "bad type: "+typ
    
    def __str__(self): return self.__repr__()

class BinOp:
    def __init__(self, op, left, right):
        self.op = op
        self.l = left
        self.r = right

    def __repr__(self):
        if self.op == XOR:
            st = "^"
        elif self.op == ADD:
            st = "+"
        else:
            assert False
        sl = str(self.l)
        sr = str(self.r)
        s = "%s %s %s"%(sl, st, sr)
        return s

def t_type(tu): return tu[0]
def t_thing(tu): return tu[1]
def t_size(tu): return tu[2]

def t_reg_ptr(reg_id):
    reg = REG_DICT[reg_id]
    return (T_REG_PTR, reg, 4)

def symb_eval(state, vmi):
    def stack_size(stack):
        l = map(lambda t: t_size(t), stack)
        return sum(l)

    def pop4(stack):
        (typ, thing, size) = stack.pop()
        if size == 4:
            return (typ, thing, size)
        elif size == 2:
            assert typ == T_CONST
            (typ2, thing2, size2) = stack.pop()
            if typ2 != typ or size != size2:
                s= "mismatch: (%s, %s), (%d, %d)"%(typ, typ2, size, size2)
                assert False, s
            x = (thing<<16)+thing2
            return (typ, x, 4)
        else:
            assert False, "bad size: "+size

    stack = state[STACK]
    addr = state[ADDR]
    vid = int(vmi.vid, 16)
    
    native = None

    if vid == LOAD_PTR_REG:
        reg_id = vmi.param
        t = t_reg_ptr(reg_id)
        stack.append(t)

    elif vid == STORE_ADDR:
        addr = pop4(stack)

    elif vid == STORE_DWORD_ADDR:
        (addr_typ, addr_thing, _) = addr
        if addr_typ == T_REG_PTR and stack == []:
                native = "vm_%s <- %s"%(addr_thing, addr_thing)
        else:
            if addr_typ in [T_REG_PTR]:
                dst = "%s"
            elif addr_typ in [T_REG, T_BINOP]:
                dst = "[%s]"
            elif addr_typ == T_CONST:
                dst = "[%x]"
            else:
                assert False
            (typ, thing, sz) = stack.pop()
            fmt = dst + " <- %s"
            native = fmt%(addr_thing, thing)
    
    elif vid == MOVE_ADDR_STACK:
        size = stack_size(stack)
        addr = (T_CONST, size, 4)

    elif vid == LOAD_ADDR:
        stack.append(addr)

    elif vid == LOAD_DWORD:
        assert vmi.param_size == 4
        t = (T_CONST, vmi.param, 4)
        stack.append(t)

    elif vid == LOAD_WORD:
        assert vmi.param_size == 2
        t = (T_CONST, vmi.param, 2)
        stack.append(t)

    elif vid == LOAD_REG:
        assert vmi.param_size == 1
        reg = REG_DICT[vmi.param]
        t = (T_REG, reg, 4)
        stack.append(t)

    elif vid == ADD_NO_FLAGS:
        (typ1, x1, s1) = stack.pop()
        (typ2, x2, s2) = stack.pop()
        assert s1 == s2
        if typ1 == typ2 == T_CONST:
            t = (T_CONST, (x1+x2)%N, s1)
            stack.append(t)
        else:
            th1 = Thing(typ1, x1)
            th2 = Thing(typ2, x2)
            th = BinOp(ADD, th1, th2)
            t = (T_BINOP, th, s1)
            stack.append(t)
    
    elif vid == ADD_DWORD:
        (typ1, x1, s1) = stack.pop()
        (typ2, x2, s2) = stack.pop()
        assert s1 == s2
        if typ1 == typ2 == T_CONST:
            assert False
        th1 = Thing(typ1, x1)
        th2 = Thing(typ2, x2)
        th = BinOp(ADD, th1, th2)
        t = (T_BINOP, th, s1)
        stack.append(t)
        t = (T_REG, REG_EFLAGS, 4)
        stack.append(t)

    elif vid == ADD_REG_TO_ADDR:
        (typ, thing, sz) = addr

        assert vmi.param_size == 1
        assert sz == 4

        reg_id = vmi.param
        if reg_id == ID_ESP:
            reg = REG_ESP
        else:
            reg = REG_DICT[reg_id]

        th1 = Thing(typ, thing)
        th2 = Thing(T_REG, reg)
        th = BinOp(ADD, th1, th2)
        t = (T_BINOP, th, 4)
        addr = t

    #nop
    elif vid == MOVE_STACK_STACK:
        (typ, x, sz) = stack.pop()
        cur_size = stack_size(stack)
        assert x == cur_size+4

    elif vid == LOAD_DWORD_ADDR:
        (typ, thing, sz) = addr
        if typ == T_REG_PTR:
            t = (T_REG, thing, sz)
            stack.append(t)
        else:
            assert False

    elif vid == XOR_DWORD:
        (typ1, thing1, sz1) = stack.pop()
        (typ2, thing2, sz2) = stack.pop()

        assert sz1 == sz2
        assert typ1 in [T_REG, T_CONST]
        assert typ2 in [T_REG, T_CONST]

        th1 = Thing(typ1, thing1)
        th2 = Thing(typ2, thing2)
        tt = BinOp(XOR, th1, th2)
        t = (T_BINOP, tt, sz1)
        stack.append(t)
        #push flags after arith ops
        t = (T_REG, REG_EFLAGS, 4)
        stack.append(t)
    
    elif vid == STORE_DWORD_REG:
        (typ, thing, sz) = stack.pop()

        if typ == T_REG:
            if vmi.param == ID_EFLAGS:
                if thing == REG_EFLAGS:
                    pass #nothing to do
                else:
                    assert False
            else:
                assert False
        else:
            assert False

    elif vid == UNCOND_JMP:
        assert vmi.param == 1
        native = "jmp $+1"

    elif vid == PUSH_RET_ADDR:
        (typ, ret_addr, sz) = stack.pop()
        assert typ == T_CONST
        native = "push_return_address: 0x%08x"%ret_addr

    elif vid == GTFO: 
        native = "gtfo"

    elif vid == 0x157:
        native = "unk_157: mov byte [edi+28h], %d"%vmi.param

    else:
        assert False, "unkown instr: "+hex(vid)

    state[STACK] = stack
    state[ADDR] = addr

    return state, native

def recover(vmis):

    state = {STACK: [], ADDR: (T_INVALID, 0, 0)}

    for vmi in vmis:
        print vmi.all_disasm()

        state, native = symb_eval(state, vmi)
        #print state

        if native != None:
            print native

