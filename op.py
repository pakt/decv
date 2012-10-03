import idc
import re
from common import *
from op_classes import *

def convert_graph(root):
    _, root = dfs(root, f_convert)
    return root

def f_convert(acc, bb, children):
    if acc == None:
        acc = dict(), None

    bb_to_dbb, root = acc

    try:
        dbb = bb_to_dbb[bb]
    except:
        dbb = convert_bb(bb)
        bb_to_dbb[bb] = dbb
    
    #print "bb:", bb.disasm()

    for i,child in enumerate(children):
        try:
            child_dbb = bb_to_dbb[child]
        except:
            child_dbb = convert_bb(child)
            bb_to_dbb[child] = child_dbb
        
        #print "child:", i, child.disasm()

        if i==0:
            dbb.child1 = child_dbb
        elif i==1:
            dbb.child2 = child_dbb
    
    if root==None:
        root = dbb

    return bb_to_dbb, root

def convert_bb(bb):
    dbb = DBB()
    last = bb.body[-1]
    for n in bb.body:
        # don't collect uncond. jmps from inside
        if is_jmp(n) and n!=last:
            continue
        m = convert_inst(n)
        dbb.add(m)
    return dbb

def convert_inst(addr):
    mnem = idc.GetMnem(addr)

    op1 = idc.GetOpnd(addr, 0)
    op2 = idc.GetOpnd(addr, 1)
    
    if not op1: op1 = None
    if not op2: op2 = None
    
    if is_jxx(addr):
        op1 = jxx_target(addr)
        op1 = str(op1)

    if op1:
        op1 = Opnd(op1)
    if op2:
        op2 = Opnd(op2)
    
    if is_jmp(addr):
        ni = Jmp(addr, mnem, op1)
    elif is_jxx(addr):
        ni = Jxx(addr, mnem, op1)

    elif mnem == "add":
        ni = Add(addr, mnem, op1, op2)
    elif mnem == "sub":
        ni = Sub(addr, mnem, op1, op2)
    elif mnem == "and":
        ni = And(addr, mnem, op1, op2)
    elif mnem == "or":
        ni = Or(addr, mnem, op1, op2)
    elif mnem == "xor":
        ni = Xor(addr, mnem, op1, op2)
    elif mnem == "dec":
        ni = Dec(addr, mnem, op1, op2)
    elif mnem == "inc":
        ni = Inc(addr, mnem, op1, op2)
    elif mnem == "not":
        ni = Not(addr, mnem, op1, op2)
    elif mnem == "neg":
        ni = Neg(addr, mnem, op1, op2)
    elif mnem == "shl":
        ni = Shl(addr, mnem, op1, op2)
    elif mnem == "shr":
        ni = Shr(addr, mnem, op1, op2)
    elif mnem == "test":
        ni = Test(addr, mnem, op1, op2)
    elif mnem == "xchg":
        ni = Xchg(addr, mnem, op1, op2)
    elif mnem == "mov":
        ni = Mov(addr, mnem, op1, op2)

    elif mnem == "push":
        ni = Push(addr, mnem, op1, op2)
    elif mnem == "pop":
        ni = Pop(addr, mnem, op1, op2)

    elif mnem == "pushf":
        ni = Pushf(addr, mnem, op1, op2)
    elif mnem == "popf":
        ni = Popf(addr, mnem, op1, op2)

    elif mnem in NOT_IMPLEMENTED:
        ni = Inst(addr, mnem, op1, op2)

    else:
        print "Unsupported addrruction @%s: %s"%(hex(addr), mnem)
        assert(False)
    
    return ni


