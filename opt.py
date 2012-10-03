import copy
import bb
import emu
from common import *
from op_classes import *

INSTR_SEPARATOR = "#"
assert(len(INSTR_SEPARATOR) == 1) #code below assumes that :P

NULL_PAIR = (0, None)

g_watched_dbb_addr = 0x405880

# remove unnecessary uncond. jumps
def contract_graph(root):
    bb_to_ubb = dict()
    visited = set()
    jmping_to = dfs(root, f_jmping_to)
    jmping_to[root] = set([root])
    new_root = contract_graph_rec(root, bb_to_ubb, visited, jmping_to)
    dfs(root, f_verify)
    return new_root


def f_verify(acc, node, children):
    if acc == False:
        return acc
    acc = node.verify()
    if not acc:
        for x in node.body:
            print hex(x)
        print "c1:", hex(node.child1.get_addr()), "c2:", hex(node.child2.get_addr())
        assert(False)
    return acc

def f_jmping_to(acc, node, children):
    if not acc:
        acc = dict()

    for c in children:
        acc = set_jmpto(acc, c, node)

    return acc

def set_jmpto(jmps, c, n):
    try:
        jmps[c].add(n)
    except:
        jmps[c] = set([n])
    return jmps


def dump(l):
    for x in l:
        print hex(x)

def merge_ubb(ubb, node, bb_to_ubb):
    if not ubb:
        ubb = bb.BB()
    ubb.merge(node)
    bb_to_ubb[node] = ubb

    return ubb

def contract_2children(node, c1, c2, contract_lambda):

    r1 = contract_lambda(c1)
    r2 = contract_lambda(c2)
    assert(r1 != r2)
    node.child1 = r1
    node.child2 = r2
    return node

def contract_1child(cur_ubb, child, bb_to_ubb, jmping_to):

    ref_count = len(jmping_to[child])

    if ref_count == 1:
        cur_ubb = merge_ubb(cur_ubb, child, bb_to_ubb)

    elif ref_count > 1:
        new = merge_ubb(None, child, bb_to_ubb)
        cur_ubb.child1 = new
        cur_ubb = new

    #ref_count == 0 -> error
    else:
        assert(False)

    return cur_ubb

def contract_graph_rec(node, bb_to_ubb, visited, jmping_to):
    
    if node in visited:
        return bb_to_ubb[node]

    contract_lambda = lambda n: contract_graph_rec(n, bb_to_ubb, visited, jmping_to)
    new_node = merge_ubb(None, node, bb_to_ubb)
    root = new_node

    while node not in visited:
        visited.add(node)
        
        c1, c2 = node.child1, node.child2

        if c1 != None and c2 != None:
            new_node = contract_2children(new_node, c1, c2, contract_lambda)
            break

        elif c1 != None:
            node = c1

            if node in visited:
                new_node.child1 = bb_to_ubb[node]
                break
            
            new_node = contract_1child(new_node, node, bb_to_ubb, jmping_to)

        elif c1==None and c2==None:
            break

        else:
            assert(False)

    return root

##################################################
# compiler optimizations for DBBs
##################################################

def run_all_opts(dbb):
    prev_len = len(dbb.body)
    chances = 2
    dbb_addr = g_watched_dbb_addr
    while True:
        dirty = False
        if dbb.get_addr() == dbb_addr:
            print "$ before peephole $"
            print dbb.dump()
            print "-"*5
        dbb, mutated  = peephole(dbb)
        dirty |= mutated

        if dbb.get_addr() == dbb_addr:
            print "$ before constant_propagation_one $"
            print dbb.dump()
            print "-"*5
        dbb, mutated = constant_propagation_one(dbb)
        dirty |= mutated

        if dbb.get_addr() == dbb_addr:
            print "$ before dead_code_elim_one $"
            print dbb.dump()
            print "-"*5

        # number of instructions does not change, so we need a flag
        dbb, mutated = cascading_movs(dbb)
        dirty |= mutated

        dbb = dead_code_elim_one(dbb)
        dbb = push_pop_pairs(dbb)
        dbb = stack_trick(dbb)
        dbb = folding(dbb)
        dbb = handle_mem_ops(dbb)

        cur_len = len(dbb.body)

        if (prev_len == cur_len) and not dirty:
            break

        prev_len = cur_len
    
    #print [v for v in sorted(stats.items(), key=lambda(k,v): (-v,k))]

    return dbb


# handle sequences of:
# mov [mem], X
# op [mem], Y
# -> mov [mem], X op Y
# handles only continouus sequences
# non-cont. have a lot of complications
def handle_mem_ops(dbb):

    class MemOp:
        def __init__(self, op, bits, value):
            self.regs = op.regs
            self.text = op.text
            self.bits = bits
            self.value = value
        def new_value(self, v):
            self.value = v

    new_body = []
    mem_ops = dict()
    ctx = Ctx()

    for instr in dbb.body:
        if instr.op1 == None or instr.op1.type != O_MEM:
            new_body.append(instr)

            kill = []
            for opnd_text, mop in mem_ops.iteritems():
                if mop.regs & instr.modified_regs:
                    kill.append(opnd_text)

            for opnd_text in kill:
                del mem_ops[opnd_text]

            #kill everything, we don't want any sideeffects
            mem_ops = dict()

        elif instr.op1 and instr.op1.type == O_MEM:
            op1 = instr.op1

            if instr.mnem == "mov" and instr.op2 and instr.op2.type == O_IMM:
                mop = MemOp(op1, instr.bits, instr.op2.imm)
                mem_ops[mop.text] = mop
                new_body.append(instr)
                continue

            cur_mop = None
            for text, mop in mem_ops.iteritems():
                if op1.text == mop.text:
                    cur_mop = mop
                    break
            
            if cur_mop and instr.bits != cur_mop.bits:
                del mem_ops[cur_mop.text]
                cur_mop = None

            if not cur_mop or (instr.op2 and instr.op2.type != O_IMM):
                new_body.append(instr)
                continue

            cur_value = cur_mop.value
            ctx.set_reg(EAX, cur_value)
            eax_opnd = Opnd(EAX)
            instr.op1 = eax_opnd
            instr.eval(ctx)

            new_value = None
            if ctx.is_known(EAX):
                new_value = ctx.get_reg(EAX)

            if new_value != None:
                new_op = Opnd(new_value)
                new_instr = Mov(FAKE_INSTR_ADDR, "mov", op1, new_op, bits=instr.bits)
                prev_i = new_body[-1]
                #delete last mov, if it assigns to the same location
                if prev_i.mnem == "mov" and prev_i.op1.type == O_MEM and prev_i.op2.type == O_IMM and prev_i.op1.text == new_instr.op1.text:
                    new_body.pop()
                cur_mop.new_value(new_value)
            else:
                instr.op1 = op1
                new_instr = instr
                del mem_ops[cur_mop.text]
                print "failed:", instr.dump()

            new_body.append(new_instr)

        else:
            assert(False)

    dbb.set_body(new_body)
    return dbb

def is_mov_reg_reg(instr):
    return instr.mnem == "mov" and instr.op1 and instr.op2 and instr.op1.type == instr.op2.type == O_REG

def can_be_updated(instr, equals):
    if instr.mnem not in ["mov", "add", "sub", "xor", "or", "and"]:
        return False

    if instr.op2.type != O_REG:
        return False

    read_reg = instr.op2.reg
    if read_reg in equals.keys():
        return True

    return False

def oldest_ancestor(equals, old_reg):
    reg = old_reg
    while reg in equals:
        reg = equals[reg]
    return reg

def update_regs(instr, equals):
    assert(instr.op2.type == O_REG)

    old_reg = instr.op2.reg
    new_reg = oldest_ancestor(equals, old_reg)
    new_op2 = Opnd(new_reg)
    instr.update_ops(instr.op1, new_op2)
    return instr

def update_equals(equals, mod_reg):
    mod_regs = REG_UNSET_AFFECTED[mod_reg][mod_reg]
    inv_dict = dict()
    for k,v in equals.iteritems():
        if v in inv_dict:
            inv_dict[v].add(k)
        else:
            inv_dict[v] = set([k])

    for m_reg in mod_regs:
        if m_reg in equals:
            del equals[m_reg]

        if m_reg in inv_dict:
            keys = inv_dict[m_reg]
        else:
            continue

        for key in keys:
            if key in equals:
                del equals[key]
            else:
                print "update_equals:", equals, key
    return equals

# mov reg1, reg2
# mov reg3, reg1
# ...
# -> mov reg3, reg2
def cascading_movs(dbb):
    dirty = False
    equals = dict()
    for instr in dbb.body:
        if can_be_updated(instr, equals):
            instr = update_regs(instr, equals)
            dirty = True

        if is_mov_reg_reg(instr):
            reg1 = instr.op1.reg
            reg2 = instr.op2.reg
            if reg1 == reg2:
                continue
            equals = update_equals(equals, reg1)
            equals[reg1] = reg2
            continue

        mod_regs = instr.modified_regs
        for mod_reg in mod_regs:
            equals = update_equals(equals, mod_reg)
    
    #everything was updated in place
    return dbb, dirty

# per one basic block
def constant_propagation_one(dbb):
    ctx = Ctx()
    new_body = []
    dirty = False
    for instr in dbb.body:
        #ctx is modified
        did_eval = False
        substituted = False
        if instr.eval(ctx):
            """
            print "eval ok"
            print ctx.values
            print instr.dump()
            """
            new = instr.equivalent_mov(ctx)
            did_eval = True
            if new != instr:
                substituted = True

        elif instr.can_substitue(ctx):
            new = instr.substitute_reg(ctx)
            substituted = True
        else:
            new = instr

        if isinstance(instr, Xchg) and did_eval:
            #Xchg returns a list
            #bleh :p
            if isinstance(instr, Xchg):
                assert(type(new) == list)
            new_body += new
        else:
            new_body.append(new)
        
        if substituted:
            dirty = True

    dbb.set_body(new_body)
    return dbb, dirty

def certainly_dead(possibly_dead, reg):
    dead = set()
    affected = REG_RESET_AFFECTED[reg]
    for instr in possibly_dead:
        if instr.op1.reg in affected[reg]:
            dead.add(instr)
    return dead

def is_mov_reg(instr):
    return instr.mnem == "mov" and instr.op1.type == O_REG

def is_pop_reg(instr):
    return instr.mnem == "pop" and instr.op1.type == O_REG

def possibly_alive(possibly_dead, read_regs):
    alive = set()
    affected = set()
    for reg in read_regs:
        affected |= REG_RESET_AFFECTED[reg][reg]

    for instr in possibly_dead:
        if instr.op1.reg in affected:
            alive.add(instr)
    
    return alive

def is_add_reg(instr):
    return instr.mnem == "add" and instr.op1.type == O_REG

def is_xchg_reg_reg(instr):
    return instr.mnem == "xchg" and instr.op1.type == instr.op2.type == O_REG

# special case dead code elim
# per one basic block
# mov reg, smth
# ... (reg is not used)
# mov reg, smth | pop reg (reg is killed)
# -> remove first mov
#FIXME: handling Peep_add_reg_mem is slow
def dead_code_elim_one(dbb):
    possibly_dead = set()
    dead = set()
    #instruction -> reason for being alive (instruction)
    alive_tree = dict()
    for instr in dbb.body:
        new_maybe_dead = None
        # do not kill mov reg, [esp+X]
        # this may be an unoptimized POP
        # seems like a bug in CV, for example:
        # pop cx / pop ax / pop ax / div cx
        if is_mov_reg(instr):
            if instr.op2.type != O_MEM or "esp" not in instr.op2.regs:
                new_maybe_dead = instr
        #this is a dirty hack to handle Peep_add_reg_mem
        elif is_add_reg(instr):
            new_maybe_dead = instr
        
        if instr not in dead:
            read_regs = instr.read_regs
            alive = possibly_alive(possibly_dead, read_regs)
            possibly_dead -= alive

        if is_mov_reg(instr) or is_pop_reg(instr):
            just_died = certainly_dead(possibly_dead, instr.op1.reg)
            possibly_dead -= just_died
            dead |= just_died

        if new_maybe_dead:
            possibly_dead.add(new_maybe_dead)

    new_body = filter(lambda instr: instr not in dead, dbb.body)
    dbb.set_body(new_body)
    return dbb

def has_two_ops(instr):
    return instr.op1 != None and instr.op2 != None

# handling this "correclty" requires tracking states of all bits in a register :(
# hopefully this is enough..
# push ecx
# mov cl, X
# not ecx|cx -> this gets changed to not cl
# OP reg, cl
# ...
# pop ecx
class Peep_partially_defined:
    def __init__(self):
        self.pattern = r"push ([a-z]+)#mov [abcdl]{2}, [^#]+#(not|neg|inc|dec) [a-z]+#.*?pop \1"
        self.regexp = re.compile(self.pattern)
        self.instr_count = None

    def run(self, body, body_str_lambda):
        new = []
        rep_instr = None

        push_i = body[0]
        mov_i = body[1]
        op_i = body[2]
        reg = push_i.op1.reg

        if op_i.op1.reg not in REG_TO_REG_SET[reg]:
            return NULL_PAIR

        #nothing to do in this case
        if op_i.op1.reg == mov_i.op1.reg:
            return NULL_PAIR

        op_reg = op_i.op1.reg
        mov_reg = mov_i.op1.reg
        assert(mov_reg in REG_8BIT)

        for i,instr in enumerate(body[3:]):
            new.append(instr)
            if instr.mnem == "pop" and instr.op1.reg == reg:
                break

            if op_reg in instr.read_regs:
                return NULL_PAIR
        
        op_i.update_ops(Opnd(mov_reg), None, bits=8)
        #print "Peep_partially_defined:", op_i.dump()
        #print body_str_lambda
        return (len(new), new)

# mov reg, [esp]
# add esp, 4|2
# -> pop reg
# special case:
# mov esp, [esp]
# add esp, 4
# -> pop esp / add esp, 4
class Peep_pop_reg:

    def __init__(self):
        self.pattern = "mov\s+([a-z]+?), \[esp\]#add\s+esp, [0-9a-fA-F]+h?"
        self.regexp = re.compile(self.pattern)
        self.instr_count = 2

    def run(self, body, body_str_lambda):
        def f_eval(chunk):
            i1 = chunk[0]
            add = chunk[1]

            if add.op2.type != O_IMM:
                return NULL_PAIR

            #you can't pop a 8bit reg :p
            if i1.op1.reg in REG_8BIT:
                return NULL_PAIR

            imm = add.op2.imm
            bits = i1.bits
            if bits == 16:
                stack_fix = -2
            elif bits == 32:
                stack_fix = -4
            else:
                assert(False)

            off = imm + stack_fix
            assert(off >= 0)

            new_instrs = [Pop(FAKE_INSTR_ADDR, "pop", i1.op1, None)]
            new_op2 = None
            if i1.op1.reg == ESP:
                new_op2 = Opnd(off+4)
            elif off != 0:
                new_op2 = Opnd(off)

            if new_op2:
                new_instrs += [Add(FAKE_INSTR_ADDR, "add", add.op1, new_op2)]

            return (self.instr_count, new_instrs)

        return peep(body, body_str_lambda, f_eval, self.instr_count, self.regexp)

# sub esp, CONST } push CONST
# mov [esp], reg|const
# -> push reg
class Peep_push_reg:
    def __init__(self):
        self.pattern = "(sub esp, [0-9a-fA-F]+h?|push\s+(small|[0-9a-fA-F]+h?))#mov\s+\[esp\], [^\[#]+($|#)"
        self.regexp = re.compile(self.pattern)
        self.instr_count = 2

    def run(self, body, body_str_lambda):
        def f_eval(chunk):
            i1 = chunk[0]
            i2 = chunk[1]

            new_instrs = [Push(FAKE_INSTR_ADDR, "push", i2.op2, None, bits=i2.bits)]
            
            if i1.mnem == "sub":
                if i1.op2.type != O_IMM:
                    return NULL_PAIR

                bits = i2.bits
                if bits == 16:
                    stack_fix = -2
                elif bits == 32:
                    stack_fix = -4
                else:
                    assert(False)

                off = i1.op2.imm + stack_fix
                if off < 0:
                    return NULL_PAIR

                if off != 0:
                    i1.update_ops(i1.op1, Opnd(off))
                    new_instrs = [i1] + new_instrs

            return (self.instr_count, new_instrs)

        return peep(body, body_str_lambda, f_eval, self.instr_count, self.regexp)

# xor reg, [esp]
# xor [esp], reg
# xor reg, [esp]
# -> xchg reg, [esp]
class Peep_xor_trick:
    def __init__(self):
        self.pat1 = "xor\s+([a-z]+), \[esp\]#xor\s+\[esp\], ([a-z]+)#xor\s+([a-z]+), \[esp\]"
        self.pat2 = "xor\s+\[esp\], ([a-z]+)#xor\s+([a-z]+), \[esp\]#xor\s+\[esp\], ([a-z]+)"
        self.regexp1 = re.compile(self.pat1)
        self.regexp2 = re.compile(self.pat2)
        self.pattern = "(%s|%s)"%(self.pat1, self.pat2)
        self.regexp = re.compile(self.pattern)
        self.instr_count = 3

    def run(self, body, body_str_lambda):
        def f_eval(chunk):
            i1 = chunk[0]
            if i1.op1.type == O_REG:
                new_op1 = i1.op1
            elif i1.op2.type == O_REG:
                new_op1 = i1.op2
            else:
                assert(False)
            new_op2 = Opnd("[esp]")
            new_instrs = [Xchg(FAKE_INSTR_ADDR, "xchg", new_op1, new_op2)]
            return (self.instr_count, new_instrs)

        (replaced, new_instrs) = peep(body, body_str_lambda, f_eval, self.instr_count, self.regexp1)

        if replaced == 0:
            (replaced, new_instrs) = peep(body, body_str_lambda, f_eval, self.instr_count, self.regexp2)
        
        return (replaced, new_instrs)

# push smth
# pop smth
# -> mov smth, smth
class Peep_push_mov:
    def __init__(self):
        self.pattern = "push\s+[^#]+#pop\s+.*"
        self.regexp = re.compile(self.pattern)
        self.instr_count = 2

    def run(self, body, body_str_lambda):
        def f_eval(chunk):
            p1 = chunk[0]
            p2 = chunk[1]
            #print p1.dump(), p2.dump()
            if p1.op1.type == O_MEM and p2.op1.type == O_MEM:
                assert(False)
                return (0, None)

            #push eax / pop eax -> nop
            if p1.op1.type == p2.op1.type == O_REG and p1.op1.reg == p2.op1.reg:
                new_instrs = []
            else:
                new_instrs = [Mov(FAKE_INSTR_ADDR, "mov", p2.op1, p1.op1)]
            return (self.instr_count, new_instrs)

        return peep(body, body_str_lambda, f_eval, self.instr_count, self.regexp)

# push reg
# mov reg, esp
# add reg, 4
# (add|sub) reg, 2|4
# xchg reg, [esp]
# pop esp
# -> (add|sub) esp, 2|4
class Peep_add_esp:
    def __init__(self):
        self.pat1 = "push\s+[a-z]+#mov\s+[a-z]+, esp#add\s+[a-z]+, 4#(add|sub)\s+[a-z]+, (2|4)#xchg\s+[a-z]+, \[esp\]#(pop\s+esp|mov\s+esp, \[esp\])"
        self.pat2 = "push\s+[a-z]+#mov\s+[a-z]+, esp#add\s+[a-z]+, 4#(add|sub)\s+[a-z]+, (2|4)#push\s+[a-z]+#mov\s+[a-z]+, \[esp\+4\]#pop\s+\[esp\]#pop\s+esp"
        self.regexp1 = re.compile(self.pat1)
        self.regexp2 = re.compile(self.pat2)
        self.pattern = "(%s|%s)"%(self.pat1, self.pat2)
        self.regexp = re.compile(self.pattern)
        self.instr_count1 = 6
        self.instr_count2 = 8

    def run(self, body, body_str_lambda):
        def f_eval(chunk):
            i1 = chunk[0]
            i4 = chunk[3]
            i5 = chunk[4]
            assert(i1.op1.type == O_REG and i4.op2.type == O_IMM)
            reg = i1.op1.reg
            imm = i4.op2.imm
            new_op1 = Opnd("esp")
            new_op2 = Opnd(imm)
            mnem = i4.mnem
            if mnem == "add":
                new_instrs = [Add(FAKE_INSTR_ADDR, "add", new_op1, new_op2)]
            elif mnem == "sub":
                new_instrs = [Sub(FAKE_INSTR_ADDR, "sub", new_op1, new_op2)]
            else:
                print "impossible mnem:", mnem
                assert(False)

            if i5.mnem == "xchg":
                icount = self.instr_count1
            elif i5.mnem == "push":
                icount = self.instr_count2

            return (icount, new_instrs)

        (replaced, new_instrs) = peep(body, body_str_lambda, f_eval, self.instr_count1, self.regexp1)

        if replaced == 0:
            (replaced, new_instrs) = peep(body, body_str_lambda, f_eval, self.instr_count2, self.regexp2)

        return (replaced, new_instrs)

# push reg
# mov reg, esp
# add reg, 4+X
# xchg reg, [esp]
# pop esp
# -> add esp, X
class Peep_add_esp2:
    def __init__(self):

        self.pattern = r"push\s+([a-z]+)#mov\s+\1, esp#add\s+\1, [0-9a-fA-F]+h?#xchg\s+\1, \[esp\]#(pop\s+esp|mov\s+esp, \[esp\])"
        self.regexp = re.compile(self.pattern)
        self.instr_count = 5

    def run(self, body, body_str_lambda):
        def f_eval(chunk):
            i1 = chunk[0]
            i3 = chunk[2]
            esp_op = Opnd("esp")
            assert(i1.op1.type == O_REG)
            assert(i3.op2.type == O_IMM)
            new_imm = i3.op2.imm - 4
            assert(-4 <= new_imm and new_imm <= 4)
            if new_imm < 0:
                new_op2 = Opnd(-new_imm)
                new_instr = Sub(FAKE_INSTR_ADDR, "sub", esp_op, new_op2)
            else:
                new_op2 = Opnd(new_imm)
                new_instr = Add(FAKE_INSTR_ADDR, "add", esp_op, new_op2)

            new_instrs = [new_instr]
            return (self.instr_count, new_instrs)

        return peep(body, body_str_lambda, f_eval, self.instr_count, self.regexp)

# mov reg2, CONST1
# xchg reg1, reg2
# mov reg1, CONST2
# xchg reg1, reg2
# -> mov reg2, CONST2
class Peep_double_mov_xchg:
    def __init__(self):

        self.pattern = "mov\s+[a-z]+, [0-9a-fA-F]+h?#xchg\s+[a-z]+, [a-z]+#mov\s+[a-z]+, [0-9a-fA-F]+h?#xchg\s+[a-z]+, [a-z]+"
        self.regexp = re.compile(self.pattern)
        self.instr_count = 4

    def run(self, body, body_str_lambda):
        def f_eval(chunk):
            i1 = chunk[0]
            i3 = chunk[2]
            assert(i1.op1.type == O_REG)
            assert(i3.op2.type == O_IMM)
            new_instrs = [Mov(FAKE_INSTR_ADDR, "mov", i1.op1, i3.op2)]
            return (self.instr_count, new_instrs)

        return peep(body, body_str_lambda, f_eval, self.instr_count, self.regexp)

# push smth1
# op [esp](, CONST)
# pop smth2
# -> mov smth2, smth1 / op smth2, CONST
# GOTCHA:
# push esp
# (add|sub) [esp], X
# pop reg
# -> mov reg, esp / op reg, X-4
class Peep_push_op_pop:
    def __init__(self):
        self.pattern = "push\s+[^#]+#(add|xor|sub|not|neg|inc|dec)\s+\[esp(\+1)?\](, [0-9a-fA-F]+h?)?#pop\s+[^#]+(#|$)"
        self.regexp = re.compile(self.pattern)
        self.instr_count = 3

    def run(self, body, body_str_lambda):
        def tricky_push_pop(op_i, push_i):
            new_instrs = []

            reg = push_i.op1.reg
            idx = op_i.op1.mem_idx
            assert(idx in [0,1])
            reg_set = REG_TO_REG_SET[reg]
            if idx == 0:
                letter = "l"
            elif idx == 1:
                letter = "h"
            else:
                assert(False)
            
            hits = filter(lambda reg: reg[1]==letter, reg_set)
            assert(hits)
            new_reg = hits[0] 

            #print "old_reg:", reg
            #print "new_reg:", new_reg

            new_op1 = Opnd(new_reg)
            new_op2 = None

            if has_two_ops(op_i):
                new_op2 = Opnd(op_i.op2.text_org)

            op_i.update_ops(new_op1, new_op2)

            new_instrs = [op_i]

            return new_instrs

        def f_eval(chunk):
            i1 = chunk[0]
            i2 = chunk[1]
            i3 = chunk[2]

            both_mem = i1.op1.type == O_MEM and i3.op1.type == O_MEM
            both_same_mem = both_mem and (i1.op1.text == i3.op1.text)

            if both_mem and not both_same_mem:
                return NULL_PAIR

            #ah can be recognized as a number
            if i2.op2 and i2.op2.type != O_IMM:
                return NULL_PAIR

            if i1.bits != i2.bits:
                if i2.op1.mem_idx in [0, 1]:
                    if i2.bits == 8:
                        if i1.op1.type == i3.op1.type == O_REG and i1.op1.reg == i3.op1.reg:
                            new_instrs = tricky_push_pop(i2, i1)
                            return (self.instr_count, new_instrs)
                        else:
                            return NULL_PAIR
                    elif i2.bits == 16:
                        return NULL_PAIR

            new_instrs = []
            if not both_same_mem:
                new_instrs = [Mov(FAKE_INSTR_ADDR, "mov", i3.op1, i1.op1)]

            new_op1 = None
            new_op2 = None

            if i1.op1.type == O_REG and i1.op1.reg in ["sp", "esp"]:
                assert(i2.mnem in ["add", "sub"])
                assert(i2.op2.type == O_IMM)
                fix = 4
                if i1.op1.reg == "sp":
                    fix = 2
                new_op1 = Opnd(i3.op1.text_org)
                new_op2 = Opnd(i2.op2.imm - fix)

            elif has_two_ops(i2):
                #it's a bad idea to share Opnd classes between instructions...
                new_op1 = Opnd(i3.op1.text_org)
                new_op2 = Opnd(i2.op2.text_org)
            
            else:
                new_op1 = Opnd(i3.op1.text_org)

            i2.update_ops(new_op1, new_op2)

            new_instrs += [i2]
            return (self.instr_count, new_instrs)

        return peep(body, body_str_lambda, f_eval, self.instr_count, self.regexp)

#push small 0
#sub byte ptr [esp], 40h (optional)
#mov ah, [esp]
#add esp, 2
#->mov ah, 0 / sub ah, 40h
class Peep_push_small:
    def __init__(self):

        self.pattern = "push [0-9a-fA-F]+h?#((add|xor|sub|not|neg|inc|dec) \[esp(\+1)?\](, [0-9a-fA-F]+h?)?#)?mov [a-z]+, \[esp\]#add esp, (2|4)"
        self.regexp = re.compile(self.pattern)
        self.instr_count = 4

    def run(self, body, body_str_lambda):
        def is_ok(push_i, mov_i):
            if push_i.op1.type != O_IMM:
                return False

            if mov_i.op1.type == O_REG and mov_i.op1.reg not in REG_8BIT:
                return False
            return True

        def f_eval(chunk):
            snd = chunk[1]
            if snd.mnem != "mov":
                return f_eval1(chunk)

            push_i = chunk[0]
            mov_i = snd
            
            if not is_ok(push_i, mov_i):
                return NULL_PAIR

            imm = push_i.op1.imm & 0xFF
            imm_op = Opnd(imm)
            new_instrs = [Mov(FAKE_INSTR_ADDR, "mov", mov_i.op1, imm_op)]

            return (self.instr_count-1, new_instrs)

        def f_eval1(chunk):
            push_i = chunk[0]
            op_i = chunk[1]
            mov_i = chunk[2]
            add_i = chunk[3]

            if not is_ok(push_i, mov_i) or (op_i.op2 and op_i.op2.type != O_IMM):
                return NULL_PAIR

            imm = push_i.op1.imm
            if op_i.op1.mem_type == O_MEM_REG_PLUS_INDEX:
                idx = op_i.op1.mem_idx
                if idx == 0:
                    imm = imm & 0xFF
                elif idx == 1:
                    imm = imm >> 8
                else:
                    print "bad idx:", idx
                    assert(False)
            else:
                assert(False)

            imm_op = Opnd(imm)
            new_instrs = [Mov(FAKE_INSTR_ADDR, "mov", mov_i.op1, imm_op)]

            #don't share Opnd classes between instructions
            new_op1 = Opnd(mov_i.op1.text_org)
            new_op2 = None

            if has_two_ops(op_i):
                new_op2 = Opnd(op_i.op2.text_org)

            op_i.update_ops(new_op1, new_op2)

            new_instrs += [op_i]
            return (self.instr_count, new_instrs)

        return peep(body, body_str_lambda, f_eval, self.instr_count, self.regexp)


# xor reg/mem, const1
# xor reg/mem, const2
# -> xor reg/mem, const1 xor const2
# these are rare enough to make it a peephole opt.
class Peep_xors:
    def __init__(self):
        self.pattern = r"xor\s+([^,]+), [0-9a-fA-F]+h?#xor\s+\1, [0-9a-fA-F]+h?"
        self.regexp = re.compile(self.pattern)
        self.instr_count = 2

    def run(self, body, body_str_lambda):
        def f_eval(chunk):
            i1 = chunk[0]
            i2 = chunk[1]

            #if i1.op1.text != i2.op1.text:
            #    return (0, None)

            #FIXME: ah as number
            if i1.op2.type != O_IMM or i2.op2.type != O_IMM:
                return NULL_PAIR
            
            new_imm = i1.op2.imm ^ i2.op2.imm
            if new_imm != 0:
                new_op2 = Opnd(new_imm)
                new_instrs = [Xor(FAKE_INSTR_ADDR, "xor", i1.op1, new_op2, i1.bits)]
            else:
                new_instrs = []
            return (self.instr_count, new_instrs)

        return peep(body, body_str_lambda, f_eval, self.instr_count, self.regexp)

# mov reg, CONST
# add reg1, reg2
# op [reg1], smth
# -> op [reg2+CONST], smth
# in order to correcly handle many consecutive op [reg1], X,
# we need to push mov/add down, since new op [reg1], X may emerge below
# as a result of optimisations

class Peep_add_reg_mem:
    def __init__(self):
        self.pattern = r"mov\s+([a-z]+), [0-9a-fA-F]+h?#add \1, [a-z]+#(([a-z]+ (\[\1\]|[a-z]+), ([a-z]+|\[[a-z]+\]|[0-9a-fA-F]+h?))|((inc|dec|not|neg) \[\1\]))"
        self.regexp = re.compile(self.pattern)
        self.instr_count = 3

    def run(self, body, body_str_lambda):
        def gen_new_op(reg2, imm):
            if imm != 0:
                op_txt = "[%s+%x]"%(reg2, imm)
            else:
                op_txt = "[%s]"%reg2
            new_op_mem = Opnd(op_txt)
            return new_op_mem

        #this handles 1arg ops
        def f_eval1(chunk):
            mov_i = chunk[0]
            add_i = chunk[1]
            op_i = chunk[2]

            assert(op_i.op2 == None)

            if mov_i.op2.type != O_IMM or add_i.op2.type != O_REG:
                return NULL_PAIR
            
            reg2 = add_i.op2.reg
            imm = mov_i.op2.imm
            new_op_mem = gen_new_op(reg2, imm)
            op_i.update_ops(new_op_mem, None)

            return (self.instr_count, [op_i, mov_i, add_i])

        #2arg ops
        def f_eval2(chunk):
            mov_i = chunk[0]
            add_i = chunk[1]
            op_i = chunk[2]

            if add_i.op2.type != O_REG:
                return NULL_PAIR
            if mov_i.op1.reg != add_i.op1.reg:
                return NULL_PAIR
            if op_i.op1.type == O_REG and op_i.op2.type == O_IMM:
                return NULL_PAIR

            reg = mov_i.op1.reg

            if op_i.op1.type == O_MEM:
                op_mem = op_i.op1
                if op_i.op2.type == O_REG:
                    op_reg = op_i.op2
                elif op_i.op2.type == O_IMM:
                    op_imm = op_i.op2
                else:
                    assert(False)
            elif op_i.op1.type == O_REG:
                op_reg = op_i.op1
                assert(op_i.op2.type == O_MEM)
                op_mem = op_i.op2
            else:
                print op_i.dis
                assert(False)
            
            if reg not in op_mem.regs or len(op_mem.regs)>1:
                return NULL_PAIR

            reg2 = add_i.op2.reg
            imm = mov_i.op2.imm
            new_op_mem = gen_new_op(reg2, imm)
            if op_i.op1.type == O_MEM:
                if op_i.op2.type == O_REG:
                    op_i.update_ops(new_op_mem, op_reg)
                elif op_i.op2.type == O_IMM:
                    op_i.update_ops(new_op_mem, op_imm)
            else:
                op_i.update_ops(op_reg, new_op_mem)

            return (self.instr_count, [op_i, mov_i, add_i])

        op_i = body[2]
        if op_i.op2 == None:
            f = f_eval1
        else:
            f = f_eval2

        return peep(body, body_str_lambda, f, self.instr_count, self.regexp)

# mov reg, reg
# -> nop
class Peep_nop:
    def __init__(self):
        self.pattern = r"mov\s+([a-z]+), \1"
        self.regexp = re.compile(self.pattern)
        self.instr_count = 1

    def run(self, body, body_str_lambda):
        def f_eval(chunk):
            mov_i = chunk[0]
            if mov_i.op1.type != mov_i.op2.type:
                return NULL_PAIR
            if mov_i.op1.type != O_REG or mov_i.op1.reg != mov_i.op2.reg:
                return NULL_PAIR

            new_instrs = []
            return (self.instr_count, new_instrs)

        return peep(body, body_str_lambda, f_eval, self.instr_count, self.regexp)

# push reg
# mov reg, [esp+2|4]
# pop [esp]
# -> xchg reg, [esp]
class Peep_xchg:
    def __init__(self):
        self.pattern = r"push ([a-z]+)#mov\s+\1, \[esp\+(2|4)\]#pop\s+\[esp\]"
        self.regexp = re.compile(self.pattern)
        self.instr_count = 3

    def run(self, body, body_str_lambda):
        def f_eval(chunk):
            push_i = chunk[0]
            mov_i = chunk[1]
            if push_i.op1.type != O_REG:
                return NULL_PAIR
            
            assert(mov_i.op1.type == O_REG)

            reg = push_i.op1.reg
            if reg != mov_i.op1.reg:
                return NULL_PAIR
            
            if (mov_i.op2.mem_idx == 2 and reg not in REG_16BIT) and (mov_i.op2.mem_idx == 4 and reg not in REG_32BIT):
                return NULL_PAIR

            op1 = push_i.op1
            new_op2 = Opnd("[esp]")
            new_instrs = [Xchg(FAKE_INSTR_ADDR, "xchg", op1, new_op2)] 
            return (self.instr_count, new_instrs)

        return peep(body, body_str_lambda, f_eval, self.instr_count, self.regexp)

#push bx 
#mov bl, dl
#mov dl, cl
#mov cl, bl
#pop bx
#->xchg cl, dl
class Peep_xchg2:
    def __init__(self):
        self.pattern = r"push ([a-z]+)#(mov\s+[a-z]+, [a-z]+#){3}pop \1"
        self.regexp = re.compile(self.pattern)
        self.instr_count = 5

    def run(self, body, body_str_lambda):
        def f_eval(chunk):
            push = chunk[0]
            mov1 = chunk[1]
            mov2 = chunk[2]
            mov3 = chunk[3]
            pop = chunk[4]

            if push.op1.type != O_REG or pop.op1.type != O_REG or push.op1.reg != pop.op1.reg:
                return NULL_PAIR
            
            if mov1.op1.reg != mov3.op2.reg or mov1.op2.reg != mov2.op1.reg or mov2.op2.reg != mov3.op1.reg:
                return NULL_PAIR

            reg1 = push.op1.reg
            reg2 = mov1.op1.reg
            if reg2 not in REG_TO_REG_SET[reg1]:
                return NULL_PAIR
            
            new_instrs = [Xchg(FAKE_INSTR_ADDR, "xchg", mov1.op2, mov3.op1)] 
            return (self.instr_count, new_instrs)

        return peep(body, body_str_lambda, f_eval, self.instr_count, self.regexp)

#push    dx
#mov     dl, cl
#mov     cl, [esp+2]
#mov     [esp+2], dl
#pop     dx
#-> xchg cl, [esp]
class Peep_xchg3: #FIXME: this is Peep_xchg2
    def __init__(self):
        self.pattern = r"push ([a-z]+)#mov ([a-z]+), ([a-z]+)#mov \3, \[esp\+(\d)\]#mov \[esp\+\4\], \2#pop \1"
        self.regexp = re.compile(self.pattern)
        self.instr_count = 5

    def run(self, body, body_str_lambda):
        def f_eval(chunk):
            push = chunk[0]
            mov1 = chunk[1]
            mov2 = chunk[2]
            mov3 = chunk[3]
            pop = chunk[4]

            reg1 = push.op1.reg
            reg2 = mov1.op1.reg
            if reg2 not in REG_TO_REG_SET[reg1]:
                return NULL_PAIR

            if push.bits == 8:
                stack_fix = -1
            elif push.bits == 16:
                stack_fix = -2
            elif push.bits == 32:
                stack_fix = -4
            else:
                assert(False)
            
            new_op2 = mov2.op2
            new_op2.update_mem_idx(stack_fix)

            new_instrs = [Xchg(FAKE_INSTR_ADDR, "xchg", mov1.op2, new_op2)] 
            return (self.instr_count, new_instrs)

        return peep(body, body_str_lambda, f_eval, self.instr_count, self.regexp)

#push reg|mem
#mov reg|mem, eax
#pop eax
#->xchg eax, reg|mem
#mem can't dereference esp
class Peep_xchg4:
    def __init__(self):
        self.pattern = r"push ([^#]+)#mov \1, ([a-z]+)#pop \2"
        self.regexp = re.compile(self.pattern)
        self.instr_count = 3

    def run(self, body, body_str_lambda):
        def f_eval(chunk):
            push = chunk[0]
            mov = chunk[1]
            pop = chunk[2]

            if mov.bits != pop.bits:
                return NULL_PAIR

            op1 = push.op1
            if op1.type == O_MEM:
                if "esp" in op1.regs:
                    return NULL_PAIR

            new_instrs = [Xchg(FAKE_INSTR_ADDR, "xchg", mov.op2, mov.op1)] 
            return (self.instr_count, new_instrs)

        return peep(body, body_str_lambda, f_eval, self.instr_count, self.regexp)

#oush reg1
#mov reg1, X
#xchg reg1, reg2
#pop reg1
#->mov reg2, X
class Peep_xchg5:
    def __init__(self):
        self.pattern = r"push ([a-z]+)#mov \1, [0-9a-fA-F]+h?#xchg \1, ([a-z]+)#pop \1"
        self.regexp = re.compile(self.pattern)
        self.instr_count = 4

    def run(self, body, body_str_lambda):
        def f_eval(chunk):
            mov = chunk[1]
            xchg = chunk[2]
            pop = chunk[3]

            new_instrs = [Mov(FAKE_INSTR_ADDR, "mov", xchg.op2, mov.op2)] 
            return (self.instr_count, new_instrs)

        return peep(body, body_str_lambda, f_eval, self.instr_count, self.regexp)

#mov bl, dl
#mov dl, 89h
#xchg dl, bl
#->mov bl, 89h
class Peep_xchg6:
    def __init__(self):
        self.pattern = r"mov ([a-z]+), ([a-z]+)#mov \2, [^#]+#xchg \2, \1"
        self.regexp = re.compile(self.pattern)
        self.instr_count = 3

    def run(self, body, body_str_lambda):
        def f_eval(chunk):
            mov1 = chunk[0]
            mov2 = chunk[1]

            new_instrs = [Mov(FAKE_INSTR_ADDR, "mov", mov1.op1, mov2.op2)] 
            return (self.instr_count, new_instrs)

        return peep(body, body_str_lambda, f_eval, self.instr_count, self.regexp)

#xor reg1, reg2|mem
#xor reg2|mem, reg1
#xor reg1, reg2|mem
#-> xchg reg1, reg2|mem
class Peep_xor_xchg:
    def __init__(self):
        self.pattern = r"xor ([^,]+), ([^#]+)#xor \2, \1#xor \1, \2"
        self.regexp = re.compile(self.pattern)
        self.instr_count = 3

    def run(self, body, body_str_lambda):
        def f_eval(chunk):
            xor1 = chunk[0]
            xor2 = chunk[1]
            xor3 = chunk[2]

            if xor1.op2.type == O_IMM:
                return NULL_PAIR

            new_instrs = [Xchg(FAKE_INSTR_ADDR, "xchg", xor1.op2, xor1.op1)] 
            return (self.instr_count, new_instrs)

        return peep(body, body_str_lambda, f_eval, self.instr_count, self.regexp)

# xchg reg, reg/mem
# op reg
# xchg reg, reg/mem
# -> op reg/mem
class Peep_double_xchg:
    def __init__(self):
        self.pattern = r"xchg ([a-z]+), ([^#]+)#(((not|neg|inc|dec) [a-z]+)|((mov|add|sub) \1, [0-9a-fA-F]+h?))#xchg (\1|\2), (\2|\1)(#|$)"
        self.regexp = re.compile(self.pattern)
        self.instr_count = 3

    def run(self, body, body_str_lambda):
        def f_eval(chunk):
            i1 = chunk[0]
            i2 = chunk[1]
            i3 = chunk[2]
            if i3.op1.text == i3.op2.text:
                return NULL_PAIR
            """
            if i1.op1.reg != i3.op1.reg:
                return NULL_PAIR
            if i1.op2.text != i3.op2.text:
                return NULL_PAIR
            """

            if i2.op1 == None or i2.op1.type != O_REG:
                return NULL_PAIR

            has_two_ops = False
            if i2.mnem in ["mov", "add", "sub"]:
                if i2.op2.type != O_IMM:
                    return NULL_PAIR
                has_two_ops = True

            #handle case:
            #xchg cl, [esp]
            #not cx
            #xchg cl, [esp]
            reg1 = i1.op1.reg
            reg2 = i2.op1.reg
            
            if reg2 == reg1 or reg2 in REG_TO_REG_SET[reg1]:
                new_op = i1.op2
            elif i1.op2.type == O_REG and i1.op2.reg == reg2:
                new_op = i1.op1
            else:
                print "Peep_double_xchg:", body_str_lambda
                assert(False)

            if has_two_ops:
                i2.update_ops(new_op, i2.op2, bits=i1.bits)
            else:
                i2.update_ops(new_op, None, bits=i1.bits)
            new_instrs = [i2]

            return (self.instr_count, new_instrs)

        return peep(body, body_str_lambda, f_eval, self.instr_count, self.regexp)

#push bx
#mov bh, al
#not bh
#mov al, bh
#pop bx
#->not al
class Peep_proxy_op:
    def __init__(self):
        self.pattern = r"push ([a-z]+)#mov ([a-z]+), ([a-z]+)#(not|neg|inc|dec) \2#mov \3, \2#pop \1"
        self.regexp = re.compile(self.pattern)
        self.instr_count = 5

    def run(self, body, body_str_lambda):
        def f_eval(chunk):
            push = chunk[0]
            mov1 = chunk[1]
            op_i = chunk[2]
            mov2 = chunk[3]
            pop = chunk[4]

            op_i.update_ops(mov1.op2, None)
            new_instrs = [op_i]

            return (self.instr_count, new_instrs)

        return peep(body, body_str_lambda, f_eval, self.instr_count, self.regexp)

#push reg
#mov reg, esp
#xchg reg, [esp]
#pop esp | mov esp, [esp]
#-> sub esp, 4
class Peep_sub_esp_4:
    def __init__(self):
        self.pattern = r"push ([a-z]+)#mov \1, esp#xchg \1, \[esp\]#(pop esp|mov esp, \[esp\])"
        self.regexp = re.compile(self.pattern)
        self.instr_count = 4

    def run(self, body, body_str_lambda):
        def f_eval(chunk):
            sub = Sub(FAKE_INSTR_ADDR, "sub", Opnd("esp"), Opnd(4)) 
            new_instrs = [sub]

            return (self.instr_count, new_instrs)

        return peep(body, body_str_lambda, f_eval, self.instr_count, self.regexp)

#push reg
#mov reg, 0
#sub reg, X
#xchg reg, X | mov X, reg (X can be mem)
#pop reg
#-> neg X
class Peep_neg1:
    def __init__(self):
        self.pattern = r"push ([a-z]+)#mov \1, 0#sub \1, ([^#]+)#(xchg \1, \2|mov \2, \1)#pop \1"
        self.regexp = re.compile(self.pattern)
        self.instr_count = 5

    def run(self, body, body_str_lambda):
        def f_eval(chunk):
            sub = body[2]
            bits = sub.bits
            neg = Neg(FAKE_INSTR_ADDR, "neg", sub.op2, None, bits=bits)
            new_instrs = [neg]

            return (self.instr_count, new_instrs)

        return peep(body, body_str_lambda, f_eval, self.instr_count, self.regexp)

#dec X (sub X, 1)| not X
#not X | inc X (add X, 1)
#-> neg X
class Peep_neg2:
    def __init__(self):
        #regexp matches:
        # dec not -> neg
        # not not -> nop
        # dec inc -> nop
        # not inc -> neg
        self.pattern = r"(dec|not|sub) ([^#]+)(, 1)?#(not|inc|add) \2(, 1)?($|#)"
        self.regexp = re.compile(self.pattern)
        self.instr_count = 2

    def run(self, body, body_str_lambda):
        def f_eval(chunk):
            i1 = body[0]
            i2 = body[1]
            if i1.bits != i2.bits:
                return NULL_PAIR
            bits = i1.bits
            op1 = i1.op1
            nops = [("not", "not"), ("dec", "inc"), ("sub", "add"), ("dec", "add"), ("sub", "inc")]
            nop = False
            for mnem1, mnem2 in nops:
                if (i1.mnem == mnem1 and i2.mnem == mnem2):
                    nop = True
                    break

            if nop:
                new_instrs = []
            elif (i1.mnem in ["dec", "sub"] and i2.mnem == "not") or (i1.mnem == "not" and i2.mnem in ["inc", "add"]):
                neg = Neg(FAKE_INSTR_ADDR, "neg", op1, None, bits=bits)
                new_instrs = [neg]
            else:
                print "Peep_neg2 impossible"
                print body_str_lambda
                assert(False)
            
            return (self.instr_count, new_instrs)

        return peep(body, body_str_lambda, f_eval, self.instr_count, self.regexp)

# push 0
# sub [esp], reg
# pop reg
# -> neg reg
class Peep_neg3:
    def __init__(self):
        self.pattern = r"push 0#sub \[esp\], ([a-z]+)#pop \1"
        self.regexp = re.compile(self.pattern)
        self.instr_count = 3

    def run(self, body, body_str_lambda):
        def f_eval(chunk):
            sub = body[1]
            bits = sub.bits
            neg = Neg(FAKE_INSTR_ADDR, "neg", sub.op2, None, bits=bits)
            new_instrs = [neg]

            return (self.instr_count, new_instrs)

        return peep(body, body_str_lambda, f_eval, self.instr_count, self.regexp)

#push eax
#push bx
#mov bl, bh (optional)
#not bl
#mov al, bl
#pop bx
#mov bh, al
#pop eax
#->not bh
class Peep_proxy_op2:
    def __init__(self):
        self.pattern = r"push ([a-z]+)#push ([a-z]+)#(mov ([a-z]+), ([a-z]+)#)?(not|inc|dec|neg) [a-z]+#mov ([a-z]+), [a-z]+#pop \2#mov [a-z]+, [a-z]+#pop \1"
        self.regexp = re.compile(self.pattern)
        self.instr_count = None

    def run(self, body, body_str_lambda):
        def f_eval1(chunk):
            push1 = chunk[0]
            push2 = chunk[1]
            op_i = chunk[2]
            mov = chunk[3]
            mov2 = chunk[5]

            if not push1.op1.reg in REG_TO_REG_SET[mov.op1.reg]:
                return NULL_PAIR
            if not push2.op1.reg in REG_TO_REG_SET[mov.op2.reg]:
                return NULL_PAIR
            
            if mov.op1.reg != mov2.op2.reg or mov.op2.reg != mov2.op1.reg or op_i.op1.reg != mov.op2.reg:
                return NULL_PAIR

            return (7, [op_i])

        def f_eval2(chunk):
            push1 = chunk[0]
            push2 = chunk[1]
            mov1 = chunk[2]
            op_i = chunk[3]
            mov2 = chunk[4]
            mov3 = chunk[6]

            if mov3.op2.reg != mov2.op1.reg or mov1.op1.reg != mov2.op2.reg or op_i.op1.reg != mov1.op1.reg:
                return NULL_PAIR

            if not push1.op1.reg in REG_TO_REG_SET[mov2.op1.reg]:
                return NULL_PAIR
            if not push2.op1.reg in REG_TO_REG_SET[mov1.op1.reg]:
                return NULL_PAIR

            op_i.update_ops(mov1.op2, None)
            new_instrs = [op_i]

            return (8, new_instrs)
        
        instr = body[2]
        if instr.mnem == "mov":
            f = f_eval2
        elif instr.mnem in ["not", "inc", "dec", "neg"]:
            f = f_eval1
        else:
            assert(False)

        return peep(body, body_str_lambda, f, self.instr_count, self.regexp)

#xchg dl, cl
#mov dl, cl
#->mov cl, dl
class Peep_xchg_mov:
    def __init__(self):
        self.pattern = r"xchg ([a-z]+), ([a-z]+)#mov \1, \2"
        self.regexp = re.compile(self.pattern)
        self.instr_count = 2

    def run(self, body, body_str_lambda):
        def f_eval(chunk):
            xchg = chunk[0]
            mov = chunk[1]

            mov.update_ops(mov.op2, mov.op1)
            new_instrs = [mov]

            return (self.instr_count, new_instrs)

        return peep(body, body_str_lambda, f_eval, self.instr_count, self.regexp)

#mov dh, ch
#xchg ch, dh
#-> mov dh, ch
class Peep_xchg_nop:
    def __init__(self):
        self.pattern = r"mov ([a-z]+), ([a-z]+)#xchg \2, \1"
        self.regexp = re.compile(self.pattern)
        self.instr_count = 2

    def run(self, body, body_str_lambda):
        def f_eval(chunk):
            mov = chunk[0]
            xchg = chunk[1]

            new_instrs = [mov]

            return (self.instr_count, new_instrs)

        return peep(body, body_str_lambda, f_eval, self.instr_count, self.regexp)

#push ecx
#mov cl, dl
#mov ah, cl
#pop ecx
#->mov ah, dl
#this would be simplified by other passes eventually, but we need to kill it
#ASAP because after constant propagation things can get messy (xchg split into multiple pieces)
class Peep_xchg_part:
    def __init__(self):
        self.pattern = r"push ([a-z]+)#mov ([a-z]+), ([a-z]+)#mov ([a-z]+), \2#pop \1"
        self.regexp = re.compile(self.pattern)
        self.instr_count = 4

    def run(self, body, body_str_lambda):
        def f_eval(chunk):
            push = chunk[0]
            mov1 = chunk[1]
            mov2 = chunk[2]

            if mov1.op2.type != O_REG:
                return NULL_PAIR

            push_reg = push.op1.reg
            reg = mov1.op1.reg
            if reg not in REG_TO_REG_SET[push_reg]:
                return NULL_PAIR

            mov = Mov(FAKE_INSTR_ADDR, "mov", mov2.op1, mov1.op2, bits=mov1.bits)
            new_instrs = [mov]

            return (self.instr_count, new_instrs)

        return peep(body, body_str_lambda, f_eval, self.instr_count, self.regexp)

# push const
# ... (esp is not read/written)
# pop reg
# -> mov reg, const (push/pop removed, mov at the end)
class Peep_push_const_pop_reg:
    def __init__(self):
        #we want at least one instruction between push/pop
        self.pattern = r"push ([0-9a-fA-F]+h?)#(?!.*(?:push|esp))(?!pop).*?#pop ([a-z]+)" 
        self.regexp = re.compile(self.pattern)
        self.instr_count = None

    def run(self, body, body_str_lambda):
        print "XXXX!"
        push = body[0]

        if push.op1.type != O_IMM:
            return NULL_PAIR

        imm = push.op1.imm

        #search for pop
        print "push:", push.dump()
        pop = None
        new = []
        for instr in body[1:]:
            if instr.mnem == "pop":
                pop = instr
                break
            new.append(instr)
        assert(pop != None)
        print pop.dump()
        bits = pop.bits
        assert(imm < (1<<bits))
        #drop push/pop
        mov = Mov(FAKE_INSTR_ADDR, "mov", pop.op1, push.op1, bits=pop.bits)
        new.append(mov)

        replace_len = len(new)+1 #+push+pop-mov

        return (replace_len, new)

def peep(body, body_str_lambda, f_eval, instr_count, regexp):
    if len(body)<instr_count:
        return NULL_PAIR

    chunk = body[:instr_count]

    disasm = body_str_lambda

    #regexp is a compiled RE
    found = regexp.match(disasm)

    if found:
        consumed, new_instrs = f_eval(chunk)
        return (consumed, new_instrs)

    return NULL_PAIR

# mutated is a per pass flag
# 'dirty' is a whole pass flag
def peephole(dbb):
    dirty = False
    while True:
        dbb, mutated = peephole_one_pass(dbb)
        if not mutated:
            break
        dirty = True

    return dbb, dirty


def calc_body_str_and_seps(body):
    disasms = map(lambda i: i.get_clean_dis(), body)
    sep_positions = []
    sep_pos = -len(INSTR_SEPARATOR)
    for disasm in disasms:
        sep_pos += len(INSTR_SEPARATOR)
        sep_pos += len(disasm)
        sep_positions.append(sep_pos)

    body_str = INSTR_SEPARATOR.join(disasms) + INSTR_SEPARATOR
    sep_positions = [-1] + sep_positions

    return body_str, sep_positions

def pos_to_index(pos, sep_positions):
    for i,sep_pos in enumerate(sep_positions):
        if pos == sep_pos+1:
            return i
    assert(False)

def get_replacements(peep, body, body_str, sep_positions):
    regexp = peep.regexp
    replacements = []
    for m in regexp.finditer(body_str):
        if not m:
            continue

        match = m.group()
        body_str_lambda = match

        pos = m.start()
        i = pos_to_index(pos, sep_positions)
        ptr = body[i:]
        (replaced, new_instrs) = peep.run(ptr, body_str_lambda)

        if replaced == 0:
            continue 

        replacements.append((i, replaced, new_instrs))

    return replacements

peeps = [Peep_pop_reg(), Peep_push_reg(), Peep_push_mov()]
peeps += [Peep_add_esp(), Peep_add_esp2()]
peeps += [Peep_xor_trick(), Peep_double_mov_xchg(), Peep_push_op_pop()]
peeps += [Peep_xors(), Peep_nop(), Peep_xchg(), Peep_double_xchg()]
peeps += [Peep_add_reg_mem(), Peep_xchg2(), Peep_xchg3(), Peep_xchg4(), Peep_xchg5()] 
peeps += [Peep_push_small(), Peep_xor_xchg(), Peep_proxy_op(), Peep_proxy_op2(), Peep_sub_esp_4()]
peeps += [Peep_partially_defined(), Peep_neg1(), Peep_neg2(), Peep_neg3(), Peep_xchg6(), Peep_xchg_mov(), Peep_xchg_nop()]
peeps += [Peep_xchg_part(), Peep_push_const_pop_reg()]

stats = {}

def peephole_one_pass(dbb):

    body = dbb.body[:]
    new_body = body
    did_change = False
    body_str, sep_positions = calc_body_str_and_seps(body)
    for peep in peeps:
        replacements = get_replacements(peep, body, body_str, sep_positions)
    
        if replacements == []:
            continue
        
        cname = peep.__class__.__name__
        if dbb.get_addr() == g_watched_dbb_addr:
            print cname
            for i in body:
                print i.dump()
            print "="*5

        """
        if cname in stats:
            stats[cname] += 1
        else:
            stats[cname] = 1
            print "name:", cname
            print "match:", match
            print "pattern:", regexp.pattern
            print "pos:", pos
            print "replaced:", replaced
        """

        did_change = True

        new_body = []
        delta = 0
        for i,replaced,new_instrs in replacements:
            n = replaced
            i = i+delta
            new_body = body[:i] + new_instrs + body[i+n:]
            body = new_body
            delta = delta-n+len(new_instrs)
        
        body = new_body
        body_str, sep_positions = calc_body_str_and_seps(body)
    

    dbb.set_body(new_body)
    return dbb, did_change

def is_push(instr):
    return instr.mnem == "push"

def is_push_reg(instr):
    return instr.mnem == "push" and instr.op1.type == O_REG

def is_pop(instr):
    return instr.mnem == "pop" 

def is_pop_reg(instr):
    return is_pop(instr) and instr.op1.type == O_REG

def push_pop_pairs(dbb):
    dead = set()
    instr_stack = []
    mod_regs_stack = []
    mod_regs = set()
    for instr in dbb.body:
        if is_push(instr):
            instr_stack.append(instr)
            mod_regs_stack.append(mod_regs)
            mod_regs = set()
        elif is_pop(instr):
            if len(instr_stack) == 0:
                continue
            push = instr_stack.pop()
            if is_pop_reg(instr):
                reg = instr.op1.reg
                if is_push_reg(push) and push.op1.reg == reg and reg not in mod_regs:
                    dead.add(push)
                    dead.add(instr)
            else:
                pass
            
            mod_regs = mod_regs | mod_regs_stack.pop()
        else:
            affected = set()
            for reg in instr.modified_regs:
                affected |= REG_UNSET_AFFECTED[reg][reg]
            mod_regs |= affected
            referenced_regs = instr.read_regs | instr.modified_regs
            if "esp" in referenced_regs:
                # don't handle tricky cases, just clear the stacks 
                instr_stack = []
                mod_regs_stack = []
    
    new_body = filter(lambda instr: instr not in dead, dbb.body)
    dbb.set_body(new_body)
    return dbb

def is_reg_reg(instr):
    return has_two_ops(instr) and instr.op1.type == instr.op2.type == O_REG

def is_reg_imm(instr):
    return has_two_ops(instr) and instr.op1.type == O_REG and instr.op2.type == O_IMM


def consume_add_sub(chunk):
    if len(chunk)<2:
        return (0, None)
    reg = None
    other_reg = None
    other_instr = None
    consumed = 0
    instr = chunk[0]
    imms = []
    supported_ops = ["add", "sub"]
    if instr.mnem in supported_ops:
        if instr.op1.type in [O_REG, O_MEM]:
            reg = instr.op1.text
            bits = instr.bits
            if instr.op2.type == O_REG:
                other_reg = instr.op2.reg
                other_instr = instr
            elif instr.op2.type == O_IMM: 
                imms.append((instr.mnem, instr.op2.imm))
            else:
                return (0, None)
        else:
            return (0, None)

        consumed = 1
    else:
        return (0, None)

    for instr in chunk[1:]:
        if instr.mnem in supported_ops:
            if instr.op1.type in [O_REG, O_MEM]:
                if reg != instr.op1.text:
                    #print "reg:'%s' other:'%s'"%(reg, instr.op1.text)
                    break

                if instr.op2.type == O_REG:
                    if other_reg == None:
                        other_reg = instr.op2.reg
                        other_instr = instr

                    else:
                        break

                elif instr.op2.type == O_IMM: 
                    imms.append((instr.mnem, instr.op2.imm))

                else:
                    break

                consumed += 1
            else:
                break
        else:
            break
    
    assert(bits in [8, 16, 32])

    result = 0
    N = 1<<bits
    for mnem, val in imms:
        if mnem=="sub":
            result -= val
        elif mnem == "add":
            result += val
        else:
            assert(False)

        if result < 0:
            result = N + result

        result %= N

    negative = False
    if result & (N>>1):
        negative = True
        result = (~result)+1+N

    new_instrs = []

    if result != 0:
        new_op1 = chunk[0].op1
        new_op2 = Opnd(result)
        #we prefer sub X, 1, over add X, 0ffffffffh
        if negative:
            instr = Sub(FAKE_INSTR_ADDR, "sub", new_op1, new_op2, bits=bits)
        else:
            instr = Add(FAKE_INSTR_ADDR, "add", new_op1, new_op2, bits=bits)
        new_instrs += [instr]

    if other_reg:
        new_instrs += [other_instr]

    return (consumed, new_instrs)

def iter_consume(dbb, f_consume):
    while True:
        dbb, did_change = consume(dbb, f_consume)
        if not did_change:
            break
    return dbb

def consume(dbb, f_consume):
    body = dbb.body
    i = 0
    new_body = []
    did_change = False
    while i<len(body):
        (consumed, new_instrs) = f_consume(body[i:])

        if consumed == 0:
            new_instrs = [body[i]]
            i += 1
        else:
            i += consumed
            did_change = True

        new_body += new_instrs

    dbb.set_body(new_body)
    return dbb, did_change

# special case folding
def folding(dbb):
    dbb, did_change = consume(dbb, consume_add_sub)
    return dbb

# push reg
# op [esp+off], smth
# pop reg
# -> op [esp+off-4], smth
# mutiple iterations will reduce it to op [esp], smth
def consume_stack_trick(chunk):
    if len(chunk)<3:
        return NULL_PAIR

    new_instrs = []
    instr = chunk[0]

    if not is_push_reg(instr):
        return NULL_PAIR

    reg = instr.op1.reg
    consumed = 1

    if reg in REG_32BIT:
        stack_fix = -4
    elif reg in REG_16BIT:
        stack_fix = -2
    else:
        assert(False)

    for instr in chunk[1:]:
        if instr.mnem in ["add", "sub", "xor"]:
            if instr.op1.type != O_MEM or instr.op2.type != O_IMM:
                return NULL_PAIR
            
            if instr.op1.mem_type != O_MEM_REG_PLUS_INDEX or (instr.op1.mem_idx + stack_fix < 0):
                return NULL_PAIR

            mem_reg = instr.op1.mem_reg
            if mem_reg != "esp":
                return NULL_PAIR

            consumed += 1
            new_instrs.append(instr)
        elif instr.mnem == "pop":
            if not is_pop_reg(instr):
                return NULL_PAIR
            popped_reg = instr.op1.reg
            if popped_reg != reg:
                return NULL_PAIR
            consumed += 1
            break
        else:
            #only way "out" is through "pop" instruction...
            return NULL_PAIR
    
    updated = []
    for instr in new_instrs:
        instr.op1.update_mem_idx(stack_fix)
        instr.update_disasm()
        updated.append(instr)
    
    return (consumed, updated)

def stack_trick(dbb):
    return iter_consume(dbb, consume_stack_trick) 

# lods
# eax_reg = al, ax, eax
# ebx_reg = bl, bx, ebx
# add/sub/xor eax_reg, ebx_reg|CONST
# add/sub/xor eax_reg, CONST|ebx_reg
# add/sub/xor eax_reg, CONST
# add/sub/xor ebx_reg, eax_reg
# fewer instructions possible, because of optimizations
def extract_decryption(body):
    i1 = body[0]
    if i1.mnem != "lods":
        return empty
    
    asx = "(add|sub|xor)"
    eax_reg = "(al|ax|eax)"
    ebx_reg = "(bl|bx|ebx)"
    const = "[0-9a-fA-F]+h?" 
    re1 = re.compile(asx+"\s+%s, (%s|%s)"%(eax_reg, ebx_reg, const))
    re2 = re1
    re3 = re.compile(asx+"\s+%s, %s"%(eax_reg, ebx_reg))
    re4 = re.compile(asx+"\s+%s, %s"%(ebx_reg, eax_reg))

    consumed = []
    for instr in body[1:]:
        if instr.mnem not in ["add", "sub", "xor"]:
            break
        disasm = instr.dis 
        m = None
        if len(consumed) == 0:
            m = re.match(re1, disasm)
        else:
            m = re.match(re2, disasm)
            if m == None:
                m = re.match(re3, disasm)
            if m == None:
                m = re.match(re4, disasm)
        
        if not m:
            break

        consumed.append(instr)
    
    n = len(consumed)
    assert(n<=4)
    return consumed

# remove parameter decryption stuff for lods handlers
# remove last lodsb instruction
# *** RETURNS NEW DBB
def remove_irrelevant(dbb):
    body = dbb.body
    i1 = body[0]
    last_instr = body[-1]
    decrypt_instrs = []
    if i1.mnem == "lods":
        decrypt_instrs = extract_decryption(body)
        new_body = filter(lambda instr: instr not in decrypt_instrs, body)
    else:
        new_body = body
    
    #remove last lodsb, if it's present
    #jump handler has multiple BBs, so lodsb won't be in first BB
    if last_instr.mnem == "lods":
        new_body = new_body[:-1]

    new_dbb = DBB()
    #this is necessary for empty handlers
    new_dbb.set_addr(dbb.get_addr())
    new_dbb.set_body(new_body)

    return new_dbb, decrypt_instrs

##################################################
# interleave deobfu/emulator to decide jumps
##################################################

#returns a list of bool values representing jump directions
def decide_jumps(dbb):

    visited = set()

    ctx = emu.emu_init_ctx()

    decided = []

    while True:
        if dbb.child1 == dbb.child2 == None:
            break

        if dbb in visited:
            print "LOOP!"
            assert(False)   #something must be wrong :(
        
        visited.add(dbb)
        last_i = dbb.body[-1]
        
        #it's possible to have BBs not ending with Jxx
        #clean them anyway
        dbb2 = DBB()
        body = copy.deepcopy(dbb.body[:])
        dbb2.set_body(body)

        if len(dbb.body)>2 and last_i.is_jxx():
            trimmed_dbb = dbb2.trim_jxx()
            nice_dbb = run_all_opts(trimmed_dbb)
            nice_dbb = dbb.untrim_jxx(nice_dbb)
        else:
            nice_dbb = run_all_opts(dbb2)

        #for BBs not ending with Jxx, taken = True
        taken = emu.emu_decide_jump(nice_dbb, ctx)
        
        #print "taken:", taken

        if taken == None:
            #print dbb.dump()
            #print "DECIDE FAIL!"
            break

        if taken:
            dbb = dbb.true_branch()
        else:
            dbb = dbb.false_branch()

        decided.append(taken)
    
    return decided

def cut_branches(dbb, decided):
    assert(dbb.is_multibranch())

    new_dbb = DBB()
    new_body = []
    
    #collect to the end, or first undecided jump
    for taken in decided+[None]:    #+None to collect the last BB
        body = dbb.body
        last_i = body[-1]
        if last_i.is_jxx() and taken != None:
            body = body[:-1]

        new_body += body
        
        if taken == None:
            break

        if taken:
            dbb = dbb.true_branch()
        else:
            dbb = dbb.false_branch()
    
    new_dbb.set_body(new_body)

    return new_dbb

def cut_and_clean(root):
    
    if root.child1 == root.child2 == None:
        return root

    decided = decide_jumps(root)
    new_dbb = cut_branches(root, decided)

    return new_dbb 
