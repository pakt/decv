import idc
import idautils 
import idaapi


MAX_USER_ADDR = 0x7fffffff
FAKE_INSTR_ADDR = 0x0BADC0DE

# "abstract" basic block class
# we use different subclasses for different tasks
class BB_:

    def __init__(self):
        self.child1 = self.child2 = None
        self.body = []
        self.body_set = set()
        self.org_addr = None

    def get_addr(self):
        return self.org_addr

    def set_addr(self, addr):
        self.org_addr = addr

    def try_to_set_addr(self, addr):
        if self.org_addr == None:
            if type(addr) != int:
                addr = addr.get_addr() 
            self.org_addr = addr

    def add(self, instr):
        self.try_to_set_addr(instr)
        if instr in self.body_set:
            assert(False)

        self.body.append(instr)
        self.body_set.add(instr)
    
    def merge(self, bb):
        self.try_to_set_addr(bb.get_addr())

        if self.body_set.intersection(bb.body_set):
            assert(False)

        self.body += bb.body
        self.body_set.union(bb.body_set)
    
    def empty(self):
        return len(self.body)==0

    #"or" instead of "and" because root's only child can be a target for multiple jumps
    def is_multibranch(self):
        return self.child1 or self.child2

def is_jxx(head):
    mnem = idc.GetMnem(head)
    if not mnem:
        print "Problem with getting mnemonic @ %08x"%head
        assert(False)
    return mnem[0]=="j"

def is_jmp(head):
    mnem = idc.GetMnem(head)
    return mnem=="jmp"

def is_short_jmp(ea):
    b = idc.Byte(ea)
    if b in [0xEB, 0x74, 0x75]: #short jmp
        return (True, 1)
    elif b == 0xE9: #long jmp
        return (False, 1)
    elif b == 0x0F:
        b2 = idc.Byte(ea+1)
        if b in [0x84, 0x85]:
            return (False, 2)
        else:
            pass #unexpected, throw assert

    print "unexpected byte @ 0x%x"%ea
    assert(False)

# jump to next line?
def is_jmp_next(ea):
    (short, off) = is_short_jmp(ea)
    if short:
        b = idc.Byte(ea+off)
        return b == 0x00
    else:
        s = idc.GetManyBytes(ea+off, 4) #Byte() returns int, but GetManyBytes a string. consistency FTW ;p
        return s == "\0\0\0\0"
    assert(False)

def raw2int(x, bits):
    assert(bits in [8,16,32])
    sign_mask = 1<<(bits-1)
    N = sign_mask << 1
    mul = 1
    if x & sign_mask:
        x = ~x+1
        x %= N
        mul = -1
    return x*mul

def decode_jump(ea):
    (short, off) = is_short_jmp(ea)
    if short:
        b = idc.Byte(ea+off)
        t = raw2int(b, 8) + 2
        return ea+t
    else:
        s = idc.GetManyBytes(ea+off, 4) #Byte() returns int, but GetManyBytes a string. consistency FTW ;p
        s = s[::-1]
        x = 0
        for b in s:
            x <<= 8
            x += ord(b)
        t = raw2int(x, 32) + 5
        t = int(t) #cast from long
        return ea+t

    assert(False)

def jxx_target(head):
    refs = idautils.CodeRefsFrom(head, 0)
    refs = list([x for x in refs])
    n = len(refs)
    #jmp $+5
    if n>0:
        target = refs[0]
    elif n==0:
        if is_jmp_next(head):
            target = idc.NextNotTail(head) 
        else:
            print "decoding @ 0x%x"%head
            #this is a bug in IDA. if MakeCode results in a new jmp, pointing to undefined byte:
            #jmp lol
            #...
            #lol:
            #   db 0
            #   <defined instructions>
            #then CodeRefsFrom() will return nothing, so we need to decode the address ourselves :p
            #FIXME: remove everything except decode_jump?
            target = decode_jump(head)
            print "result: 0x%x"%target
    else:
        print "unknown jxx_target @ 0x%x"%head
        assert(False)

    return target

def next_head(head):
    nxt = idc.NextHead(head, MAX_USER_ADDR)
    assert(nxt != idc.BADADDR)
    return nxt

def prev_head(head):

    prv = idc.PrevHead(head, 0)
    assert(prv != idc.BADADDR)

    return prv

def dfs(root, func):
    jmps = dict()
    Q = [root]
    visited = set()
    acc = None
    while Q:
        n = Q.pop()
        if n in visited:
            continue
        visited.add(n)
        c1, c2 = n.child1, n.child2
        children = filter(lambda c: c != None, [c1,c2])
        for child in children:
            Q.append(child)
        #func. programming style :P
        acc = func(acc, n, children)

    return acc

def str2int(s):
    s = s.replace("h", "")
    x = int(s, 16)
    return x
