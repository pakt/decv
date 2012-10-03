import idc
import idaapi
import idautils
from common import *

class BB(BB_):
    def __init__(self):
        BB_.__init__(self)

    def verify(self):
        for i,n in enumerate(self.body[:-1]):
            if is_jxx(n) and not is_jmp(n):
                return False
            if is_jmp(n):
                nxt = self.body[i+1]
                if nxt != jxx_target(n):
                    return False
        last = self.body[-1]

        if self.child1 == self.child2 and self.child1 == None:
            return True

        if is_jxx(last):
            if is_jmp(last):
                return self.child1.get_addr() == jxx_target(last)
            else:
                b1 = self.child1.get_addr() == next_head(last)
                b2 = self.child2.get_addr() == jxx_target(last)
                return b1 and b2

        else:
            return self.child1.get_addr() == next_head(last)

        return True

    def mnem_stats(self):
        stats = {}
        for n in self.body:
            mnem = idc.GetMnem(n)
            try:
                stats[mnem] += 1
            except:
                stats[mnem] = 1
        return stats

    
    def disasm(self):
        l = []
        for n in self.body:
            di = "0x%08x %s %s %s"%(n, idc.GetMnem(n), idc.GetOpnd(n, 0), idc.GetOpnd(n, 1))
            l.append(di)
        return "\n".join(l)

def disasm(root):
    di = dfs(root, f_disasm)
    return di

def f_disasm(acc, node, children):
    if acc == None:
        acc = ""
    acc += node.disasm()
    return acc

def mnem_stats(root):
    stats = dfs(root, f_mnem_stats)
    return stats

def f_mnem_stats(acc, node, children):
    if acc == None:
        acc = dict()

    stats = node.mnem_stats()
    for k,v in stats.iteritems():
        try:
            acc[k] += v
        except:
            acc[k] = v
    return acc

# heads - handler body
# outputs a graph of basic blocks
# no cleaning
def consume_raw_code(heads, c_jmps, u_jmps):
    
    jmp_targets = set(c_jmps.values()).union(set(u_jmps.values()))
    ea_to_bb = dict()
    visited = set()
    heads_set = set(heads)
    assert(len(heads) == len(heads_set))

    root = BB()
    root = make_bbs(heads[0], root, heads_set, jmp_targets, ea_to_bb, visited)

    return root


def merge(cur_bb, new_bb):

    if cur_bb.empty():
        return new_bb

    assert(cur_bb.child1 == None)
    cur_bb.child1 = new_bb
    return cur_bb

def handle_jxx(head, make_bbs_fun): 

    target = jxx_target(head)

    c1 = make_bbs_fun(target, BB())
    c2 = None
    
    nxt = next_head(head)
    if not is_jmp(head):
        c2 = make_bbs_fun(nxt, BB())

        # false path comes first
        c1, c2 = c2, c1

    return c1,c2

def make_bbs(head, cur_bb, heads_set, jmp_targets, ea_to_bb, visited):
    
    make_bbs_fun = lambda h, cur: make_bbs(h, cur, heads_set, jmp_targets, ea_to_bb, visited)

    while True:
        if head not in heads_set:
            if cur_bb.empty():
                #we went outside of handler?
                print "outside handler:", hex(head)
                assert(False)
            break

        if head in visited:
            bb = ea_to_bb[head]
            return merge(cur_bb, bb)

        if head in jmp_targets:

            new_bb = BB()
            new_bb.add(head)
            ea_to_bb[head] = new_bb
            visited.add(head)

            if is_jxx(head):
                c1, c2 = handle_jxx(head, make_bbs_fun) 
                new_bb.child1 = c1
                new_bb.child2 = c2

                return merge(cur_bb, new_bb)

            nxt = next_head(head) 
            new_bb = make_bbs_fun(nxt, new_bb)
            return merge(cur_bb, new_bb)

        cur_bb.add(head)
        ea_to_bb[head] = cur_bb
        visited.add(head)

        if is_jxx(head):
            c1, c2 = handle_jxx(head, make_bbs_fun)
            cur_bb.child1 = c1
            cur_bb.child2 = c2
            break
        
        head = next_head(head)
    
    cur_bb.verify()
    return cur_bb


def hexx(n):
    return hex(n).replace("0x", "x")

# export to dot (graphviz) format
def export_graph(root, fn):
    
    visited = set()
    o = "digraph g {\n"
    Q = [root]
    edges = [] 
    nodes = []
    # dfs
    while Q:
        node = Q.pop(0)
        addr = node.get_addr()
        if addr in visited:
            continue
        visited.add(addr)
        nodes.append(hexx(addr))
        c1, c2 = node.child1, node.child2

        for c in [c1,c2]:
            if c:
                c_addr = c.get_addr()
                Q.append(c)
                edges.append((hexx(addr), hexx(c_addr)))
        
    s = "\n".join(nodes)
    o += s
    o += "\n"

    for n1,n2 in edges:
        o += "%s -> %s\n"%(n1,n2)

    o += "}"

    f = open(fn, "w")
    f.write(o)
    f.close()

