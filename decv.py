#DeCV
#decompiler for code virtualizer by oreans
#tested on cv 1.3.8
#
#greets to softworm for his unpacked CV version :)
#
#p_k
#02.10.2012
#gdtr.wordpress.com

import idc
import idautils 
import idaapi
import op
import bb
import opt
import matcher
import pickler
from common import *
from vm_classes import *
from vm_instructions import *
import decompiler
import emu
import sys
import time
import copy
import cProfile, pstats
import recover_x86 as x86
import pickle

#magic constants
#this can be greater, up to 168
#earlier versions of CV have 150 handlers, newer 168
MIN_HANDLERS_COUNT = 100   
MAX_HANDLERS_PREFIX_LEN = 0x13*4
MIN_REFS_TO_MAGIC_LODSB = MIN_HANDLERS_COUNT+1 

CALL_DELTA = "e8 00 00 00 00"
LODSB = "ac"

# if this is the handlers table
# all entries should have two highest bytes equal
def get_handlers(ea):
    handlers = []
    dw = idc.Dword(ea)
    hi_word = dw & 0xffff0000
    while True:
        handlers.append(dw)
        ea += 4
        dw = idc.Dword(ea)
        if dw & 0xffff0000 != hi_word:
            break
    return handlers

def skip_zero_dwords(ea):    
    while True:
        dw = idc.Dword(ea)
        if dw != 0:
            break
        ea += 4
    return ea

def is_handlers_tab(ea):

    handlers = get_handlers(ea)

    return (len(handlers) >= MIN_HANDLERS_COUNT)

# collect 2nd op, if it's immediate
def collect_imm_opnd2(ea, count):
   
    ops = []
    ea = prev_head(ea)
    for i in range(count):
        ea = next_head(ea)

        otype = idc.GetOpType(ea, 1)
        if otype != idc.o_imm:
            continue

        op2 = idc.GetOperandValue(ea, 1)
        ops.append(op2)

    return ops

def find_bytes(start, end, seq, seq_len):
    hits = []

    while start < end-seq_len:

        hit_ea = idaapi.find_binary(start, end, seq, 16, idaapi.BIN_SEARCH_FORWARD)
        
        if hit_ea == idaapi.BADADDR:
            break
        
        start = hit_ea+seq_len
        
        #if idaapi.isCode(idc.GetFlags(hit_ea)):
        #    hits.append(hit_ea)
           
        hits.append(hit_ea)

    return hits

# search for call $+5 (delta call)
# CV main handler starts this way
def search_for_delta(start, end):
    
    call_len = CALL_DELTA.count(" ")+1

    calls = find_bytes(start, end, CALL_DELTA, call_len)
    
    # (delta_call, handler table) pairs
    found = [] 
    for call_ea in calls:
       ops = collect_imm_opnd2(call_ea, 5)
       for op in ops:
           new_op = skip_zero_dwords(op)
           if new_op > op + MAX_HANDLERS_PREFIX_LEN or new_op == op:
               continue
           op = new_op
           if is_handlers_tab(op):
               found.append((call_ea, op))

    return found

# all handlers end with a jump to magic lodsb
def search_for_magic_lodsb(start):
    SCAN_SIZE = 0x10000

    loads = find_bytes(start, start+SCAN_SIZE, LODSB, 1)
    candidates = []
    for load_ea in loads:
        refs = idautils.CodeRefsTo(load_ea, 1)

        #unpack generator
        refs = list(x for x in refs)

        #the one we are looking for has >150 refs pointing to it
        if len(refs)<MIN_REFS_TO_MAGIC_LODSB:
            continue
        
        candidates.append(load_ea)

    return candidates

def is_magic_jmp(addr):
    op = idc.GetOpnd(addr, 0)
    return is_jmp(addr) and op == "dword ptr [edi+eax*4]"

# lodsb
# ...
# movzx eax, al
# jmp [edi+eax*4]
# ^^ we are looking for this jmp
def search_for_magic_jmp(start):
    cur_ea = start
    print "search fmj:", hex(start)
    while True:
        if is_magic_jmp(cur_ea):
            break

        elif is_jmp(cur_ea):
            cur_ea = jxx_target(cur_ea)

        elif is_jxx(cur_ea):
            print "Multibranching in main handler not supported:", hex(cur_ea)
            assert(False)

        else:
            cur_ea = next_head(cur_ea)

    return cur_ea
    
def disasm_one(head):
    mnem = idc.GetMnem(head)
    dis = mnem +" "+ idc.GetOpnd(head,0) +" "+ idc.GetOpnd(head, 1)
    return dis

def disasm(heads):
    for head in heads:
        print hex(head), disasm_one(head)
#
# collect instructions from a handler, omitting garbage uncoditional jumps
# start - start address
#
# f_terminate - function that takes an address as a parameter and decides if
#               we should stop collecting
#
def contract_handler(start, f_terminate):
    
    visited = set()
    cond_jmps, uncond_jmps = dict(), dict()
    collected = contract_handler_rec(start, f_terminate, visited, cond_jmps, uncond_jmps)

    return collected, cond_jmps, uncond_jmps

# invariant:
# if address is in visited_heads, then all code reachable from that address
# was already collected
#
def contract_handler_rec(start, f_terminate, visited_heads, cond_jmps, uncond_jmps):
    ea = prev_head(start)
    collected = []
    branches = []
    while True:

        ea = next_head(ea)

        if f_terminate(ea):
            break
        
        if ea in visited_heads:
            break

        visited_heads.add(ea)

        mnem = idc.GetMnem(ea) 
        dis = mnem +" "+ idc.GetOpnd(ea,0) +" "+ idc.GetOpnd(ea, 1)+'\n'
        #print hex(ea), dis

        refs = idautils.CodeRefsFrom(ea, 0)
        refs = list([x for x in refs])
        #print refs
        if is_jmp(ea):
            t = jxx_target(ea)
            refs = [t]
        
        collected.append(ea)

        # jmp $+5 has an empty ref list
        if is_jmp(ea) and len(refs) == 0:
            uncond_jmps[ea] = next_head(ea)
            continue

        if len(refs) > 0:
            target = refs[0]

            if is_jmp(ea):
                uncond_jmps[ea] = target

                if target in visited_heads:
                    break

                ea = prev_head(target)

            # multibranching
            elif is_jxx(ea):
                cond_jmps[ea] = target

                if target not in visited_heads:
                    collected_branch = contract_handler_rec(target, f_terminate, visited_heads, cond_jmps, uncond_jmps) 
                
                    # append it later, for natural code layout
                    branches.append(collected_branch)
            else:
                assert(False)

    combined_branches = reduce(lambda x,y: x+y, branches, [])

    return collected+combined_branches

def visit(ea, visited): visited[ea]=True

def was_visited(ea, visited):
    try:
        visited[ea]
        return True
    except:
        return False

def make_code_rec(ea, visited, magic_lodsb):

    #print "rec"
    while True:

        if was_visited(ea, visited):
            break

        if ea == magic_lodsb:
            break
    
        visit(ea, visited)

        old_op = idc.GetOpnd(ea, 0)
        if not isCode(GetFlags(ea)):
            n = 6
            undefBytes(ea, n)
            i = 0
            while i<n:
                r = idc.MakeCode(ea+i)
                if r==0:
                    break
                i += r
            idc.AnalyzeArea(ea, ea+n)

        OpHex(ea, -1)

        if is_jxx(ea):
            jmp_ea = jxx_target(ea)
            if is_jmp(ea):
                ea = jmp_ea
                continue
            else:
                make_code_rec(jmp_ea, visited, magic_lodsb)
                #false branch will be taken below

        nea = NextNotTail(ea)
        ea = nea

def make_code_rec_wrapper(ea, visited, magic_lodsb):
    new_v = copy.deepcopy(visited)
    make_code_rec(ea, new_v, magic_lodsb)

# fix problems with undefined bytes in handlers
# by turning them into code ("C", or Make Code in IDA)
def make_code_in_handlers(handlers_addrs, magic_lodsb):

    visited = dict()
    for ea in handlers_addrs:
        make_code_rec_wrapper(ea, visited, magic_lodsb)
        #make_code_rec(ea, visited, magic_lodsb)

def undefBytes(ea, count):
    for i in range(count):
        idc.MakeUnkn(ea+i, 1)

def undefDword(ea):
    undefBytes(ea, 4)

def make_dwords_in_handlers_tab(handlers_tab, count):

    ea = handlers_tab
    for i in range(count):
        undefDword(ea)
        idc.MakeDword(ea)
        ea += 4

def find_stuff():

    candidates = []
    for seg_ea in Segments():
        seg_end = SegEnd(seg_ea)
        #print hex(seg_ea), hex(seg_end)
        
        candidates += search_for_delta(seg_ea, seg_end)

    #FIXME: we can deal with many delta calls
    if len(candidates) != 1:
        print "Too many, or too little candidates for delta call :("
        print "candidates:", map(lambda c: "0x%08x, 0x%08x"%(c[0], c[1]), candidates)
        assert(False)
    
    delta_call, handlers_tab = candidates[0]
    #handlers_tab += HANDLERS_TAB_PREFIX_LEN

    candidates = search_for_magic_lodsb(delta_call)

    if len(candidates) != 1:
        print "Too many, or too little candidates for lodsb inside dispatcher :("
        print "candidates:", map(lambda c: "0x%08x"%c, candidates)
        assert(False)

    magic_lodsb = candidates[0]
    
    handlers_addrs = get_handlers(handlers_tab)
    count = len(handlers_addrs)
    make_dwords_in_handlers_tab(handlers_tab, count)
    make_code_in_handlers(handlers_addrs, magic_lodsb)

    norm_ops()

    magic_jmp = search_for_magic_jmp(magic_lodsb)

    return (delta_call, handlers_tab, magic_lodsb, magic_jmp)

def emit_graph(start_ea, stop_ea):
    terminate_f = lambda ea: ea == stop_ea
    body, c_jmps, u_jmps = contract_handler(start_ea, terminate_f)

    #print hex(start_ea), len(body)

    body += [stop_ea]
    root = bb.consume_raw_code(body, c_jmps, u_jmps)
    return root

def contract_handlers(handlers_addrs, stop_ea):

    handler_roots = []
    for addr in handlers_addrs:
        root = emit_graph(addr, stop_ea)
        handler_roots.append(root)

    return handler_roots

# we don't want indirect jumps at the end of BB
# follow backward refs until we land on a non-jmp instruction
# it's necessary, since handlers can be split with jumps at any point
def emit_main_handler_graph(start_ea, magic_jmp):
    prev_ea = magic_jmp
    while is_jxx(prev_ea):
        assert(is_jmp(prev_ea))
        refs = idautils.CodeRefsTo(prev_ea, 1)
        refs = list(x for x in refs)
        assert(len(refs)==1)
        prev_ea = refs[0]

    graph = emit_graph(start_ea, prev_ea)

    return graph

# kill jumps
def optimize_handlers(handler_roots):
    
    optimized = []

    f = open("disasm.txt", "w")

    for i,root in enumerate(handler_roots):
        root = opt.contract_graph(root)
        optimized.append(root)
        #bb.export_graph(root, "graphs\\"+str(i)+".txt")
        #print "handler:", hex(root.get_addr())

        di = bb.disasm(root)

        f.write(di+"\n########\n")

    f.close()
    
    return optimized

def norm_ops():
    for seg_ea in Segments():
        for head in Heads(seg_ea, SegEnd(seg_ea)):
            if isCode(GetFlags(head)):
                OpHex(head, 0)
                OpHex(head, 1)

#convert from BBs to DBBs
#DBBs are richer (instructions are wrapped in classes, etc)
def convert_bbs_to_dbbs(handler_roots):
    converted = []
    for root in handler_roots:
        root = op.convert_graph(root)
        converted.append(root)
    return converted

def deobfuscate_handlers(handler_roots):
    deobfuscated = []
    for i,root in enumerate(handler_roots):
        root = opt.run_all_opts(root)
        deobfuscated.append(root)
    
    return deobfuscated

# remove parameter decryption stuff
# to make identification easier
def strip_decryption(roots):
    stripped_roots = []
    decrypt_procs = []
    for root in roots:
        stripped_root, decrypt_instrs = opt.remove_irrelevant(root)
        stripped_roots.append(stripped_root)
        decrypt_procs.append(decrypt_instrs)

    return stripped_roots, decrypt_procs


#return a list of pairs
#(vm_entry_point, vm_code_offset)
def find_vm_codes(dispatcher_ea):
    mnem = idc.GetMnem(dispatcher_ea)

    if mnem != "pusha":
        print "dispatcher_ea: 0x%08x, bad mnem: %s"(dispatcher_ea, mnem)
        assert(False)

    refs = idautils.CodeRefsTo(dispatcher_ea, 1)
    refs = list(x for x in refs)

    print "vms found:", len(refs)
    
    for ref in refs:
        print hex(ref)

    vms = []
    for ref in refs:
        #push offset
        #jmp dispatcher
        push_ea = prev_head(ref)
        mnem = idc.GetMnem(push_ea)
        if mnem != "push":
            print "push_ea:", hex(push_ea)
            print "unexpected mnem:", mnem
            assert(False)
        op = idc.GetOpnd(push_ea, 0)

        op = str2int(op)

        vms.append((push_ea, op))
    
    return vms

def get_vm_codes(delta_call):

    dispatcher_ea = delta_call - 3 #pusha, pushf, cld
    vms = find_vm_codes(dispatcher_ea)
    
    vm_codes = []
    for (push_addr, code_addr) in vms:
        vmc = VM_Code(push_addr, code_addr)
        vm_codes.append(vmc)
    return vm_codes

def dump_to_file(outfn, handlers):

    f = open(outfn, "w")
    for h in handlers:
        s = h.dump()
        f.write(s)
    f.close()

def save_example(vmis):
    f = open(FN_EXAMPLE, "w")
    pickle.dump(vmis, f)
    f.close()

if __name__=="__main__":

    idaapi.autoWait()

    #should we close IDA after successful decompilation?
    die = False
    x = idaapi.get_plugin_options("die") #hax from http://accessomat.wordpress.com/2010/08/04/not-so-new-feature-on-ida-pro-5-7/
    if x == "1":
        die = True

    outfn = idaapi.get_plugin_options("outfn") 
    if not outfn:
        outfn = "deobfu.txt"
    
    print "-"*20
    print "DeCV 1.0b by p_k / twitter.com/pa_kt"
    print "-"*20
    
    print "normalizing operands...",
    norm_ops()
    print "done"

    start_time = time.time()

    sys.setrecursionlimit(10000) #pickle

    pcklr = pickler.Pickler()
    state_loaded = False
    if pcklr.can_load_state() and False:
        state_loaded = True
        state = pcklr.load_state()
        delta_call, handlers_tab, magic_lodsb, magic_jmp, roots, handlers_addrs = state
        print "state was loaded from:", pcklr.pickle_fn
    else:
        delta_call, handlers_tab, magic_lodsb, magic_jmp = find_stuff()

    #makecode can produce new code..
    norm_ops()

    print "delta_call:", hex(delta_call)
    print "handlers_tab:", hex(handlers_tab)
    print "magic_lodsb:", hex(magic_lodsb)
    print "magic_jmp:", hex(magic_jmp)
    
    delta =  time.time() - start_time
    print "find_stuff time:", delta

    if not state_loaded:
        #consume up to magic_jmp to avoid problems with BB creation
        main_handler = emit_main_handler_graph(magic_lodsb, magic_jmp)
        handlers_addrs = get_handlers(handlers_tab)
        roots = contract_handlers(handlers_addrs, magic_lodsb)
        roots.append(main_handler)

        roots = optimize_handlers(roots)
        roots = convert_bbs_to_dbbs(roots)
        """
        prof_fn = "prof.txt"
        cProfile.run('roots = convert_bbs_to_dbbs(roots)', prof_fn)
        p = pstats.Stats(prof_fn)
        p.sort_stats('cumulative').print_stats(30)
        """

        #roots = convert_bbs_to_dbbs(roots)
        delta =  time.time() - start_time
        print "convert_bbs_to_dbbs time:", delta
        roots = map(lambda r: opt.cut_and_clean(r), roots)
        delta =  time.time() - start_time
        print "cut_and_clean time:", delta
        roots = deobfuscate_handlers(roots)
        dump_to_file(outfn, roots)
        #pcklr.save_state((delta_call, handlers_tab, magic_lodsb, magic_jmp, roots, handlers_addrs)) 
        delta =  time.time() - start_time
        print "deobfuscate_handlers time:", delta

    delta =  time.time() - start_time
    print "elapsed time:", delta

    #multi = filter(lambda r: r.is_multibranch(), roots)
    #print "handlers with multibranching:", len(multi)
    
    #print_one(roots)

    stripped_roots, decrypt_procs = strip_decryption(roots)

    main_dbb, main_decrypt = stripped_roots.pop(), decrypt_procs.pop()

    vmis = matcher.identify_handlers(stripped_roots)
    
    assert(len(handlers_addrs) == len(stripped_roots) == len(decrypt_procs) == len(vmis))

    handlers = []
    for addr, dbb, decrypt, vmi in zip(handlers_addrs, stripped_roots, decrypt_procs, vmis):
        h = Handler(addr, dbb, decrypt, vmi)
        handlers.append(h)
    
    main = Handler(magic_lodsb, main_dbb, main_decrypt, VM_Instruction())
    main.set_main()

    #print main.dbb.dump()

    vm_codes = get_vm_codes(delta_call) 

    for i,vm_code in enumerate(vm_codes):
        print "vm:", i
        vmis = decompiler.decompile(main, handlers, vm_code)
        print "-"*5
        #x86.recover(vmis)
    
    delta =  time.time() - start_time
    print "done. total time:", delta

    if die:
        idc.Exit(0)
    
