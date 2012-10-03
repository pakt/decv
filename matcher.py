# matches deobfuscated handlers the original ones
from config import *
import re
import os
from vm_instructions import *

HANDLERS_DICT = dict()

def get_disasm(handler_id):
    return HANDLERS_DICT[handler_id]

def get_id_from_fn(fn):
    dot = fn.find(".")
    assert(dot>0)
    return int(fn[:dot], 16)

def load_clean_handlers(clean_dir):
    clean_handlers = []
    files = os.listdir(clean_dir)
    for fn in files:
        dir_fn = os.path.join(clean_dir, fn)
        f = open(dir_fn, "r")
        disasm = f.read()
        f.close()
        id = get_id_from_fn(fn)
        HANDLERS_DICT[id] = disasm
        clean_handlers.append(id)
    return clean_handlers

def dump_identified(identified):
    for disasm, clean_sorted in identified:
        print disasm
        print "matched with:", "#"*10
        id = clean_sorted[0]
        clean_disasm = get_disasm(handler_id)
        print clean_disasm

#make lowercase
#contract whitespace
def normalize(txt):
    txt = txt.lower()
    txt = re.sub("\s+", " ", txt)
    txt = txt.strip()
    return txt

def count_matching_lines(s1, s2):
    s = s1 & s2
    return len(s)

#n^2, but no need to be faster
#returns list of (i,j) pairs: l1[i] == l2[j]
def exact_matcher(l1, l2):
    c = 0
    matched = []
    for i,x1 in enumerate(l1):
        ok = False
        for j,x2 in enumerate(l2):
            if x1 == x2 and ok:
                """
                print "dupe:"
                print x1
                print "---"
                """
            elif x1 == x2:
                #print "EXACT MATCH!"
                #print x1
                c += 1
                matched.append((i,j))
                ok = True
        if not ok:
            #print "unmatched: '%s'"%x1
            pass

    print "matched: %d/%d"%(c, len(l1))

    return matched

#cut everything after "j" (cut after first jump)
def trim_jxx(txt):
    txt = re.sub(r"j.*", "j", txt)
    return txt

#FIXME: empty handlers
def x_identify_handlers(deobfu_handlers):
    
    clean_handlers = load_clean_handlers(CLEAN_HANDLERS_DIR)

    print "clean_handlers:", len(clean_handlers)

    identified = []

    deobfu_disasms = map(lambda h: h.get_org_disasm(), deobfu_handlers)
    clean_disasms = map(lambda h_id: HANDLERS_DICT[h_id], clean_handlers)

    norm_deobfu_disasms = map(lambda h: normalize(h), deobfu_disasms)
    norm_clean_disasms = map(lambda h: normalize(h), clean_disasms)
    
    matched = exact_matcher(norm_deobfu_disasms, norm_clean_disasms)
    unmatched = list(set(norm_deobfu_disasms) - set(matched))
    unmatched_clean = list(set(norm_clean_disasms) - set(matched))

    trim_unmatched = map(lambda h: trim_jxx(h), unmatched)
    trim_clean = map(lambda h: trim_jxx(h), unmatched_clean)

    matched = exact_matcher(trim_unmatched, trim_clean)

    unmatched = list(set(trim_unmatched) - set(matched))

    #print "UNMATCHED"
    assert(unmatched == [])
    
    vm_instrs = map(lambda h: VM_Instruction(), deobfu_handlers)
    return vm_instrs

def load_all_vm_instrs():

    vmis = map(lambda vmi_class: vmi_class(), VM_INSTRUCTIONS_SET)
    return vmis

def identify_handlers(deobfu_handlers):
    
    vmis = load_all_vm_instrs()
    for vmi in vmis:
        vmi.trimmed_src = trim_jxx(normalize(vmi.src))

    """
    vmis_with_jxx = filter(lambda vmi: vmi.src_has_branches(), vmis)
    vmis_with_jxx = set(vmis_with_jxx)
    vmis = set(vmis) - vmis_with_jxx
    """
    
    print "deobfu handlers count:", len(deobfu_handlers)
    print "vmi count:", len(vmis)

    identified = []

    for h in deobfu_handlers:
        disasm = h.get_org_disasm()
        trimmed_disasm = trim_jxx(normalize(disasm))
        found = False
        for vmi in vmis:
            if trimmed_disasm == vmi.trimmed_src:
                if not found:
                    identified.append(vmi)
                    found = True
                else:
                    """
                    print "dupe:", disasm
                    print "-"*5
                    """
                    pass
        
        if found:
            continue
        
        print "not found:"
        print hex(h.get_addr())
        print disasm
        print "-"*5
        assert(False)

    assert(len(identified) == len(deobfu_handlers))

    return identified

