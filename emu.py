from op_classes import *

STACK_MEM_TOP = 0x11220000

def emu_init_ctx():
    ctx = Ctx()
    ctx.set_reg(ESP, STACK_MEM_TOP)
    return ctx

def emu_decide_jump(dbb, ctx):
    #don't ask about the last BB
    #assert(dbb.child1 != None or dbb.child2 != None)

    taken = None
    seen_jxx = True
    for instr in dbb.body:
        instr.eval(ctx)
        if instr.is_jxx():
            seen_jxx = True
            if instr.can_eval(ctx):
                taken = instr.eval_jxx(ctx)
        
            #jumps are last instructions in BBs
            break
    
    #if there is no jump at the end, then execution transfers to the only child
    if not seen_jxx:
        assert(dbb.child1 != None and dbb.child2 == None)
        taken = True

    return taken

def emulate_list(ctx, instrs):
    for instr in instrs:
        instr.eval(ctx)

def emulate(dbb):

    visited = set()
    ctx = emu_init_ctx()
    emulate_rec(dbb, ctx, visited)

def emulate_rec(dbb, ctx, visited):
    
    assert(dbb not in visited)

    visited.add(dbb)

    for instr in dbb.body:

        instr.eval(ctx)
        print instr.dump()
        o = ctx.dump()
        print o
        
        if instr.is_jxx():
            taken = None
            if instr.can_eval(ctx):
                taken = instr.eval_jxx(ctx)
        
            #jumps are last instructions
            if taken == None:
                break
            
            if taken:
                child = dbb.true_branch()
            else:
                child = dbb.false_branch()

            emulate_rec(child, ctx, visited)

    print "#"*10
