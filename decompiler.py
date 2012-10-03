import emu
import copy
from op_classes import *
from vm_classes import *

VMI_PREFIX = "VM_"
HANDLER_ID_SIZE = 1
handlers_dict = {}

def emu_decrypt(handler, ctx, vm_code, size):

    raw = vm_code.consume(size)
    ctx.set_reg(EAX, raw)
    proc = handler.decrypt_proc
    
    emu.emulate_list(ctx, proc)
    eax = ctx.get_reg(EAX)
    return eax

def decompile(main, handlers, vm_code):

    for i,h in enumerate(handlers):
        handlers_dict[i] = h

    ebx = vm_code.vaddr
    ctx = Ctx()
    ctx.set_reg(EBX, ebx)   #ebx is our decryption key

    vmis = decompile_(main, ctx, handlers, vm_code)
    return vmis

def decompile_(main, ctx, handlers, vm_code):
    
    c = 0
    vmis = []
    while True:
        ebx = ctx.get_reg(EBX)
        #print "ebx:", hex(ebx)
        id = vm_code.peek(HANDLER_ID_SIZE)
        #print "enc id:", hex(id)

        vm_code_off = vm_code.offset
        next_id = emu_decrypt(main, ctx, vm_code, HANDLER_ID_SIZE)
        
        #0x13 dwords before handlers_tab
        next_id = next_id - 0x13
        #print "next_id:", hex(next_id)

        handler = handlers_dict[next_id]
        vmi = handler.vmi
        
        param, param_size = None, None
        if handler.takes_esi_params:
            param_size = handler.param_size
            param = emu_decrypt(handler, ctx, vm_code, param_size)
            #print "size:", size, "decrypted param:", hex(param)

        if vmi.affects_ctx():
            vmi.update_ctx(ctx, vm_code, param)

        c += 1

        vmi = copy.deepcopy(vmi)
        vmi.param = param #we don't know these until decryption
        vmi.param_size = param_size
        vmi.code_off = vm_code_off

        dis = vmi.all_disasm()
        print dis

        vmis.append(vmi)

        if vmi.is_halt():
            break
    return vmis
