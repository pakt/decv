import idc

class Handler:
    def __init__(self, addr, dbb, decrypt, vmi):
        #original address (as in handlers tab)
        self.addr = addr
        #is this the dispatcher?
        self.is_main = False
        #deobfuscated dbb
        self.dbb = None 
        #parameter decryption procedure (few instructions: add/sub/xor)
        self.decrypt_proc = decrypt
        #corresponding vm_instruction class
        self.vmi = vmi

        #we need to care about handlers taking params from esi
        #stack params are irrelevant
        self.takes_esi_params = False 
        #what is it: lodsb/w/d?
        self.param_size = None
        
        self.set_dbb(dbb)

    def bits_to_bytes(self, fst):
        bits = fst.bits
        if bits == 8:
            size = 1
        elif bits == 16:
            size = 2
        elif bits == 32:
            size = 4
        else:
            print "bits:", bits
            assert(False)

        return size

    def set_dbb(self, dbb):
        self.dbb = dbb
        if len(dbb.body)==0: #true for empty handler
            return
        fst = dbb.body[0]
        if fst.mnem == "lods":
            size = self.bits_to_bytes(fst)
            self.takes_esi_params = True
            self.param_size = size
    
    def set_main(self):
        self.is_main = True
    
#unfortunately, we don't know size of the code before we decrypt it,
#so we need to talk to IDA here :(
class VM_Code:
    def __init__(self, push_addr, vaddr):
        self.push_addr = push_addr
        self.vaddr = vaddr
        self.offset = 0
    
    def peek(self, size):
        ea = self.vaddr + self.offset
        if size==1:
            raw = idc.Byte(ea)
        elif size==2:
            raw = idc.Word(ea)
        elif size==4:
            raw = idc.Dword(ea)
        else:
            print "bad size:", size
            assert(False)
        return raw

    def advance(self, size):
        self.offset += size
    
    def consume(self, size):
        raw = self.peek(size)
        self.advance(size)
        return raw
