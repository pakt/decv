import idc
import os

CLEAN_DIR = "clean_handlers"

def disasm(start, end):
    head = start
    l = []
    while head<end:
        if isCode(GetFlags(head)):
            OpHex(head, 0)
            OpHex(head, 1)
            dis = idc.GetDisasm(head)
            l.append(dis)
        head = idc.NextHead(head, 0x7fffffff)
    
    dis = "\n".join(l)
    return dis

def dump_one(id, start, end):
    fn = os.path.join(CLEAN_DIR, "%03x.txt"%id)
    dis = disasm(start, end)
    f = open(fn, "w")
    f.write(dis)
    f.close()

def decode_id(id):
    return id>>16

def dump_all(tab):
    while True:
        id = idc.Dword(tab)
        start = idc.Dword(tab+4)
        end = idc.Dword(tab+8)
        tab += 16
        id = decode_id(id) 
        print hex(id), hex(start), hex(end)
        if id == 0xFFFF:
            break
        dump_one(id, start, end)

handlers = 0x603b70
dump_all(handlers)
