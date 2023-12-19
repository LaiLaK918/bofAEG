# -*- coding: utf-8 -*-
import PwnContext as pwn
import IPython
import subprocess, os, sys
import binascii
import r2pipe
import json
import angr

def one_gadget(filename):
  return [int(i) for i in subprocess.check_output(['one_gadget', '--raw', filename]).decode().split(' ')]
def killmyself():
    os.system('kill %d' % os.getpid())

def check_in_mapinfo(num, mapinfo):
    for i in mapinfo:
        if num >= i[0] and num <= i[1]:
            return True

    return False

def init_profile(filepath, libpath, inputpath, outputpath):
    """Initialize profile.rr2 file
    """
    content = """#!/usr/local/bin/rarun2
program={filepath}
stdin={inputpath}
stdout={outputpath}
stderr=./error.txt
libpath={libpath}
aslr=no
""".format(filepath=filepath, libpath=libpath, inputpath=inputpath, outputpath=outputpath)
    
    with open('profile.rr2','w') as fp:
        fp.write(content)

def init_r2(filepath, input):
    """Initialize r2 in debug mode for dynamic analysis
    """
    with open('input.txt', 'wb') as f:
        f.write(input)

    if os.path.exists('output.txt'):
        os.remove('output.txt')

    r2 = r2pipe.open(filepath,flags=['-r','profile.rr2'])
    r2.cmd('doo') # Reopen in debug mode with args (alias for 'ood')
    return r2

def set_concrete(state, addrs, concrete_byte=None, pad_byte=b'\x00'):
    """
    addrs: []
    Concrete addrs of state into concrete_str
    """
    if addrs == []:
        return
    if not concrete_byte:
        tmp = pwn.cyclic(len(addrs))
    else:
        if len(concrete_byte) > len(addrs):
            pwn.log.error("set_concrete: len(concrete_byte) > len(addrs).")
        tmp = concrete_byte
        tmp = tmp.ljust(len(addrs), pad_byte)

    if len(addrs) == 1:
        state.add_constraints(state.memory.load(addrs[0],1) == tmp[0])
    else:
        for i in range(len(addrs)-1):
            state.add_constraints(state.memory.load(addrs[i],1) == tmp[i])

        #The last bit may be set to \n by the gets function
        if state.solver.satisfiable( \
            extra_constraints = (state.memory.load(addrs[i+1],1) == tmp[i+1],)):
            state.add_constraints(state.memory.load(addrs[i+1],1) == tmp[i+1])

def check_r2_one(r2, stack_off=0):
    """Determine whether the memory status of the current program satisfies one_gadget
    """

    rsp = int(r2.cmd('dr rsp'),16)+stack_off
    rax = int(r2.cmd('dr rax'),16)

    if rax == 0:
        return 0x45206

    if not unpack(bytes(json.loads(r2.cmd('xj 8 @'+hex(rsp+0x30))))):
        return 0x4525a

    if not unpack(bytes(json.loads(r2.cmd('xj 8 @'+hex(rsp+0x50))))):
        return 0xef9f4
        
    if not unpack(bytes(json.loads(r2.cmd('xj 8 @'+hex(rsp+0x70))))):
        return 0xf0897

def parse_str_to_int(int_str: str):
    if int_str.startswith('0x'):
        return int(int_str, 16)
    else:
        return int(int_str)
    
def pack(address: int) -> bytes:
    if pwn.context.arch == 'amd64':
        return pwn.p64(address)
    elif pwn.context.arch == 'i386':
        return pwn.p32(address)
    raise NotImplementedError(f"This tool is not yet supported the architecture {pwn.context.arch}")

def unpack(address: bytes) -> int:
    if pwn.context.arch == 'amd64':
        return pwn.u64(address)
    elif pwn.context.arch == 'i386':
        return pwn.u32(address)
    raise NotImplementedError(f"This tool is not yet supported the architecture {pwn.context.arch}")

def get_di_register(st: angr.SimState):
    if pwn.context.arch == 'amd64':
        return st.regs.rdi
    elif pwn.context.arch == 'i386':
        return st.regs.edi
    raise NotImplementedError(f"This tool is not yet supported the architecture {pwn.context.arch}")

def get_sp_register(st: angr.SimState):
    if pwn.context.arch == 'amd64':
        return st.regs.rsp
    elif pwn.context.arch == 'i386':
        return st.regs.esp
    raise NotImplementedError(f"This tool is not yet supported the architecture {pwn.context.arch}")

import re

def find_hex_strings(input_string):
    pattern = rb'0x[0-9a-fA-F]+'
    hex_strings = re.findall(pattern, input_string)
    return hex_strings