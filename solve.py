#!/usr/bin/env python3
# -*- coding: utf-8 -*- 

from pwn import *

BINARY = './bin'
ARGS = ''
LIBC = './libc.so.6'
HOST  = 'aloha.com'
PORT = 1337

elf = ELF(BINARY, checksec=FALSE)
#libc = ELF(LIBC, checksec=FALSE)

context.terminal = ['tmux', 'split-w']

#printf = elf.got['printf']		

def get_base_address(proc):
	return int(open("/proc/{}/maps".format(proc.pid), 'rb').readlines()[0].split('-')[0], 16)

def debug(breakpoints):
	script = ""
	for bp in breakpoints:
		script += "b *0x%x\n"%(PIE+bp)
	gdb.attach(process(BINARY), gdbscript=script)

def start():
	if not args.REMOTE:
		print("LOCAL PROCESS")
		return process([BINARY, ARGS], env={"LD_PRELOAD":LIBC})
	else:
		print("REMOTE PROCESS")
		return remote(HOST, PORT)

def write(addr, value):
	p.sendlineafter("", "1")
	p.sendlineafter("", addr)
	p.sendlineafter("", value)

def read(addr):
	p.sendlineafter("", "2")
	p.sendlineafter("", addr)

p = start()
if args.GDB:
    gdb.attach(p)

p.interactive()

