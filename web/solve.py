#!/usr/bin/env python3
# -*- coding: utf-8 -*- 

import requests

BINARY = './bin'
ARGS = ''
LIBC = './libc.so.6'
HOST  = 'aloha.com'
PORT = 1337


elf = ELF(BINARY, checksec=FALSE)
#libc = ELF(LIBC, checksec=FALSE) Use this line to prevent checksec running

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
	p.sendafter("", value)

def read(addr):
	p.sendlineafter("", "2")
	p.sendafter("", addr)

def generateCSRF(method, parameters):
	#Generate html code

def spawnWebServer(port):
	#Spawn http server at port $port

# Generate CSRF payload
# Host web server
	

p = start()
if args.GDB:
    gdb.attach(p)

p.interactive()

