#!/bin/bash

qemu-system-aarch64 \
    -machine virt \
    -cpu max \
    -smp 2 \
    -kernel ./Image \
    -initrd ./initramfs.cpio.gz \
    -nic none \
    -nographic \
    -monitor telnet:127.0.0.1:1235,server,nowait\
    -append "console=ttyAMA0" \
#    -append "console=ttyAMA0 nokaslr" \
#    -d trace:pl666*

