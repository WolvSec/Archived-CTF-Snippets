#!/bin/sh
# FROM debian:bullseye
echo "Spawning the VM..."
LD_PRELOAD=./skip_mbind.so stdbuf -i0 -o0 -e0 \
qemu-system-aarch64 \
    -m 64M \
    -kernel Image \
    -initrd rootfs.img \
    -nographic \
    -machine virt \
    -cpu max \
    -smp 1 \
    -no-reboot \
    -nodefaults -snapshot \
    -chardev stdio,id=char0,mux=off,signal=off -serial chardev:char0 \
    #-sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny \
    -append "oops=panic loglevel=2 panic=1 kaslr" \

