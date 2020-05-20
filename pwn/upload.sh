#!/bin/bash

mkdir fs; pushd fs; cpio --extract --verbose --formatt=new < ../rootfs.img; popd

musl-gcc -static -Wall -Wextra main.c -o fs/main

pushd fs; find . -print0 | cpio --null --create --verbose --format=new | gzip -9 > ../initramfs.cpio.gz; popd
