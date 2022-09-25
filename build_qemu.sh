#!/bin/bash

qemu_wrkdir=./dd_build
echo "This is the script to build QEMU for RISC-V by DongDu."

rm -rf $qemu_wrkdir
mkdir -p $qemu_wrkdir
cd $qemu_wrkdir && ../configure \
	--prefix=$(pwd) \
	--target-list=riscv64-softmmu

make -j8
make install -j8
