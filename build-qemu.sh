#!/bin/bash
rm -r build
./configure --target-list=riscv64-softmmu --enable-virtfs && make -j $(nproc)