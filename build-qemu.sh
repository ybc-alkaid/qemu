#!/bin/bash

./configure --target-list=riscv64-softmmu --enable-virtfs && make -j $(nproc)