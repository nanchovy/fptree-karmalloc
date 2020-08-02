#!/bin/bash

ARCH_FD=../arch-dep/include

rm -r build
mkdir build
cd build

cmake .. -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_FLAGS_DEBUG="-g3 -gdwarf-2 -march=native" -DCMAKE_CXX_FLAGS_DEBUG="-g3 -gdwarf-2 -march=native" \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DARCH_INC_DIR=$ARCH_FD
make clean
make -j8
