#!/bin/bash

clang -arch arm64 -dynamiclib -fPIC inject-code.c -o injseg_data