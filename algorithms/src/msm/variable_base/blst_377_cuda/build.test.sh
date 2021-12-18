#!/bin/bash

nvcc ./asm_cuda.cu ./blst_377_ops.cu ./tests.cu ./msm.cu -arch=compute_70 -code=sm_70 --device-debug -dlink -fatbin -o ./kernel.test