#!/bin/bash

source /opt/Rongannetwork/1.0/environment-setup-core2-64-poky-linux

make clean PLATFORM=x86;make all PLATFORM=x86
