#!/bin/bash

ROFL_BUILD_DIR="$1"
XDPD_BUILD_DIR="$2"

cd $ROFL_BUILD_DIR
make
sudo make install

cd $XDPD_BUILD_DIR
make 
