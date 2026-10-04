#!/bin/sh
mkdir -p ro
mount -t tmpfs -o ro,size=64k tracewhy-test ro
