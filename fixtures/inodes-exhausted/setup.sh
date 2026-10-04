#!/bin/sh
mkdir -p fs
mount -t tmpfs -o size=1m,nr_inodes=4 tracewhy-test fs
