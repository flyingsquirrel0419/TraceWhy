#!/bin/sh
set -e
mkdir -p vendor
printf 'int hello(void){return 7;}\n' > h.c
printf 'int hello(void);\nint main(void){return hello()==7?0:1;}\n' > m.c
gcc -shared -fPIC -o vendor/libtwhello.so.1 h.c
gcc -o app m.c -Lvendor -l:libtwhello.so.1
