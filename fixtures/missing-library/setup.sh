#!/bin/sh
set -e
printf 'int greet(void){return 42;}\n' > g.c
printf 'int greet(void);\nint main(void){return greet()==42?0:1;}\n' > m.c
gcc -shared -fPIC -o libtwgreet.so.1 g.c
gcc -o app m.c -L. -l:libtwgreet.so.1
rm -f libtwgreet.so.1 g.c
