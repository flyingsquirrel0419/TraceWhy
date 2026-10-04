#!/bin/sh
set -e
v=$(python3 -c 'import sys; print(f"python{sys.version_info[0]}.{sys.version_info[1]}")')
mkdir -p ".venv/bin" ".venv/lib/$v/site-packages/twfixturemod"
printf 'home = /usr/bin\ninclude-system-site-packages = false\n' > .venv/pyvenv.cfg
echo 'VALUE = 1' > ".venv/lib/$v/site-packages/twfixturemod/__init__.py"
