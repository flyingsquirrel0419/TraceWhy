#!/bin/sh
set -e
cp "$(readlink -f "$(command -v python3)")" py
chmod 755 py
setcap cap_net_bind_service+ep py
