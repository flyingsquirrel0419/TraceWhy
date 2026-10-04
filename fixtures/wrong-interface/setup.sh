#!/bin/sh
python3 -c 'import socket,time
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 47915)); s.listen(); time.sleep(60)' > /dev/null 2>&1 &
echo $! > holder.pid
sleep 0.5
