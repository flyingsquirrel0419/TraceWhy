import socket, sys
try:
    socket.create_connection(("127.0.0.1", 47913), timeout=2)
except ConnectionRefusedError as e:
    print(f"cannot connect to 127.0.0.1:47913: {e}", file=sys.stderr)
    sys.exit(1)
