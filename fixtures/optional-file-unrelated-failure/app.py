import sys
try:
    open(".env").read()
except FileNotFoundError:
    pass
values = [1, 2, 3]
if sum(values) != 7:
    print("self-check failed", file=sys.stderr)
    sys.exit(3)
