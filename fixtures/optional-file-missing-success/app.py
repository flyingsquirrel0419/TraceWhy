import os
config = {"port": 3000}
try:
    with open(".env") as f:
        config.update(line.split("=", 1) for line in f.read().splitlines() if "=" in line)
except FileNotFoundError:
    pass
print("starting on", config["port"])
