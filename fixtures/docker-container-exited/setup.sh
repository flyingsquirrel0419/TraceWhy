#!/bin/sh
set -e
docker compose up -d postgres >/dev/null 2>&1
sleep 3
docker compose stop postgres >/dev/null 2>&1
