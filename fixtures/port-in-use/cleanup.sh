#!/bin/sh
kill "$(cat holder.pid)" 2>/dev/null || true
