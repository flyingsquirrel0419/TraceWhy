#!/bin/sh
set -e
docker run -d --rm --name tracewhy-fixture-holder -e POSTGRES_PASSWORD=x -p 47916:5432 postgres:16-alpine >/dev/null
sleep 2
