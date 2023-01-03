#!/usr/bin/env bash -e

docker stop fuzzingserver || true

docker run -it --rm \
    -v "${PWD}/config:/config" \
    -v "${PWD}/reports:/reports" \
    --name fuzzingserver \
    -p 9001:9001 \
    -p 8080:8080 \
    crossbario/autobahn-testsuite:0.8.2 \
    wstest --mode fuzzingserver --spec /config/all.json
