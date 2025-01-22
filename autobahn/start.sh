#!/bin/bash -e

podman stop fuzzingserver || true
podman stop fuzzingclient || true

mkdir -p reports/clients

podman run -d --rm \
    -v "${PWD}/config:/config" \
    -v "${PWD}/reports:/reports" \
    --name fuzzingserver \
    -p 9001:9001 \
    -p 8080:8080 \
    crossbario/autobahn-testsuite:0.8.2 \
    wstest --mode fuzzingserver --spec /config/functional.json

podman run -d --rm --network=host \
    -v "${PWD}/config:/config" \
    -v "${PWD}/reports:/reports" \
    --name fuzzingclient \
    crossbario/autobahn-testsuite:0.8.2 \
    wstest --mode fuzzingclient --spec /config/functional_server.json
