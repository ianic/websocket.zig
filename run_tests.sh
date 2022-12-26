#!/bin/bash -ex

zig build -freference-trace -Drelease-fast
#zig build -freference-trace

url=ws://localhost:9001
msgs=$(websocat "$url/getCaseCount" -E --jsonrpc)

./zig-out/bin/autobahn_client3 "$msgs"
websocat "$url/updateReports?agent=websocket.zig" -E
