#!/bin/bash -e

zig build -freference-trace -Drelease-fast
#zig build -freference-trace

url=ws://localhost:9001
msgs=$(websocat "$url/getCaseCount" -E --jsonrpc)

./zig-out/bin/autobahn_client "$msgs"
websocat "$url/updateReports?agent=dummy" -E
