#!/bin/bash -e

cd ../iox/
zig build #-freference-trace #-Doptimize=ReleaseFast
cd -

url=ws://localhost:9001
msgs=$(websocat "$url/getCaseCount" -E --jsonrpc)

../iox/zig-out/bin/ws_autobahn_client "$msgs"
websocat "$url/updateReports?agent=dummy" -E

open $(pwd)/autobahn/reports/clients/index.html
