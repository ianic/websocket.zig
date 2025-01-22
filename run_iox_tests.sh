#!/bin/bash -e

cd ../iox/
zig build #-freference-trace #-Doptimize=ReleaseFast
cd -

killall ws_echo_server || true
../iox/zig-out/bin/ws_echo_server &
server_pid=$!

cd autobahn/
./start.sh
cd -

sleep 1

url=ws://localhost:9001
msgs=$(websocat "$url/getCaseCount" -E --jsonrpc)

../iox/zig-out/bin/ws_autobahn_client "$msgs"
websocat "$url/updateReports?agent=dummy" -E

open $(pwd)/autobahn/reports/clients/index.html
open $(pwd)/autobahn/reports/servers/index.html

kill $server_pid
